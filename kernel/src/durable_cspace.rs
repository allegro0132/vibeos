//! Persistent capability-space lifecycle over the unified object journal.
//!
//! Only the boot-registered `persistent-test` SpaceId is admitted. Journal
//! records remain inert until the external root constraint, object-kind map,
//! and typed `StoredObject` witness all match; only then is the whole recovered
//! graph installed atomically. The target CSpace never receives Store WRITE.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use vibeos_core::cap::{
    InvocationLease, PendingSlotReservation, PersistentCapIdentity, PersistentDerivationWitness,
    PersistentResourceWitness, Resource, Rights,
};
use vibeos_core::durable::{
    self, DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, ObjectKind,
    RecoveredGrant, RecoveredSlot, RecoveredStore, ResourceKind, RootConstraint,
    RootRightsConstraint, SlotIdentity, SpaceId, TransactionId,
};
use vibeos_core::program::{self as program_model, RootPolicyPartition};
use vibeos_core::store as object_codec;

use crate::saved_program::{self, SavedProgramService, TrustedProgram};
use crate::store::{AuthorityJournal, AuthoritySnapshot, StoreError, StoredObject};
use crate::world::Space;
use crate::{exec, heap, sync::SpinLock, virtio_blk};

const PERSISTENT_SPACE_ID_RAW: u128 = 0x5053;
const STORED_OBJECT_RESOURCE_KIND_RAW: u32 = 0x5354_4f52;
const PERSISTENT_OBJECT_KIND_RAW: u32 = 0x4353_5043;
const ROOT_SLOT: u32 = 0;
const CHILD_SLOT: u32 = 1;
const GRANDCHILD_SLOT: u32 = 2;
const ROOT_RIGHTS: DurableRights = DurableRights::READ
    .union(DurableRights::GRANT)
    .union(DurableRights::REVOKE);
const CHILD_RIGHTS: DurableRights = DurableRights::READ.union(DurableRights::GRANT);
const GRANDCHILD_RIGHTS: DurableRights = DurableRights::READ;
const MARKER: &[u8] = b"VIBEOS-PERSISTENT-CSPACE-v1";

pub(crate) const fn persistent_space_id() -> SpaceId {
    match SpaceId::new(PERSISTENT_SPACE_ID_RAW) {
        Some(id) => id,
        None => unreachable!(),
    }
}

fn stored_object_resource_kind() -> ResourceKind {
    ResourceKind::new(STORED_OBJECT_RESOURCE_KIND_RAW)
        .expect("the StoredObject durable resource kind is non-zero")
}

fn persistent_object_kind() -> ObjectKind {
    ObjectKind::new(PERSISTENT_OBJECT_KIND_RAW)
        .expect("the persistent-test object kind is non-zero")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DurableCSpaceState {
    Cold = 0,
    WaitingBlock = 1,
    Recovering = 2,
    Ready = 3,
    FailedClosed = 4,
}

impl DurableCSpaceState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Cold,
            1 => Self::WaitingBlock,
            2 => Self::Recovering,
            3 => Self::Ready,
            _ => Self::FailedClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentTestPhase {
    Boot1Created,
    Boot2Revoked,
    Boot3Reused,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentTestReport {
    pub phase: PersistentTestPhase,
    pub root_slot: u32,
    pub root_generation: u64,
    pub child_slot: u32,
    pub old_child_generation: u64,
    pub child_generation: u64,
    pub read_ok: bool,
    pub old_child_absent: bool,
    pub descendant_absent: bool,
    pub no_store_write: bool,
    pub dependent_started: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableCSpaceInfo {
    pub state: DurableCSpaceState,
    pub live_grants: usize,
    pub tombstones: usize,
    pub dependent_started: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableCSpaceError {
    PermissionDenied,
    Busy,
    OutsideTask,
    FailedClosed,
    Store(StoreError),
    IdExhausted,
    Encode,
    RootPolicy,
    Install,
    UnexpectedGraph,
}

impl core::fmt::Display for DurableCSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "durable CSpace journal failed: {error}"),
            _ => f.write_str(match self {
                Self::PermissionDenied => "durable CSpace service lacks WRITE",
                Self::Busy => "durable CSpace operation already active",
                Self::OutsideTask => "durable CSpace operations require an executor task",
                Self::FailedClosed => "durable CSpace recovery failed closed",
                Self::IdExhausted => "durable stable ID space exhausted",
                Self::Encode => "durable authority record encoding failed",
                Self::RootPolicy => "durable root policy did not match exactly",
                Self::Install => "durable CSpace publication revalidation failed",
                Self::UnexpectedGraph => "durable CSpace graph has an unexpected shape",
                Self::Store(_) => unreachable!(),
            }),
        }
    }
}

impl From<StoreError> for DurableCSpaceError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Default)]
struct LiveGraph {
    root: Option<PersistentCapIdentity>,
    child: Option<PersistentCapIdentity>,
    descendant: Option<PersistentCapIdentity>,
    child_history_generation: Option<u64>,
    descendant_history_generation: Option<u64>,
    live_grants: usize,
    tombstones: usize,
}

#[derive(Clone, Copy)]
struct ValidatedGraphShape {
    child_history_generation: Option<u64>,
    descendant_history_generation: Option<u64>,
    tombstones: usize,
}

struct DurableActiveClaim {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    reservation: Option<PendingSlotReservation>,
}

struct DurableCSpaceInner {
    journal: AuthorityJournal,
    target: Arc<Space>,
    saved_program: Arc<SavedProgramService>,
    state: AtomicU8,
    active: SpinLock<Option<DurableActiveClaim>>,
    dependent_started: AtomicBool,
    graph: crate::sync::SpinLock<LiveGraph>,
}

pub struct DurableCSpaceService {
    inner: Arc<DurableCSpaceInner>,
}

static INSTALLED_DURABLE_CSPACE: SpinLock<Option<Arc<DurableCSpaceInner>>> = SpinLock::new(None);
static NEXT_ACTIVE_TOKEN: AtomicU64 = AtomicU64::new(1);

impl DurableCSpaceInner {
    fn begin_claim(self: &Arc<Self>) -> Result<ActiveServiceOperation, DurableCSpaceError> {
        let task = exec::current_task_id().ok_or(DurableCSpaceError::OutsideTask)?;
        let domain = heap::current_domain();
        let token = NEXT_ACTIVE_TOKEN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .expect("durable CSpace operation token space exhausted");
        let mut active = self.active.lock();
        if active.is_some() {
            return Err(DurableCSpaceError::Busy);
        }
        *active = Some(DurableActiveClaim {
            task,
            domain,
            token,
            reservation: None,
        });
        drop(active);
        Ok(ActiveServiceOperation {
            inner: self.clone(),
            task,
            domain,
            token,
            armed: true,
        })
    }

    fn take_claim(
        &self,
        task: exec::TaskId,
        domain: heap::AllocationDomain,
        token: Option<u64>,
    ) -> Option<DurableActiveClaim> {
        let mut active = self.active.lock();
        let matches = active.as_ref().is_some_and(|claim| {
            claim.task == task
                && claim.domain == domain
                && token.is_none_or(|expected| claim.token == expected)
        });
        if matches {
            active.take()
        } else {
            None
        }
    }

    fn clear_claim(&self, task: exec::TaskId, domain: heap::AllocationDomain, token: u64) -> bool {
        let reservation = {
            let active = self.active.lock();
            let Some(claim) = active.as_ref().filter(|claim| {
                claim.task == task && claim.domain == domain && claim.token == token
            }) else {
                return false;
            };
            claim.reservation
        };
        if let Some(reservation) = reservation {
            let _ = self.target.0.lock().cancel_persistent_slot(&reservation);
        }
        self.take_claim(task, domain, Some(token)).is_some()
    }

    fn quarantine_claim(
        &self,
        task: exec::TaskId,
        domain: heap::AllocationDomain,
        token: Option<u64>,
    ) -> bool {
        let claimed = self.active.lock().as_ref().is_some_and(|claim| {
            claim.task == task
                && claim.domain == domain
                && token.is_none_or(|expected| claim.token == expected)
        });
        if !claimed {
            return false;
        }

        // Retain the exact claim until both durable targets are fail-closed.
        // If any step below faults, raw cleanup can still attribute and repeat
        // this idempotent sequence instead of losing the recovery breadcrumb.
        self.dependent_started.store(false, Ordering::Release);
        self.state
            .store(DurableCSpaceState::FailedClosed as u8, Ordering::Release);
        let _ = self.target.0.lock().quarantine_persistent();
        self.saved_program.mark_failed_closed();
        self.take_claim(task, domain, token).is_some()
    }
}

impl DurableCSpaceService {
    pub(crate) fn new(
        journal: AuthorityJournal,
        target: Arc<Space>,
        saved_program: Arc<SavedProgramService>,
    ) -> Arc<Self> {
        let inner = Arc::new(DurableCSpaceInner {
            journal,
            target,
            saved_program,
            state: AtomicU8::new(DurableCSpaceState::Cold as u8),
            active: SpinLock::new(None),
            dependent_started: AtomicBool::new(false),
            graph: crate::sync::SpinLock::new(LiveGraph::default()),
        });
        {
            let mut installed = INSTALLED_DURABLE_CSPACE.lock();
            assert!(
                installed.is_none(),
                "only one durable CSpace service may own the fixed target"
            );
            *installed = Some(inner.clone());
        }
        Arc::new(Self { inner })
    }

    pub fn info(&self) -> DurableCSpaceInfo {
        let graph = self.inner.graph.lock();
        DurableCSpaceInfo {
            state: self.state(),
            live_grants: graph.live_grants,
            tombstones: graph.tombstones,
            dependent_started: self.inner.dependent_started.load(Ordering::Acquire),
        }
    }

    pub fn state(&self) -> DurableCSpaceState {
        DurableCSpaceState::from_raw(self.inner.state.load(Ordering::Acquire))
    }

    /// Explicit gate shared by the acceptance component and future `run hello`.
    /// No caller can pass it until store validation and atomic CSpace install
    /// have both completed.
    pub async fn wait_ready(&self) -> Result<(), DurableCSpaceError> {
        loop {
            match self.state() {
                DurableCSpaceState::Ready => return Ok(()),
                DurableCSpaceState::FailedClosed => return Err(DurableCSpaceError::FailedClosed),
                DurableCSpaceState::Cold
                | DurableCSpaceState::WaitingBlock
                | DurableCSpaceState::Recovering => exec::sleep_ms(1).await,
            }
        }
    }

    pub(crate) fn begin_boot_recovery(&self) -> Result<ActiveServiceOperation, DurableCSpaceError> {
        let operation = self.inner.begin_claim()?;
        if let Err(error) =
            self.transition(DurableCSpaceState::Cold, DurableCSpaceState::WaitingBlock)
        {
            operation.fail();
            return Err(error);
        }
        Ok(operation)
    }

    pub(crate) async fn recover_after_block_online(&self) -> Result<(), DurableCSpaceError> {
        if !virtio_blk::is_online() {
            return Err(StoreError::Backend(virtio_blk::BlockError::Offline).into());
        }
        self.transition(
            DurableCSpaceState::WaitingBlock,
            DurableCSpaceState::Recovering,
        )?;

        // Capture the target before the first await. The atomic installer
        // checks this exact incarnation after journal recovery completes.
        let expected_incarnation = self.inner.target.0.lock().incarnation();
        let expected_program_incarnation = self.inner.saved_program.target().0.lock().incarnation();
        let result = async {
            let snapshot = self.inner.journal.recover().await?;
            let trusted = authorize_snapshot(snapshot)?;
            let identities = self
                .inner
                .target
                .0
                .lock()
                .install_recovered_graph(
                    expected_incarnation,
                    &trusted.slots,
                    &trusted.grants,
                    &trusted.resources,
                )
                .map_err(|_| DurableCSpaceError::Install)?;
            let program_identities = self
                .inner
                .saved_program
                .target()
                .0
                .lock()
                .install_recovered_graph(
                    expected_program_incarnation,
                    &trusted.program.slots,
                    &trusted.program.grants,
                    &trusted.program.resources,
                )
                .map_err(|_| DurableCSpaceError::Install)?;
            if program_identities.len() != usize::from(trusted.program.live) {
                return Err(DurableCSpaceError::Install);
            }
            self.inner
                .saved_program
                .install_recovered(program_identities.first().copied())
                .map_err(|_| DurableCSpaceError::Install)?;
            self.install_live_graph(&identities, trusted.shape);
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                self.transition(DurableCSpaceState::Recovering, DurableCSpaceState::Ready)?;
                Ok(())
            }
            Err(error) => {
                let next = if retryable_boot_recovery_error(&error) {
                    DurableCSpaceState::WaitingBlock
                } else {
                    DurableCSpaceState::FailedClosed
                };
                self.inner.state.store(next as u8, Ordering::Release);
                Err(error)
            }
        }
    }

    pub(crate) fn fail_closed(&self) {
        self.inner.dependent_started.store(false, Ordering::Release);
        self.inner
            .state
            .store(DurableCSpaceState::FailedClosed as u8, Ordering::Release);
        let _ = self.inner.target.0.lock().quarantine_persistent();
        self.inner.saved_program.mark_failed_closed();
    }

    pub(crate) async fn activate_dependent(&self) -> Result<(), DurableCSpaceError> {
        self.wait_ready().await?;
        // The first target-CSpace observation occurs strictly after Ready.
        let _ = self.inner.target.0.lock().incarnation();
        self.inner.dependent_started.store(true, Ordering::Release);
        Ok(())
    }

    fn transition(
        &self,
        from: DurableCSpaceState,
        to: DurableCSpaceState,
    ) -> Result<(), DurableCSpaceError> {
        self.inner
            .state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| DurableCSpaceError::UnexpectedGraph)
    }

    fn install_live_graph(&self, identities: &[PersistentCapIdentity], shape: ValidatedGraphShape) {
        let mut graph = LiveGraph {
            root: None,
            child: None,
            descendant: None,
            child_history_generation: shape.child_history_generation,
            descendant_history_generation: shape.descendant_history_generation,
            live_grants: identities.len(),
            tombstones: shape.tombstones,
        };
        for identity in identities {
            debug_assert_eq!(identity.space(), persistent_space_id());
            match identity.slot() {
                ROOT_SLOT => {
                    debug_assert!(graph.root.is_none());
                    graph.root = Some(*identity);
                }
                CHILD_SLOT => {
                    debug_assert!(graph.child.is_none());
                    graph.child = Some(*identity);
                }
                GRANDCHILD_SLOT => {
                    debug_assert!(graph.descendant.is_none());
                    graph.descendant = Some(*identity);
                }
                _ => debug_assert!(false, "prevalidated graph returned an extra slot"),
            }
        }
        *self.inner.graph.lock() = graph;
    }

    async fn run_test(&self) -> Result<PersistentTestReport, DurableCSpaceError> {
        self.wait_ready().await?;
        while !self.inner.dependent_started.load(Ordering::Acquire) {
            exec::sleep_ms(1).await;
        }
        let operation = self.inner.begin_claim()?;
        // Every durable publication below revalidates this pre-await target
        // incarnation through a pending reservation or exact witness.
        let expected_incarnation = self.inner.target.0.lock().incarnation();
        let (root, child, descendant, child_history, descendant_history) = {
            let graph = self.inner.graph.lock();
            (
                graph.root,
                graph.child,
                graph.descendant,
                graph.child_history_generation,
                graph.descendant_history_generation,
            )
        };
        let result = match (root, child, descendant, child_history, descendant_history) {
            (None, None, None, None, None) => {
                self.complete_boot1(&operation, expected_incarnation, None, None, None)
                    .await
            }
            (Some(root), None, None, None, None) => {
                self.complete_boot1(&operation, expected_incarnation, Some(root), None, None)
                    .await
            }
            (Some(root), Some(child), None, Some(0), None) if child.generation() == 0 => {
                self.complete_boot1(
                    &operation,
                    expected_incarnation,
                    Some(root),
                    Some(child),
                    None,
                )
                .await
            }
            (Some(root), Some(child), Some(descendant), Some(0), Some(0))
                if child.generation() == 0 && descendant.generation() == 0 =>
            {
                self.read_and_revoke(root, child, descendant).await
            }
            (Some(root), None, None, Some(0), Some(0)) => {
                self.reuse_child_slot(&operation, root, expected_incarnation)
                    .await
            }
            (Some(root), Some(child), None, Some(generation), Some(0)) if generation >= 1 => {
                let read_ok = self.read_identity(child).await?;
                Ok(self.report(
                    PersistentTestPhase::AlreadyComplete,
                    root,
                    child,
                    generation.saturating_sub(1),
                    read_ok,
                    true,
                    true,
                ))
            }
            _ => Err(DurableCSpaceError::UnexpectedGraph),
        };
        if result.is_ok() {
            operation.finish();
        } else {
            // An append error can be ambiguous after its final flush. Any
            // ordinary error therefore quarantines the target just like raw
            // fault/cancellation; only reboot recovery may reopen authority.
            operation.fail();
        }
        result
    }

    async fn complete_boot1(
        &self,
        operation: &ActiveServiceOperation,
        expected_incarnation: u64,
        root: Option<PersistentCapIdentity>,
        child: Option<PersistentCapIdentity>,
        descendant: Option<PersistentCapIdentity>,
    ) -> Result<PersistentTestReport, DurableCSpaceError> {
        let root = match root {
            Some(root) => root,
            None => self.persist_root(operation, expected_incarnation).await?,
        };
        let child = match child {
            Some(child) => child,
            None => {
                self.persist_child(
                    operation,
                    expected_incarnation,
                    root,
                    CHILD_SLOT,
                    0,
                    CHILD_RIGHTS,
                )
                .await?
            }
        };
        let descendant = match descendant {
            Some(descendant) => descendant,
            None => {
                self.persist_child(
                    operation,
                    expected_incarnation,
                    child,
                    GRANDCHILD_SLOT,
                    0,
                    GRANDCHILD_RIGHTS,
                )
                .await?
            }
        };
        let read_ok = self.read_identity(descendant).await?;
        Ok(self.report(
            PersistentTestPhase::Boot1Created,
            root,
            child,
            0,
            read_ok,
            false,
            false,
        ))
    }

    async fn persist_root(
        &self,
        operation: &ActiveServiceOperation,
        expected_incarnation: u64,
    ) -> Result<PersistentCapIdentity, DurableCSpaceError> {
        let mut snapshot = self.inner.journal.recover().await?;
        let mut object = unique_marker_object(&snapshot)?;
        if object.is_none() {
            let ids = reserve_ids(&snapshot, 2)?;
            let expected = snapshot.checkpoint;
            let mut chain = snapshot.chain()?;
            let mut records = Vec::new();
            if !snapshot.formatted {
                records.push(
                    chain
                        .append(None, durable::RecordBody::Format)
                        .map_err(|_| DurableCSpaceError::Encode)?,
                );
            }
            let (high_water, next) = durable::preview_id_high_water(&chain, ids.exclusive_end)
                .map_err(|_| DurableCSpaceError::Encode)?;
            records.extend(high_water.records);
            chain = next;
            let (transaction, _next) = object_codec::preview_object_transaction(
                &chain,
                transaction_id(ids.first),
                object_id(ids.first + 1),
                persistent_object_kind(),
                MARKER,
            )
            .map_err(|_| DurableCSpaceError::Encode)?;
            records.extend(transaction.records);
            snapshot = self.inner.journal.append(expected, &records).await?;
            object = unique_marker_object(&snapshot)?;
        }
        let object = object.ok_or(DurableCSpaceError::UnexpectedGraph)?;

        let target = operation.reserve(expected_incarnation)?;
        if target
            != (SlotIdentity {
                space: persistent_space_id(),
                slot: ROOT_SLOT,
                generation: 0,
            })
        {
            return Err(DurableCSpaceError::Install);
        }
        let ids = reserve_ids(&snapshot, 2)?;
        let grant = GrantRecord {
            derivation_id: derivation_id(ids.first + 1),
            parent_id: None,
            object_id: object.object_id,
            target,
            rights: ROOT_RIGHTS,
            resource_kind: stored_object_resource_kind(),
            flags: GrantFlags::ROOT,
        };
        let committed = self
            .append_grant(
                snapshot,
                transaction_id(ids.first),
                ids.exclusive_end,
                &grant,
            )
            .await?;
        let resource = StoredObject::from_recovered(&object);
        let identity = operation.install_root(&grant, resource)?;
        self.refresh_live_graph(committed)?;
        Ok(identity)
    }

    async fn persist_child(
        &self,
        operation: &ActiveServiceOperation,
        expected_incarnation: u64,
        parent: PersistentCapIdentity,
        slot: u32,
        generation: u64,
        rights: DurableRights,
    ) -> Result<PersistentCapIdentity, DurableCSpaceError> {
        let target = operation.reserve(expected_incarnation)?;
        if target
            != (SlotIdentity {
                space: persistent_space_id(),
                slot,
                generation,
            })
        {
            return Err(DurableCSpaceError::Install);
        }
        let parent_witness: PersistentDerivationWitness<StoredObject> = self
            .inner
            .target
            .0
            .lock()
            .persistent_witness_for_identity(parent, Rights::GRANT)
            .map_err(|_| DurableCSpaceError::Install)?;
        let snapshot = self.inner.journal.recover().await?;
        let ids = reserve_ids(&snapshot, 2)?;
        let grant = GrantRecord {
            derivation_id: derivation_id(ids.first + 1),
            parent_id: Some(parent.derivation_id()),
            object_id: parent.object_id(),
            target,
            rights,
            resource_kind: stored_object_resource_kind(),
            flags: GrantFlags::DERIVED,
        };
        let committed = self
            .append_grant(
                snapshot,
                transaction_id(ids.first),
                ids.exclusive_end,
                &grant,
            )
            .await?;
        let identity = operation.install_child(&parent_witness, &grant)?;
        self.refresh_live_graph(committed)?;
        Ok(identity)
    }

    async fn append_grant(
        &self,
        snapshot: AuthoritySnapshot,
        transaction_id: TransactionId,
        exclusive_end: u128,
        grant: &GrantRecord,
    ) -> Result<AuthoritySnapshot, DurableCSpaceError> {
        let expected = snapshot.checkpoint;
        let mut chain = snapshot.chain()?;
        let (high_water, next) = durable::preview_id_high_water(&chain, exclusive_end)
            .map_err(|_| DurableCSpaceError::Encode)?;
        let mut records = high_water.records;
        chain = next;
        let (transaction, _next) =
            durable::preview_grant_transaction(&chain, transaction_id, grant.clone())
                .map_err(|_| DurableCSpaceError::Encode)?;
        records.extend(transaction.records);
        Ok(self.inner.journal.append(expected, &records).await?)
    }

    fn refresh_live_graph(&self, snapshot: AuthoritySnapshot) -> Result<(), DurableCSpaceError> {
        let trusted = authorize_snapshot(snapshot)?;
        let live = identities_from_live_cspace(&self.inner.target, &trusted.grants)?;
        self.install_live_graph(&live, trusted.shape);
        Ok(())
    }

    async fn read_and_revoke(
        &self,
        root: PersistentCapIdentity,
        child: PersistentCapIdentity,
        descendant: PersistentCapIdentity,
    ) -> Result<PersistentTestReport, DurableCSpaceError> {
        let read_ok = self.read_identity(descendant).await?;
        let root_witness = self
            .inner
            .target
            .0
            .lock()
            .persistent_witness_for_identity::<StoredObject>(root, Rights::REVOKE)
            .map_err(|_| DurableCSpaceError::Install)?;
        let snapshot = self.inner.journal.recover().await?;
        let ids = reserve_ids(&snapshot, 1)?;
        let expected = snapshot.checkpoint;
        let mut chain = snapshot.chain()?;
        let (high_water, next) = durable::preview_id_high_water(&chain, ids.exclusive_end)
            .map_err(|_| DurableCSpaceError::Encode)?;
        let mut records = high_water.records;
        chain = next;
        let (tombstone, _next) = durable::preview_revoke_transaction(
            &chain,
            transaction_id(ids.first),
            child.derivation_id(),
        )
        .map_err(|_| DurableCSpaceError::Encode)?;
        records.extend(tombstone.records);
        let committed = self.inner.journal.append(expected, &records).await?;

        // No await exists between the verified tombstone flush and this exact
        // ancestor-authorized live revoke.
        let retired = self
            .inner
            .target
            .0
            .lock()
            .complete_persistent_revoke(&root_witness, child)
            .map_err(|_| DurableCSpaceError::Install)?;
        if retired == 0 {
            return Err(DurableCSpaceError::Install);
        }
        let (old_child_absent, descendant_absent) = {
            let target = self.inner.target.0.lock();
            (
                target
                    .lookup_persistent_identity::<StoredObject>(child, Rights::NONE)
                    .is_err(),
                target
                    .lookup_persistent_identity::<StoredObject>(descendant, Rights::NONE)
                    .is_err(),
            )
        };
        if !old_child_absent || !descendant_absent {
            return Err(DurableCSpaceError::Install);
        }
        let trusted = authorize_snapshot(committed)?;
        let live = identities_from_live_cspace(&self.inner.target, &trusted.grants)?;
        self.install_live_graph(&live, trusted.shape);
        Ok(self.report(
            PersistentTestPhase::Boot2Revoked,
            root,
            child,
            child.generation(),
            read_ok,
            old_child_absent,
            descendant_absent,
        ))
    }

    async fn reuse_child_slot(
        &self,
        operation: &ActiveServiceOperation,
        root: PersistentCapIdentity,
        expected_incarnation: u64,
    ) -> Result<PersistentTestReport, DurableCSpaceError> {
        let old_generation = self
            .inner
            .graph
            .lock()
            .child_history_generation
            .ok_or(DurableCSpaceError::UnexpectedGraph)?;
        let old_child_absent = self
            .inner
            .target
            .0
            .lock()
            .list()
            .iter()
            .all(|(cap, _, _, _)| cap.slot() != CHILD_SLOT);
        if !old_child_absent {
            return Err(DurableCSpaceError::Install);
        }
        let target = operation.reserve(expected_incarnation)?;
        if target.slot != CHILD_SLOT || target.generation <= old_generation {
            return Err(DurableCSpaceError::Install);
        }
        let root_witness: PersistentDerivationWitness<StoredObject> = self
            .inner
            .target
            .0
            .lock()
            .persistent_witness_for_identity(root, Rights::GRANT)
            .map_err(|_| DurableCSpaceError::Install)?;
        let snapshot = self.inner.journal.recover().await?;
        let ids = reserve_ids(&snapshot, 2)?;
        let grant = GrantRecord {
            derivation_id: derivation_id(ids.first + 1),
            parent_id: Some(root.derivation_id()),
            object_id: root.object_id(),
            target,
            rights: CHILD_RIGHTS,
            resource_kind: stored_object_resource_kind(),
            flags: GrantFlags::DERIVED,
        };
        let expected = snapshot.checkpoint;
        let mut chain = snapshot.chain()?;
        let (high_water, next) = durable::preview_id_high_water(&chain, ids.exclusive_end)
            .map_err(|_| DurableCSpaceError::Encode)?;
        let mut records = high_water.records;
        chain = next;
        let (grant_transaction, _next) =
            durable::preview_grant_transaction(&chain, transaction_id(ids.first), grant.clone())
                .map_err(|_| DurableCSpaceError::Encode)?;
        records.extend(grant_transaction.records);
        let committed = self.inner.journal.append(expected, &records).await?;

        let child = operation.install_child(&root_witness, &grant)?;
        self.refresh_live_graph(committed)?;
        let read_ok = self.read_identity(child).await?;
        Ok(self.report(
            PersistentTestPhase::Boot3Reused,
            root,
            child,
            old_generation,
            read_ok,
            old_child_absent,
            true,
        ))
    }

    async fn read_identity(
        &self,
        identity: PersistentCapIdentity,
    ) -> Result<bool, DurableCSpaceError> {
        let lease = self
            .inner
            .target
            .0
            .lock()
            .lookup_persistent_identity::<StoredObject>(identity, Rights::READ)
            .map_err(|_| DurableCSpaceError::Install)?;
        let bytes = self.inner.journal.read(lease).await?;
        Ok(bytes.as_slice() == MARKER)
    }

    fn report(
        &self,
        phase: PersistentTestPhase,
        root: PersistentCapIdentity,
        child: PersistentCapIdentity,
        old_child_generation: u64,
        read_ok: bool,
        old_child_absent: bool,
        descendant_absent: bool,
    ) -> PersistentTestReport {
        let no_store_write =
            self.inner
                .target
                .0
                .lock()
                .list()
                .iter()
                .all(|(_cap, kind, rights, _description)| {
                    *kind == "stored-object" && !rights.contains(Rights::WRITE)
                });
        PersistentTestReport {
            phase,
            root_slot: root.slot(),
            root_generation: root.generation(),
            child_slot: child.slot(),
            old_child_generation,
            child_generation: child.generation(),
            read_ok,
            old_child_absent,
            descendant_absent,
            no_store_write,
            dependent_started: self.inner.dependent_started.load(Ordering::Acquire),
        }
    }
}

fn retryable_boot_recovery_error(error: &DurableCSpaceError) -> bool {
    matches!(
        error,
        DurableCSpaceError::Store(StoreError::Busy | StoreError::JournalChanged)
            | DurableCSpaceError::Store(StoreError::Backend(
                virtio_blk::BlockError::Offline
                    | virtio_blk::BlockError::DriverFault
                    | virtio_blk::BlockError::DriverRestarted
            ))
    )
}

/// Quarantine persistent authority abandoned by one exact faulted task.
///
/// # Safety
///
/// `task` in `domain` must be permanently detached and unable to resume. The
/// cleanup path performs no allocation and drops no persistent resource.
pub(crate) unsafe fn recover_faulted_task(task: exec::TaskId, domain: heap::AllocationDomain) {
    let installed = INSTALLED_DURABLE_CSPACE.lock();
    let Some(inner) = installed.as_ref() else {
        return;
    };

    // Safety: the executor detached the exact task before this hook. Repair
    // each possibly abandoned lock before taking it. The saved-program hook is
    // ordered before this one in `cleanup_faulted_task`, because quarantine of
    // a durable boot claim also fail-closes the saved-program target.
    let _ = unsafe { inner.active.recover_after_fault(domain) };
    let _ = unsafe { inner.target.0.recover_after_fault(domain) };
    let _ = unsafe { inner.graph.recover_after_fault(domain) };

    // Keep the exact claim published until both CSpaces have been quarantined.
    // Repeating this after a partially completed cleanup is intentionally safe.
    let _ = inner.quarantine_claim(task, domain, None);
}

impl Resource for DurableCSpaceService {
    fn kind(&self) -> &'static str {
        "durable-cspace"
    }

    fn describe(&self) -> String {
        let info = self.info();
        format!(
            "persistent-test CSpace [{:?}, {} live grants, {} tombstones]",
            info.state, info.live_grants, info.tombstones
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub async fn test_with(
    lease: InvocationLease<DurableCSpaceService>,
) -> Result<PersistentTestReport, DurableCSpaceError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(DurableCSpaceError::PermissionDenied);
    }
    let service = lease.with(|service| service.inner.clone());
    DurableCSpaceService { inner: service }.run_test().await
}

pub(crate) struct ActiveServiceOperation {
    inner: Arc<DurableCSpaceInner>,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    armed: bool,
}

impl ActiveServiceOperation {
    fn reserve(&self, expected_incarnation: u64) -> Result<SlotIdentity, DurableCSpaceError> {
        let reservation = self
            .inner
            .target
            .0
            .lock()
            .reserve_persistent_slot(expected_incarnation)
            .map_err(|_| DurableCSpaceError::Install)?;
        let target = reservation.target();
        let mut active = self.inner.active.lock();
        let matching = active.as_mut().filter(|claim| {
            claim.task == self.task
                && claim.domain == self.domain
                && claim.token == self.token
                && claim.reservation.is_none()
        });
        if let Some(claim) = matching {
            // The reservation is copied into SYSTEM-stable state immediately
            // after reserve returns; no allocation or await exists in between.
            claim.reservation = Some(reservation);
            return Ok(target);
        }
        drop(active);
        let _ = self
            .inner
            .target
            .0
            .lock()
            .cancel_persistent_slot(&reservation);
        Err(DurableCSpaceError::Install)
    }

    fn reservation(&self) -> Result<PendingSlotReservation, DurableCSpaceError> {
        self.inner
            .active
            .lock()
            .as_ref()
            .filter(|claim| {
                claim.task == self.task && claim.domain == self.domain && claim.token == self.token
            })
            .and_then(|claim| claim.reservation)
            .ok_or(DurableCSpaceError::Install)
    }

    fn consume_reservation(
        &self,
        reservation: PendingSlotReservation,
    ) -> Result<(), DurableCSpaceError> {
        let mut active = self.inner.active.lock();
        let claim = active
            .as_mut()
            .filter(|claim| {
                claim.task == self.task
                    && claim.domain == self.domain
                    && claim.token == self.token
                    && claim.reservation == Some(reservation)
            })
            .ok_or(DurableCSpaceError::Install)?;
        claim.reservation = None;
        Ok(())
    }

    fn install_root(
        &self,
        grant: &GrantRecord,
        resource: Arc<StoredObject>,
    ) -> Result<PersistentCapIdentity, DurableCSpaceError> {
        let reservation = self.reservation()?;
        let result = self
            .inner
            .target
            .0
            .lock()
            .install_reserved_root(&reservation, grant, resource)
            .map(|(_cap, witness)| witness.identity())
            .map_err(|_| DurableCSpaceError::Install)?;
        self.consume_reservation(reservation)?;
        Ok(result)
    }

    fn install_child(
        &self,
        parent: &PersistentDerivationWitness<StoredObject>,
        grant: &GrantRecord,
    ) -> Result<PersistentCapIdentity, DurableCSpaceError> {
        let reservation = self.reservation()?;
        let result = self
            .inner
            .target
            .0
            .lock()
            .install_reserved_child(&reservation, parent, grant)
            .map(|(_cap, witness)| witness.identity())
            .map_err(|_| DurableCSpaceError::Install)?;
        self.consume_reservation(reservation)?;
        Ok(result)
    }

    pub(crate) fn finish(mut self) {
        assert!(
            self.inner.clear_claim(self.task, self.domain, self.token),
            "only the exact durable CSpace operation may release its claim"
        );
        self.armed = false;
    }

    pub(crate) fn fail(mut self) {
        assert!(
            self.inner
                .quarantine_claim(self.task, self.domain, Some(self.token)),
            "only the exact durable CSpace operation may quarantine its claim"
        );
        self.armed = false;
    }
}

impl Drop for ActiveServiceOperation {
    fn drop(&mut self) {
        if self.armed {
            let cleaned = self
                .inner
                .quarantine_claim(self.task, self.domain, Some(self.token));
            debug_assert!(cleaned, "a live durable claim must remain exact");
        }
    }
}

struct TrustedSnapshot {
    slots: Vec<RecoveredSlot>,
    grants: Vec<RecoveredGrant>,
    resources: Vec<PersistentResourceWitness>,
    shape: ValidatedGraphShape,
    program: TrustedProgram,
}

fn authorize_snapshot(snapshot: AuthoritySnapshot) -> Result<TrustedSnapshot, DurableCSpaceError> {
    let Some(preflight) = snapshot.preflight else {
        return Ok(TrustedSnapshot {
            slots: Vec::new(),
            grants: Vec::new(),
            resources: Vec::new(),
            shape: ValidatedGraphShape {
                child_history_generation: None,
                descendant_history_generation: None,
                tombstones: 0,
            },
            program: TrustedProgram {
                slots: Vec::new(),
                grants: Vec::new(),
                resources: Vec::new(),
                live: false,
            },
        });
    };
    let committed_grants = preflight.committed_grants().to_vec();
    let persistent_committed_grants: Vec<_> = committed_grants
        .iter()
        .filter(|grant| grant.grant.target.space == persistent_space_id())
        .cloned()
        .collect();
    // Root selection is global. Each independently owned SpaceId contributes a
    // constraint only when its slot history says it has live authority; finish
    // then rejects every extra root not present in this union.
    let has_live_authority = preflight
        .slots()
        .iter()
        .any(|slot| slot.space == persistent_space_id() && slot.live_derivation.is_some());
    let has_live_program = preflight.slots().iter().any(|slot| {
        slot.space == program_model::program_space_id() && slot.live_derivation.is_some()
    });
    let persistent_constraints = [RootConstraint {
        space: persistent_space_id(),
        first_slot: ROOT_SLOT,
        last_slot_inclusive: ROOT_SLOT,
        rights: RootRightsConstraint::exact(ROOT_RIGHTS),
        resource_kind: stored_object_resource_kind(),
        object_kind: persistent_object_kind(),
    }];
    let program_constraints = [program_model::program_root_constraint()];
    let mut partitions = Vec::new();
    if has_live_authority {
        partitions.push(RootPolicyPartition {
            space: persistent_space_id(),
            constraints: &persistent_constraints,
        });
    }
    if has_live_program {
        partitions.push(RootPolicyPartition {
            space: program_model::program_space_id(),
            constraints: &program_constraints,
        });
    }
    let roots = program_model::select_root_policy_union(&preflight, &partitions)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    if has_live_program
        && !roots.iter().any(|root| {
            root.grant.target.space == program_model::program_space_id()
                && program_model::program_root_policy_is_exact(root)
        })
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let root_object = roots
        .iter()
        .find(|root| root.grant.target.space == persistent_space_id())
        .map(|root| {
            if root.grant.target.generation != 0 {
                return Err(DurableCSpaceError::RootPolicy);
            }
            let object = preflight
                .committed_objects()
                .iter()
                .find(|object| object.object_id == root.grant.object_id)
                .ok_or(DurableCSpaceError::RootPolicy)?;
            if object.object_kind != persistent_object_kind() {
                return Err(DurableCSpaceError::RootPolicy);
            }
            Ok(StoredObject::from_recovered(object))
        })
        .transpose()?;
    let recovered = preflight
        .finish(&roots)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    let policy_spaces = [persistent_space_id(), program_model::program_space_id()];
    let tombstone_partitions = program_model::partition_tombstones_by_space(
        &committed_grants,
        &recovered.tombstones,
        &policy_spaces,
    )
    .map_err(|_| DurableCSpaceError::RootPolicy)?;
    let persistent_tombstones = tombstone_partitions
        .iter()
        .find(|partition| partition.space == persistent_space_id())
        .ok_or(DurableCSpaceError::RootPolicy)?
        .tombstones
        .clone();
    let program_tombstones = tombstone_partitions
        .iter()
        .find(|partition| partition.space == program_model::program_space_id())
        .ok_or(DurableCSpaceError::RootPolicy)?
        .tombstones
        .clone();
    if recovered.grants.iter().any(|grant| {
        !matches!(
            grant.grant.target.space,
            space if space == persistent_space_id() || space == program_model::program_space_id()
        )
    }) || recovered.slots.iter().any(|slot| {
        slot.space != persistent_space_id() && slot.space != program_model::program_space_id()
    }) {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let persistent = RecoveredStore {
        store_id: recovered.store_id,
        id_high_water: recovered.id_high_water,
        grants: recovered
            .grants
            .iter()
            .filter(|grant| grant.grant.target.space == persistent_space_id())
            .cloned()
            .collect(),
        objects: recovered.objects.clone(),
        slots: recovered
            .slots
            .iter()
            .filter(|slot| slot.space == persistent_space_id())
            .copied()
            .collect(),
        tombstones: persistent_tombstones,
        last_sequence: recovered.last_sequence,
        last_crc32c: recovered.last_crc32c,
    };
    if persistent.grants.iter().any(|grant| {
        grant.grant.resource_kind != stored_object_resource_kind()
            || grant.grant.rights.contains(DurableRights::WRITE)
    }) {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let shape = validate_fixed_graph_shape(&persistent_committed_grants, &persistent)?;
    let persistent_root = roots
        .iter()
        .find(|root| root.grant.target.space == persistent_space_id());
    let resources = match (persistent_root, root_object) {
        (Some(root), Some(object)) => vec![PersistentResourceWitness::new(
            root.grant.object_id,
            stored_object_resource_kind(),
            object,
        )],
        (None, None) => Vec::new(),
        _ => return Err(DurableCSpaceError::RootPolicy),
    };
    let program_recovered = RecoveredStore {
        store_id: recovered.store_id,
        id_high_water: recovered.id_high_water,
        grants: recovered
            .grants
            .iter()
            .filter(|grant| grant.grant.target.space == program_model::program_space_id())
            .cloned()
            .collect(),
        objects: recovered.objects,
        slots: recovered
            .slots
            .iter()
            .filter(|slot| slot.space == program_model::program_space_id())
            .copied()
            .collect(),
        tombstones: program_tombstones,
        last_sequence: recovered.last_sequence,
        last_crc32c: recovered.last_crc32c,
    };
    let program = saved_program::authorize_recovered(&program_recovered)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    Ok(TrustedSnapshot {
        slots: persistent.slots,
        grants: persistent.grants,
        resources,
        shape,
        program,
    })
}

fn validate_fixed_graph_shape(
    committed: &[RecoveredGrant],
    recovered: &durable::RecoveredStore,
) -> Result<ValidatedGraphShape, DurableCSpaceError> {
    fn slot(
        slots: &[RecoveredSlot],
        number: u32,
        generation: u64,
        live: Option<DerivationId>,
    ) -> bool {
        slots.iter().any(|candidate| {
            candidate.space == persistent_space_id()
                && candidate.slot == number
                && candidate.max_generation == generation
                && candidate.live_derivation == live
        })
    }

    fn grant_at(grants: &[RecoveredGrant], number: u32, generation: u64) -> Option<&GrantRecord> {
        grants
            .iter()
            .map(|recovered| &recovered.grant)
            .find(|grant| {
                grant.target.space == persistent_space_id()
                    && grant.target.slot == number
                    && grant.target.generation == generation
            })
    }

    fn exact_root(grant: &GrantRecord) -> bool {
        grant.target.space == persistent_space_id()
            && grant.target.slot == ROOT_SLOT
            && grant.target.generation == 0
            && grant.parent_id.is_none()
            && grant.rights == ROOT_RIGHTS
            && grant.resource_kind == stored_object_resource_kind()
            && grant.flags == GrantFlags::ROOT
    }

    fn exact_child(
        grant: &GrantRecord,
        slot: u32,
        generation: u64,
        parent: DerivationId,
        object: ObjectId,
        rights: DurableRights,
    ) -> bool {
        grant.target.space == persistent_space_id()
            && grant.target.slot == slot
            && grant.target.generation == generation
            && grant.parent_id == Some(parent)
            && grant.object_id == object
            && grant.rights == rights
            && grant.resource_kind == stored_object_resource_kind()
            && grant.flags == GrantFlags::DERIVED
    }

    fn exact_live(grants: &[RecoveredGrant], expected: &[DerivationId]) -> bool {
        grants.len() == expected.len()
            && expected.iter().all(|derivation| {
                grants
                    .iter()
                    .any(|grant| grant.grant.derivation_id == *derivation)
            })
    }

    fn exact_tombstones(actual: &[DerivationId], expected: &[DerivationId]) -> bool {
        actual.len() == expected.len()
            && expected
                .iter()
                .all(|derivation| actual.contains(derivation))
    }

    if recovered.slots.is_empty() {
        if committed.is_empty() && recovered.grants.is_empty() && recovered.tombstones.is_empty() {
            return Ok(ValidatedGraphShape {
                child_history_generation: None,
                descendant_history_generation: None,
                tombstones: 0,
            });
        }
        return Err(DurableCSpaceError::UnexpectedGraph);
    }

    let root = grant_at(committed, ROOT_SLOT, 0)
        .filter(|grant| exact_root(grant))
        .ok_or(DurableCSpaceError::UnexpectedGraph)?;
    let root_commit_sequence = committed
        .iter()
        .find(|recovered| recovered.grant.derivation_id == root.derivation_id)
        .map(|recovered| recovered.commit_sequence)
        .ok_or(DurableCSpaceError::UnexpectedGraph)?;
    if !recovered.objects.iter().any(|object| {
        object.object_id == root.object_id
            && object.object_kind == persistent_object_kind()
            && object.commit_sequence < root_commit_sequence
    }) {
        return Err(DurableCSpaceError::UnexpectedGraph);
    }

    // A root tombstone leaves no authority to publish but its complete fixed
    // slot history remains valid input for future generation safety. Accept
    // only exact prefixes of the fixed graph (plus the one replacement phase),
    // never arbitrary dead slots or malformed committed grants.
    if recovered.grants.is_empty()
        && recovered
            .slots
            .iter()
            .all(|slot| slot.live_derivation.is_none())
    {
        let root_dead = slot(&recovered.slots, ROOT_SLOT, 0, None);
        if committed.len() == 1
            && recovered.slots.len() == 1
            && root_dead
            && exact_tombstones(&recovered.tombstones, &[root.derivation_id])
        {
            return Ok(ValidatedGraphShape {
                child_history_generation: None,
                descendant_history_generation: None,
                tombstones: 1,
            });
        }

        let child = grant_at(committed, CHILD_SLOT, 0).filter(|grant| {
            exact_child(
                grant,
                CHILD_SLOT,
                0,
                root.derivation_id,
                root.object_id,
                CHILD_RIGHTS,
            )
        });
        if let Some(child) = child {
            let child_dead = slot(&recovered.slots, CHILD_SLOT, 0, None);
            if committed.len() == 2
                && recovered.slots.len() == 2
                && root_dead
                && child_dead
                && exact_tombstones(&recovered.tombstones, &[root.derivation_id])
            {
                return Ok(ValidatedGraphShape {
                    child_history_generation: Some(0),
                    descendant_history_generation: None,
                    tombstones: 1,
                });
            }

            let descendant = grant_at(committed, GRANDCHILD_SLOT, 0).filter(|grant| {
                exact_child(
                    grant,
                    GRANDCHILD_SLOT,
                    0,
                    child.derivation_id,
                    root.object_id,
                    GRANDCHILD_RIGHTS,
                )
            });
            if descendant.is_some() {
                let descendant_dead = slot(&recovered.slots, GRANDCHILD_SLOT, 0, None);
                if committed.len() == 3
                    && recovered.slots.len() == 3
                    && root_dead
                    && child_dead
                    && descendant_dead
                    && exact_tombstones(&recovered.tombstones, &[root.derivation_id])
                {
                    return Ok(ValidatedGraphShape {
                        child_history_generation: Some(0),
                        descendant_history_generation: Some(0),
                        tombstones: 1,
                    });
                }

                let replacement = grant_at(committed, CHILD_SLOT, 1).filter(|grant| {
                    exact_child(
                        grant,
                        CHILD_SLOT,
                        1,
                        root.derivation_id,
                        root.object_id,
                        CHILD_RIGHTS,
                    )
                });
                if replacement.is_some()
                    && committed.len() == 4
                    && recovered.slots.len() == 3
                    && root_dead
                    && slot(&recovered.slots, CHILD_SLOT, 1, None)
                    && descendant_dead
                    && exact_tombstones(
                        &recovered.tombstones,
                        &[root.derivation_id, child.derivation_id],
                    )
                {
                    return Ok(ValidatedGraphShape {
                        child_history_generation: Some(1),
                        descendant_history_generation: Some(0),
                        tombstones: 2,
                    });
                }
            }
        }
        return Err(DurableCSpaceError::UnexpectedGraph);
    }

    if !slot(&recovered.slots, ROOT_SLOT, 0, Some(root.derivation_id)) {
        return Err(DurableCSpaceError::UnexpectedGraph);
    }

    if recovered.slots.len() == 1
        && committed.len() == 1
        && recovered.tombstones.is_empty()
        && exact_live(&recovered.grants, &[root.derivation_id])
    {
        return Ok(ValidatedGraphShape {
            child_history_generation: None,
            descendant_history_generation: None,
            tombstones: 0,
        });
    }

    let child = grant_at(committed, CHILD_SLOT, 0)
        .filter(|grant| {
            exact_child(
                grant,
                CHILD_SLOT,
                0,
                root.derivation_id,
                root.object_id,
                CHILD_RIGHTS,
            )
        })
        .ok_or(DurableCSpaceError::UnexpectedGraph)?;

    if recovered.slots.len() == 2
        && committed.len() == 2
        && recovered.tombstones.is_empty()
        && slot(&recovered.slots, CHILD_SLOT, 0, Some(child.derivation_id))
        && exact_live(
            &recovered.grants,
            &[root.derivation_id, child.derivation_id],
        )
    {
        return Ok(ValidatedGraphShape {
            child_history_generation: Some(0),
            descendant_history_generation: None,
            tombstones: 0,
        });
    }

    let descendant = grant_at(committed, GRANDCHILD_SLOT, 0)
        .filter(|grant| {
            exact_child(
                grant,
                GRANDCHILD_SLOT,
                0,
                child.derivation_id,
                root.object_id,
                GRANDCHILD_RIGHTS,
            )
        })
        .ok_or(DurableCSpaceError::UnexpectedGraph)?;
    if recovered.slots.len() != 3 {
        return Err(DurableCSpaceError::UnexpectedGraph);
    }

    if committed.len() == 3
        && recovered.tombstones.is_empty()
        && slot(&recovered.slots, CHILD_SLOT, 0, Some(child.derivation_id))
        && slot(
            &recovered.slots,
            GRANDCHILD_SLOT,
            0,
            Some(descendant.derivation_id),
        )
        && exact_live(
            &recovered.grants,
            &[
                root.derivation_id,
                child.derivation_id,
                descendant.derivation_id,
            ],
        )
    {
        return Ok(ValidatedGraphShape {
            child_history_generation: Some(0),
            descendant_history_generation: Some(0),
            tombstones: 0,
        });
    }

    let child_tombstone =
        recovered.tombstones.len() == 1 && recovered.tombstones[0] == child.derivation_id;
    let dead_initial_subtree = slot(&recovered.slots, CHILD_SLOT, 0, None)
        && slot(&recovered.slots, GRANDCHILD_SLOT, 0, None);
    if committed.len() == 3
        && child_tombstone
        && dead_initial_subtree
        && exact_live(&recovered.grants, &[root.derivation_id])
    {
        return Ok(ValidatedGraphShape {
            child_history_generation: Some(0),
            descendant_history_generation: Some(0),
            tombstones: 1,
        });
    }

    let replacement = grant_at(committed, CHILD_SLOT, 1)
        .filter(|grant| {
            exact_child(
                grant,
                CHILD_SLOT,
                1,
                root.derivation_id,
                root.object_id,
                CHILD_RIGHTS,
            )
        })
        .ok_or(DurableCSpaceError::UnexpectedGraph)?;
    if committed.len() == 4
        && child_tombstone
        && slot(
            &recovered.slots,
            CHILD_SLOT,
            1,
            Some(replacement.derivation_id),
        )
        && slot(&recovered.slots, GRANDCHILD_SLOT, 0, None)
        && exact_live(
            &recovered.grants,
            &[root.derivation_id, replacement.derivation_id],
        )
    {
        return Ok(ValidatedGraphShape {
            child_history_generation: Some(1),
            descendant_history_generation: Some(0),
            tombstones: 1,
        });
    }

    Err(DurableCSpaceError::UnexpectedGraph)
}

fn identities_from_live_cspace(
    target: &Space,
    grants: &[RecoveredGrant],
) -> Result<Vec<PersistentCapIdentity>, DurableCSpaceError> {
    let cspace = target.0.lock();
    grants
        .iter()
        .map(|recovered| {
            let grant = &recovered.grant;
            let identity = cspace
                .list()
                .into_iter()
                .find(|(cap, _, _, _)| {
                    cap.slot() == grant.target.slot
                        && cspace
                            .persistent_witness::<StoredObject>(*cap, Rights::NONE)
                            .is_ok_and(|witness| {
                                witness.identity().derivation_id() == grant.derivation_id
                            })
                })
                .and_then(|(cap, _, _, _)| {
                    cspace
                        .persistent_witness::<StoredObject>(cap, Rights::NONE)
                        .ok()
                        .map(|witness| witness.identity())
                });
            identity.ok_or(DurableCSpaceError::Install)
        })
        .collect()
}

fn unique_marker_object(
    snapshot: &AuthoritySnapshot,
) -> Result<Option<durable::RecoveredObject>, DurableCSpaceError> {
    let Some(preflight) = snapshot.preflight.as_ref() else {
        return Ok(None);
    };
    let mut matches = preflight.committed_objects().iter().filter(|object| {
        object.object_kind == persistent_object_kind() && object.bytes.as_slice() == MARKER
    });
    let first = matches.next().cloned();
    if matches.next().is_some() {
        return Err(DurableCSpaceError::UnexpectedGraph);
    }
    Ok(first)
}

struct ReservedIds {
    first: u128,
    exclusive_end: u128,
}

fn reserve_ids(
    snapshot: &AuthoritySnapshot,
    count: u128,
) -> Result<ReservedIds, DurableCSpaceError> {
    let first = snapshot
        .id_high_water()
        .max(PERSISTENT_SPACE_ID_RAW + 1)
        .max(1);
    let exclusive_end = first
        .checked_add(count)
        .ok_or(DurableCSpaceError::IdExhausted)?;
    Ok(ReservedIds {
        first,
        exclusive_end,
    })
}

fn transaction_id(raw: u128) -> TransactionId {
    TransactionId::new(raw).expect("reserved transaction ID is non-zero")
}

fn object_id(raw: u128) -> ObjectId {
    ObjectId::new(raw).expect("reserved object ID is non-zero")
}

fn derivation_id(raw: u128) -> DerivationId {
    DerivationId::new(raw).expect("reserved derivation ID is non-zero")
}
