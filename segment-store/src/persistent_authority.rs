//! Atomic persistent authority cutover and recovery.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_blob_format::{BlobDescriptor, LEAF_SIZE};
use vibeos_segment_format::{payload_sha256, ExtentKind, PhysicalPointer, ANCHOR_SEGMENT_NO};

use crate::allocation_v2::{encode_allocation_v2, AllocationTransition, SegmentAllocation};
use crate::authority::AuthorizedObject;
use crate::authority_snapshot::{
    encode_persistent_authority_snapshot, AuthoritySnapshotError, PersistentAuthorityImport,
    PersistentAuthoritySnapshot, PersistentObjectBinding, PersistentPrincipalPolicy,
};
use crate::cas::{
    recover_persistent_cas_object, recover_promotable_cas_object, CasObjectHandle, CasStoreError,
};
use crate::device::PageDevice;
use crate::gc::{
    publish_checkpoint, select_free_segments, verify_staged_payloads, GcError, GcStoreError,
    SegmentBuilder, SegmentPayload,
};
use crate::maintenance::{MaintenanceOperation, MaintenanceOperationLease, StoreMaintenance};
use crate::quota::{canonical_attributable_physical_bytes, QuotaReservation, StoragePrincipal};
use crate::root_codec::{PersistentRootEntry, PersistentRootSet};
use crate::store::{CapacityClass, CasMountedState, MountedState, SegmentStore, StoreError};

const METADATA_KIND_PERSISTENT_AUTHORITY: u32 = 0xffff_0021;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;

/// Store-bound proof used for subsequent authority transactions. It embeds an
/// attenuated maintenance capability but exposes no maintenance operation.
#[derive(Clone)]
pub struct PersistentAuthorityWriter {
    maintenance: StoreMaintenance,
}

/// Trusted update input for appending one immutable sealed singleton object.
/// The external policy commitment is unchanged: it binds the allowlisted
/// ObjectKinds, while existence and latest version are mutable checkpoint data.
pub struct PersistentSingletonUpdate {
    exact_roots: Vec<vibeos_durable_format::RootPolicy>,
    allowed_singleton_kinds: Vec<vibeos_durable_format::ObjectKind>,
    canonical_external_root_policy: Vec<u8>,
    object_kind: vibeos_durable_format::ObjectKind,
    bytes: Vec<u8>,
}

impl PersistentSingletonUpdate {
    pub fn new(
        exact_roots: Vec<vibeos_durable_format::RootPolicy>,
        mut allowed_singleton_kinds: Vec<vibeos_durable_format::ObjectKind>,
        canonical_external_root_policy: Vec<u8>,
        object_kind: vibeos_durable_format::ObjectKind,
        bytes: Vec<u8>,
    ) -> Result<Self, AuthoritySnapshotError> {
        allowed_singleton_kinds.sort_unstable();
        if bytes.len() > vibeos_durable_format::MAX_OBJECT_SIZE
            || allowed_singleton_kinds
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || allowed_singleton_kinds.binary_search(&object_kind).is_err()
            || canonical_external_root_policy.is_empty()
        {
            return Err(AuthoritySnapshotError::OutOfBounds);
        }
        Ok(Self {
            exact_roots,
            allowed_singleton_kinds,
            canonical_external_root_policy,
            object_kind,
            bytes,
        })
    }
}

impl fmt::Debug for PersistentAuthorityWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistentAuthorityWriter(<opaque>)")
    }
}

/// One recovered persistent object. No ObjectId, CAS key, digest, or physical
/// pointer is exposed through this type.
#[derive(Clone)]
pub struct PersistentObjectHandle {
    stable_object_id: u128,
    object: Arc<AuthorizedObject<CasObjectHandle>>,
}

impl fmt::Debug for PersistentObjectHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentObjectHandle")
            .field("object_kind", &self.object.object_kind())
            .field("exact_len", &self.object.exact_len())
            .finish_non_exhaustive()
    }
}

impl PersistentObjectHandle {
    pub fn object_kind(&self) -> u32 {
        self.object.object_kind()
    }

    pub fn exact_len(&self) -> u64 {
        self.object.exact_len()
    }
}

/// Cold-verified authority checkpoint. Possession of this view, rather than a
/// caller-supplied ObjectId, is the capability required to obtain handles.
pub struct PersistentAuthorityView {
    store_uuid: [u8; 16],
    snapshot_sha256: [u8; 32],
    snapshot: PersistentAuthoritySnapshot,
    objects: Vec<PersistentObjectHandle>,
    principals: Vec<StoragePrincipal>,
}

/// Result of one validated logical-authority append. Persistent objects are
/// available through [`Self::view`]. Objects committed by this append but not
/// yet named by a durable grant are available only through this value; they
/// are omitted from the VIBEAUT2 binding table and disappear on reboot.
pub struct PersistentAuthorityAppendResult {
    view: PersistentAuthorityView,
    transient: PersistentAuthorityTransientObjects,
}

/// Boot-local authority for objects committed by one logical append but not
/// yet named by a durable grant. Keeping this witness alive keeps those exact
/// CAS objects readable; it cannot be reconstructed after a remount.
pub struct PersistentAuthorityTransientObjects {
    objects: Vec<PersistentObjectHandle>,
}

impl fmt::Debug for PersistentAuthorityAppendResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentAuthorityAppendResult")
            .field("checkpoint_generation", &self.view.checkpoint_generation())
            .field("persistent_object_count", &self.view.objects.len())
            .field("transient_object_count", &self.transient.objects.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PersistentAuthorityTransientObjects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentAuthorityTransientObjects")
            .field("object_count", &self.objects.len())
            .finish_non_exhaustive()
    }
}

impl PersistentAuthorityAppendResult {
    pub const fn view(&self) -> &PersistentAuthorityView {
        &self.view
    }

    pub fn into_view(self) -> PersistentAuthorityView {
        self.view
    }

    /// Split the durable view from the boot-local transient witness. Runtime
    /// authority caches can retain the view while commit tokens retain only
    /// the witness needed to publish objects produced by this append.
    pub fn into_parts(self) -> (PersistentAuthorityView, PersistentAuthorityTransientObjects) {
        (self.view, self.transient)
    }

    /// Resolve either a durable binding in the new view or an unrooted object
    /// committed by this exact append. There is no stable-ID or CAS lookup API;
    /// the caller must present a record from the authenticated logical pass.
    pub fn object_for_recovered(
        &self,
        object: &vibeos_durable_format::RecoveredObject,
    ) -> Option<&PersistentObjectHandle> {
        self.view
            .object_for_recovered(object)
            .or_else(|| self.transient.object_for_recovered(object))
    }
}

impl PersistentAuthorityTransientObjects {
    /// Resolve only a logical record authenticated by the append that created
    /// this witness. Stable IDs and CAS keys remain private.
    pub fn object_for_recovered(
        &self,
        object: &vibeos_durable_format::RecoveredObject,
    ) -> Option<&PersistentObjectHandle> {
        self.objects
            .binary_search_by_key(&object.object_id.get(), |handle| handle.stable_object_id)
            .ok()
            .map(|index| &self.objects[index])
            .filter(|handle| {
                handle.object_kind() == object.object_kind.get()
                    && handle.exact_len() == object.bytes.len() as u64
            })
    }
}

impl fmt::Debug for PersistentAuthorityView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentAuthorityView")
            .field("checkpoint_generation", &self.checkpoint_generation())
            .field("object_count", &self.objects.len())
            .field("principal_count", &self.principals.len())
            .finish_non_exhaustive()
    }
}

impl PersistentAuthorityView {
    pub const fn store_uuid(&self) -> [u8; 16] {
        self.store_uuid
    }

    pub const fn checkpoint_generation(&self) -> u64 {
        self.snapshot.checkpoint_generation()
    }

    pub const fn root_policy_sha256(&self) -> [u8; 32] {
        self.snapshot.root_policy_sha256()
    }

    pub const fn snapshot_sha256(&self) -> [u8; 32] {
        self.snapshot_sha256
    }

    pub fn record_stream(&self) -> &[u8] {
        self.snapshot.record_stream()
    }

    pub fn principal_policies(&self) -> &[PersistentPrincipalPolicy] {
        self.snapshot.principals()
    }

    pub fn objects(&self) -> &[PersistentObjectHandle] {
        &self.objects
    }

    pub fn principals(&self) -> &[StoragePrincipal] {
        &self.principals
    }

    /// Resolve only an object record already present in this authenticated
    /// authority view. There is deliberately no SegmentStore ObjectId lookup.
    pub fn object_for_recovered(
        &self,
        object: &vibeos_durable_format::RecoveredObject,
    ) -> Option<&PersistentObjectHandle> {
        self.objects
            .binary_search_by_key(&object.object_id.get(), |handle| handle.stable_object_id)
            .ok()
            .map(|index| &self.objects[index])
            .filter(|handle| {
                handle.object_kind() == object.object_kind.get()
                    && handle.exact_len() == object.bytes.len() as u64
            })
    }
}

#[derive(Debug)]
pub enum PersistentAuthorityError<E> {
    Unauthorized,
    AlreadyInitialized,
    NotInitialized,
    GenerationMismatch,
    PolicyMismatch,
    InvalidQuotaPolicy,
    Snapshot(AuthoritySnapshotError),
    Store(StoreError<E>),
    Cas(CasStoreError<E>),
    Gc(GcError),
}

impl<E: fmt::Display> fmt::Display for PersistentAuthorityError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("persistent authority writer denied"),
            Self::AlreadyInitialized => {
                formatter.write_str("persistent authority is already initialized")
            }
            Self::NotInitialized => formatter.write_str("persistent authority is not initialized"),
            Self::GenerationMismatch => {
                formatter.write_str("persistent authority generation changed")
            }
            Self::PolicyMismatch => {
                formatter.write_str("persistent authority external policy mismatch")
            }
            Self::InvalidQuotaPolicy => {
                formatter.write_str("persistent principal accounting does not match objects")
            }
            Self::Snapshot(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Cas(error) => write!(formatter, "{error}"),
            Self::Gc(error) => write!(formatter, "{error}"),
        }
    }
}

impl<E> From<StoreError<E>> for PersistentAuthorityError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<CasStoreError<E>> for PersistentAuthorityError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Cas(value)
    }
}

impl<E> From<GcStoreError<E>> for PersistentAuthorityError<E> {
    fn from(value: GcStoreError<E>) -> Self {
        match value {
            GcStoreError::Store(error) => Self::Store(error),
            GcStoreError::Gc(error) => Self::Gc(error),
        }
    }
}

fn gc_can_relieve_persistent_import<E>(error: &PersistentAuthorityError<E>) -> bool {
    matches!(
        error,
        PersistentAuthorityError::Gc(GcError::Capacity)
            | PersistentAuthorityError::Cas(CasStoreError::Store(StoreError::GcResumeRequired))
            | PersistentAuthorityError::Cas(CasStoreError::Store(StoreError::Capacity(
                CapacityClass::Metadata | CapacityClass::CleanerReserve
            )))
            | PersistentAuthorityError::Cas(CasStoreError::Quota(
                crate::quota::QuotaError::OrdinaryCapacityExceeded
            ))
    )
}

impl<D: PageDevice> SegmentStore<D> {
    /// Atomically replace trusted-service roots while preserving the exact M4
    /// authority graph, object bindings, and persistent quota policy. The
    /// caller must already hold the store-bound maintenance root; ordinary
    /// object or path capabilities cannot invoke this checkpoint operation.
    pub(crate) async fn replace_persistent_external_roots(
        &mut self,
        maintenance: &StoreMaintenance,
        external_roots: Vec<PersistentRootEntry>,
    ) -> Result<u64, PersistentAuthorityError<D::Error>> {
        let _lease = self
            .acquire_maintenance(maintenance, MaintenanceOperation::ExplicitMaintenance)
            .ok_or(PersistentAuthorityError::Unauthorized)?;
        let state = self.require_current_generation()?.clone();
        if !state.allocation.retired_segments().is_empty() {
            return Err(PersistentAuthorityError::Store(
                StoreError::GcResumeRequired,
            ));
        }
        let current = state
            .persistent_authority
            .as_ref()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(PersistentAuthorityError::Gc(GcError::InvalidGeneration))?;
        let snapshot = current
            .relocated(generation)
            .and_then(|snapshot| snapshot.with_external_roots(external_roots))
            .map_err(PersistentAuthorityError::Snapshot)?;
        self.preflight_persistent_quota(snapshot.principals(), &snapshot.objects)?;
        let bytes = encode_persistent_authority_snapshot(&snapshot)
            .map_err(PersistentAuthorityError::Snapshot)?;
        self.publish_persistent_snapshot(state, generation, bytes, &snapshot)
            .await?;
        // `publish_persistent_snapshot` has already read back every newly
        // written payload and both checkpoint anchors before installing the
        // exact successor.  A generic mount here would rescan all historical
        // CAS payloads and discard the scrub proof carried into that
        // successor, even though no unverified state intervenes.
        let observed = self
            .require_current_generation()?
            .persistent_authority
            .as_ref()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        if observed.checkpoint_generation() != generation
            || observed.external_roots() != snapshot.external_roots()
        {
            return Err(PersistentAuthorityError::PolicyMismatch);
        }
        Ok(generation)
    }

    pub fn derive_persistent_authority_writer(
        &self,
        maintenance: &StoreMaintenance,
    ) -> Result<PersistentAuthorityWriter, PersistentAuthorityError<D::Error>> {
        let _lease = self
            .acquire_maintenance(maintenance, MaintenanceOperation::ExplicitMaintenance)
            .ok_or(PersistentAuthorityError::Unauthorized)?;
        let maintenance = maintenance
            .attenuate(&[MaintenanceOperation::ExplicitMaintenance])
            .map_err(|_| PersistentAuthorityError::Unauthorized)?;
        Ok(PersistentAuthorityWriter { maintenance })
    }

    pub async fn import_persistent_authority(
        &mut self,
        maintenance: &StoreMaintenance,
        import: PersistentAuthorityImport,
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let lease = self
            .acquire_maintenance(maintenance, MaintenanceOperation::ExplicitMaintenance)
            .ok_or(PersistentAuthorityError::Unauthorized)?;
        if self.require_current_generation()?.authority_root != PhysicalPointer::Null {
            return Err(PersistentAuthorityError::AlreadyInitialized);
        }
        // The incoming stream is not a strict successor of any cached state.
        self.logical_roots.clear();
        self.install_persistent_import(import, BTreeSet::new(), BTreeSet::new(), lease, None)
            .await
            .map(|(view, _)| view)
    }

    pub async fn replace_persistent_authority(
        &mut self,
        writer: &PersistentAuthorityWriter,
        expected_generation: u64,
        update: PersistentAuthorityImport,
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let lease = self
            .acquire_maintenance(
                &writer.maintenance,
                MaintenanceOperation::ExplicitMaintenance,
            )
            .ok_or(PersistentAuthorityError::Unauthorized)?;
        let state = self.require_current_generation()?;
        let current = state
            .persistent_authority
            .as_ref()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        if current.checkpoint_generation() != expected_generation {
            return Err(PersistentAuthorityError::GenerationMismatch);
        }
        // A replacement may redefine logical content behind existing IDs.
        self.logical_roots.clear();
        self.install_persistent_import(update, BTreeSet::new(), BTreeSet::new(), lease, None)
            .await
            .map(|(view, _)| view)
    }

    /// Append a strict successor of the current logical M4 record stream.
    /// Newly committed objects which are not yet admitted by a live grant or
    /// sealed-singleton policy remain boot-local: only this return value can
    /// resolve them. A later grant append reimports the logical bytes and then
    /// installs a durable binding in the recovered authority view.
    pub async fn append_persistent_authority(
        &mut self,
        writer: &PersistentAuthorityWriter,
        expected_generation: u64,
        update: PersistentAuthorityImport,
        principal: &StoragePrincipal,
    ) -> Result<PersistentAuthorityAppendResult, PersistentAuthorityError<D::Error>> {
        let lease = self
            .acquire_maintenance(
                &writer.maintenance,
                MaintenanceOperation::ExplicitMaintenance,
            )
            .ok_or(PersistentAuthorityError::Unauthorized)?;
        let state = self.require_current_generation()?;
        let current = state
            .persistent_authority
            .as_ref()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        if current.checkpoint_generation() != expected_generation {
            return Err(PersistentAuthorityError::GenerationMismatch);
        }
        if current.root_policy_sha256() != update.root_policy_sha256 {
            return Err(PersistentAuthorityError::PolicyMismatch);
        }
        if current.principals().len() != 1
            || principal.stable_id() != Some(current.principals()[0].principal)
        {
            return Err(PersistentAuthorityError::InvalidQuotaPolicy);
        }
        if update.record_stream.len() <= current.record_stream().len()
            || !update.record_stream.starts_with(current.record_stream())
        {
            return Err(PersistentAuthorityError::GenerationMismatch);
        }
        let old_object_ids: BTreeSet<u128> = match &self.committed_ids_cache {
            // The predecessor stream's committed set was captured when that
            // exact generation was installed; no re-decode is needed.
            Some((generation, ids)) if *generation == expected_generation => ids.clone(),
            _ => {
                let old_sectors: Vec<[u8; vibeos_durable_format::RECORD_SIZE]> =
                    current.record_sectors().copied().collect();
                let store_id =
                    decoded_store_id(&old_sectors).ok_or(PersistentAuthorityError::Snapshot(
                        AuthoritySnapshotError::InvalidAuthorityGraph,
                    ))?;
                vibeos_durable_format::preflight_recovery(&old_sectors, store_id)
                    .map_err(|_| {
                        PersistentAuthorityError::Snapshot(
                            AuthoritySnapshotError::InvalidAuthorityGraph,
                        )
                    })?
                    .committed_objects()
                    .iter()
                    .map(|object| object.object_id.get())
                    .collect()
            }
        };
        let new_object_ids: BTreeSet<u128> = update
            .recovered
            .objects
            .iter()
            .filter(|object| !old_object_ids.contains(&object.object_id.get()))
            .map(|object| object.object_id.get())
            .collect();
        let transient_ids: BTreeSet<u128> = new_object_ids
            .iter()
            .copied()
            .filter(|object_id| !update.is_admitted(*object_id))
            .collect();
        let retry_update = update.clone();
        let retry_transient_ids = transient_ids.clone();
        let retry_new_object_ids = new_object_ids.clone();
        let (view, transient_objects) = match self
            .install_persistent_import(
                update,
                transient_ids,
                new_object_ids,
                lease,
                Some(principal),
            )
            .await
        {
            Ok(result) => result,
            Err(error) if gc_can_relieve_persistent_import(&error) => {
                // A logical authority append owns an explicit maintenance
                // lease, so it may spend the cleaner reserve only through one
                // bounded foreground collection. The failed import publishes
                // no authority snapshot; any anonymous CAS objects from a
                // partial attempt are deliberately unrooted and may be
                // reclaimed before the retry.
                let retry_lease = self
                    .acquire_maintenance(
                        &writer.maintenance,
                        MaintenanceOperation::ExplicitMaintenance,
                    )
                    .ok_or(PersistentAuthorityError::Unauthorized)?;
                Box::pin(self.collect_garbage()).await?;

                // GC advances the checkpoint generation while preserving the
                // exact logical authority stream and external policy. Rebind
                // the same successor to that relocated predecessor rather
                // than accepting an arbitrary intervening authority update.
                let current = self
                    .require_current_generation()?
                    .persistent_authority
                    .as_ref()
                    .ok_or(PersistentAuthorityError::NotInitialized)?;
                if current.root_policy_sha256() != retry_update.root_policy_sha256 {
                    return Err(PersistentAuthorityError::PolicyMismatch);
                }
                if retry_update.record_stream.len() <= current.record_stream().len()
                    || !retry_update
                        .record_stream
                        .starts_with(current.record_stream())
                {
                    return Err(PersistentAuthorityError::GenerationMismatch);
                }
                self.install_persistent_import(
                    retry_update,
                    retry_transient_ids,
                    retry_new_object_ids,
                    retry_lease,
                    Some(principal),
                )
                .await?
            }
            Err(error) => return Err(error),
        };
        Ok(PersistentAuthorityAppendResult {
            view,
            transient: PersistentAuthorityTransientObjects {
                objects: transient_objects,
            },
        })
    }

    /// Append one immutable singleton record and atomically replace the
    /// authority snapshot so `latest(kind)` and all CSpace/program roots name
    /// the same checkpoint. Callers must supply an import built with the exact
    /// external policy and the prior canonical stream.
    pub async fn put_persistent_singleton(
        &mut self,
        writer: &PersistentAuthorityWriter,
        expected_generation: u64,
        update: PersistentSingletonUpdate,
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let state = self.require_current_generation()?;
        let current = state
            .persistent_authority
            .as_ref()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        if current.checkpoint_generation() != expected_generation {
            return Err(PersistentAuthorityError::GenerationMismatch);
        }
        if current.root_policy_sha256()
            != crate::authority_snapshot::root_policy_commitment(
                &update.canonical_external_root_policy,
            )
        {
            return Err(PersistentAuthorityError::PolicyMismatch);
        }
        let sectors: Vec<[u8; vibeos_durable_format::RECORD_SIZE]> =
            current.record_sectors().copied().collect();
        let store_id = sectors
            .first()
            .and_then(
                |sector| match vibeos_durable_format::LogRecord::decode(sector).ok()? {
                    vibeos_durable_format::DecodeStatus::Valid(decoded) => {
                        Some(decoded.record.store_id)
                    }
                    _ => None,
                },
            )
            .ok_or(PersistentAuthorityError::Snapshot(
                AuthoritySnapshotError::InvalidAuthorityGraph,
            ))?;
        let recovered = vibeos_durable_format::preflight_recovery(&sectors, store_id)
            .and_then(|preflight| preflight.finish(&update.exact_roots))
            .map_err(|_| {
                PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidAuthorityGraph)
            })?;
        let checkpoint = recovered.chain_checkpoint().map_err(|_| {
            PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidAuthorityGraph)
        })?;
        let mut chain = vibeos_durable_format::RecordChain::from_checkpoint(store_id, checkpoint)
            .map_err(|_| {
            PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidAuthorityGraph)
        })?;
        let transaction_id_raw = recovered.id_high_water.max(1);
        let object_id_raw =
            transaction_id_raw
                .checked_add(1)
                .ok_or(PersistentAuthorityError::Snapshot(
                    AuthoritySnapshotError::ArithmeticOverflow,
                ))?;
        let exclusive_end =
            object_id_raw
                .checked_add(1)
                .ok_or(PersistentAuthorityError::Snapshot(
                    AuthoritySnapshotError::ArithmeticOverflow,
                ))?;
        let mut records = Vec::new();
        records.push(
            chain
                .append(
                    None,
                    vibeos_durable_format::RecordBody::IdHighWater { exclusive_end },
                )
                .map_err(|_| {
                    PersistentAuthorityError::Snapshot(
                        AuthoritySnapshotError::InvalidAuthorityGraph,
                    )
                })?,
        );
        let transaction = vibeos_durable_format::encode_object_transaction(
            &mut chain,
            vibeos_durable_format::TransactionId::new(transaction_id_raw).ok_or(
                PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidField),
            )?,
            vibeos_durable_format::ObjectId::new(object_id_raw).ok_or(
                PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidField),
            )?,
            update.object_kind,
            &update.bytes,
        )
        .map_err(|_| {
            PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidAuthorityGraph)
        })?;
        records.extend(transaction.records);
        let mut sectors = sectors;
        sectors.extend(records);
        let rebuilt = PersistentAuthorityImport::from_m4_with_sealed_singletons(
            &sectors,
            store_id,
            &update.exact_roots,
            &update.allowed_singleton_kinds,
            &update.canonical_external_root_policy,
            Vec::new(),
        )
        .map_err(PersistentAuthorityError::Snapshot)?;
        let system = current
            .principals()
            .first()
            .filter(|_| current.principals().len() == 1)
            .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
        let rebuilt = rebuilt
            .with_system_principal(
                system.principal,
                system.logical_limit_bytes,
                system.physical_limit_bytes,
                system.admission_revoked,
            )
            .map_err(PersistentAuthorityError::Snapshot)?;
        self.replace_persistent_authority(writer, expected_generation, rebuilt)
            .await
    }

    pub async fn recover_persistent_authority(
        &self,
        expected_policy_sha256: [u8; 32],
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let state = self.require_current_generation()?;
        let snapshot = state
            .persistent_authority
            .clone()
            .ok_or(PersistentAuthorityError::NotInitialized)?;
        if snapshot.root_policy_sha256() != expected_policy_sha256 {
            return Err(PersistentAuthorityError::PolicyMismatch);
        }
        self.build_persistent_view(state, snapshot, true).await
    }

    /// Prove that a cold-recovered authority view is the exact object binding
    /// selected by one independently reconstructed external-policy import.
    ///
    /// Stable ObjectIds and CAS identities remain private to this crate. The
    /// caller supplies only the inert import produced by its compiled policy;
    /// this method checks the exact stable set and verifies every referenced
    /// blob before comparing its Merkle identity with the logical record
    /// bytes. Matching kind and length alone is deliberately insufficient.
    pub async fn verify_persistent_authority_import(
        &self,
        view: &PersistentAuthorityView,
        import: &PersistentAuthorityImport,
    ) -> Result<(), PersistentAuthorityError<D::Error>> {
        if view.root_policy_sha256() != import.root_policy_sha256()
            || view.record_stream() != import.record_stream
            || view.principal_policies() != import.principals()
            || view.objects.len() != import.admitted_object_count()
        {
            return Err(PersistentAuthorityError::PolicyMismatch);
        }
        for recovered in import.admitted_objects() {
            let object = view
                .objects
                .binary_search_by_key(&recovered.object_id.get(), |object| object.stable_object_id)
                .ok()
                .map(|index| &view.objects[index])
                .filter(|object| {
                    object.object_kind() == recovered.object_kind.get()
                        && object.exact_len() == recovered.bytes.len() as u64
                })
                .ok_or(PersistentAuthorityError::PolicyMismatch)?;
            if !self
                .persistent_object_matches_recovered(object.object.as_ref(), recovered)
                .await?
            {
                return Err(PersistentAuthorityError::PolicyMismatch);
            }
        }
        Ok(())
    }

    /// Authenticate both the immutable Blob structure and every logical byte
    /// selected by the durable record stream. Descriptor equality alone is not
    /// sufficient at this authority boundary: the hash-collision model still
    /// requires an exact byte comparison before a mapping can confer authority.
    async fn persistent_object_matches_recovered(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        recovered: &vibeos_durable_format::RecoveredObject,
    ) -> Result<bool, PersistentAuthorityError<D::Error>> {
        if object.object_kind() != recovered.object_kind.get()
            || object.exact_len() != recovered.bytes.len() as u64
        {
            return Ok(false);
        }
        let expected = BlobDescriptor::from_content(recovered.object_kind.get(), &recovered.bytes)
            .map_err(|_| PersistentAuthorityError::PolicyMismatch)?;
        let bytes = self.read_verified_blob(object).await?;
        Ok(BlobDescriptor::from_content(object.object_kind(), &bytes)
            .is_ok_and(|observed| observed == expected)
            && bytes == recovered.bytes)
    }

    pub async fn read_persistent_object(
        &self,
        object: &PersistentObjectHandle,
    ) -> Result<Vec<u8>, PersistentAuthorityError<D::Error>> {
        self.read_verified_blob(object.object.as_ref())
            .await
            .map_err(Into::into)
    }

    /// Read an object obtained from this append result. The logical recovered
    /// record is required again, so a caller cannot repurpose the opaque
    /// handle as a general CAS lookup capability.
    pub async fn read_appended_object(
        &self,
        result: &PersistentAuthorityAppendResult,
        recovered: &vibeos_durable_format::RecoveredObject,
    ) -> Result<Vec<u8>, PersistentAuthorityError<D::Error>> {
        let object =
            result
                .object_for_recovered(recovered)
                .ok_or(PersistentAuthorityError::Store(
                    StoreError::ObjectUnavailable,
                ))?;
        self.read_verified_blob(object.object.as_ref())
            .await
            .map_err(Into::into)
    }

    /// Read a boot-local object retained by a transient append witness. The
    /// authenticated logical record is required again so the witness cannot
    /// become an ambient object namespace.
    pub async fn read_transient_object(
        &self,
        witness: &PersistentAuthorityTransientObjects,
        recovered: &vibeos_durable_format::RecoveredObject,
    ) -> Result<Vec<u8>, PersistentAuthorityError<D::Error>> {
        let object =
            witness
                .object_for_recovered(recovered)
                .ok_or(PersistentAuthorityError::Store(
                    StoreError::ObjectUnavailable,
                ))?;
        self.read_persistent_object(object).await
    }

    /// Return the newest sealed singleton selected by external policy for one
    /// known ObjectKind. The scan is bounded by the authenticated view and is
    /// not an ambient CAS namespace lookup.
    pub async fn read_persistent_singleton(
        &self,
        view: &PersistentAuthorityView,
        object_kind: u32,
    ) -> Result<Option<Vec<u8>>, PersistentAuthorityError<D::Error>> {
        let mut preflight = vibeos_durable_format::preflight_recovery(
            &view.snapshot.record_sectors().copied().collect::<Vec<_>>(),
            view.snapshot
                .record_sectors()
                .next()
                .and_then(
                    |sector| match vibeos_durable_format::LogRecord::decode(sector).ok()? {
                        vibeos_durable_format::DecodeStatus::Valid(decoded) => {
                            Some(decoded.record.store_id)
                        }
                        _ => None,
                    },
                )
                .ok_or(PersistentAuthorityError::Snapshot(
                    AuthoritySnapshotError::InvalidAuthorityGraph,
                ))?,
        )
        .map_err(|_| {
            PersistentAuthorityError::Snapshot(AuthoritySnapshotError::InvalidAuthorityGraph)
        })?
        .into_objects();
        let selected = preflight
            .iter_mut()
            .filter(|object| object.object_kind.get() == object_kind)
            .max_by_key(|object| object.commit_sequence);
        let Some(recovered) = selected else {
            return Ok(None);
        };
        let handle = view
            .object_for_recovered(recovered)
            .ok_or(PersistentAuthorityError::PolicyMismatch)?;
        self.read_persistent_object(handle).await.map(Some)
    }

    async fn install_persistent_import(
        &mut self,
        import: PersistentAuthorityImport,
        transient_ids: BTreeSet<u128>,
        charged_ids: BTreeSet<u128>,
        _lease: MaintenanceOperationLease,
        admission_principal: Option<&StoragePrincipal>,
    ) -> Result<
        (PersistentAuthorityView, Vec<PersistentObjectHandle>),
        PersistentAuthorityError<D::Error>,
    > {
        validate_quota_totals(&import, None)?;
        // Captured for the successor's committed-set cache before the import
        // moves into the snapshot.
        let imported_committed_ids: BTreeSet<u128> = import
            .recovered
            .objects
            .iter()
            .map(|object| object.object_id.get())
            .collect();
        // Merkle roots for every logical object, from the cache where the
        // stable ObjectId was already hashed by an earlier installation.
        let mut logical_roots: alloc::collections::BTreeMap<u128, vibeos_blob_format::Hash> =
            alloc::collections::BTreeMap::new();
        for recovered in &import.recovered.objects {
            let root = self.cached_logical_root(recovered)?;
            logical_roots.insert(recovered.object_id.get(), root);
        }
        // A strict logical-stream successor cannot redefine an existing M4
        // ObjectId. Reuse its already authenticated V2 binding instead of
        // consuming a new CAS mapping/segment on every authority append.
        let reusable_bindings = self
            .require_current_generation()?
            .persistent_authority
            .as_ref()
            .filter(|snapshot| import.record_stream.starts_with(snapshot.record_stream()))
            .map_or_else(Vec::new, |snapshot| snapshot.objects.clone());
        let external_roots = self
            .require_current_generation()?
            .persistent_authority
            .as_ref()
            .map_or_else(Vec::new, |snapshot| snapshot.external_roots().to_vec());
        let mut claimed_v2_object_ids = BTreeSet::new();
        for binding in &reusable_bindings {
            claimed_v2_object_ids.insert(binding.v2_object_id);
        }
        if admission_principal.is_none() {
            let mut retained_reusable = Vec::new();
            retained_reusable
                .try_reserve_exact(reusable_bindings.len())
                .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
            retained_reusable.extend(
                reusable_bindings
                    .iter()
                    .copied()
                    .filter(|binding| import.is_admitted(binding.stable_object_id)),
            );
            self.preflight_persistent_quota(import.principals(), &retained_reusable)?;
        }
        // Reserve every fresh charge before the first promotion read or media
        // mutation. New logical objects always need a charge. A later durable
        // grant may reuse an anonymous RAW mapping without allocating another
        // ObjectMapping, but it still needs fresh admission unless that exact
        // stable/V2 pair has a live boot-local candidate charge.
        let mut quota_reservations: Vec<(u128, QuotaReservation)> = Vec::new();
        if let Some(principal) = admission_principal {
            let state = self.require_current_generation()?;
            let table = self
                .quota
                .as_ref()
                .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
            let mut reservation_ids = charged_ids;
            for recovered in import.admitted_objects() {
                let stable_id = recovered.object_id.get();
                if reusable_bindings
                    .binary_search_by_key(&stable_id, |binding| binding.stable_object_id)
                    .is_ok()
                {
                    continue;
                }
                let root = *logical_roots
                    .get(&stable_id)
                    .ok_or(PersistentAuthorityError::PolicyMismatch)?;
                let has_active_exact_candidate = state.cas.as_ref().is_some_and(|cas| {
                    cas.objects.iter().any(|mapping| {
                        !claimed_v2_object_ids.contains(&mapping.object_id)
                            && mapping.reference_codec == crate::cas_codec::REFERENCE_CODEC_RAW
                            && mapping.blob_key.object_kind() == recovered.object_kind.get()
                            && mapping.blob_key.exact_len() == recovered.bytes.len() as u64
                            && mapping.blob_key.merkle_root() == root
                            && table.has_active_persistent_candidate(stable_id, mapping.object_id)
                    })
                });
                if !has_active_exact_candidate {
                    reservation_ids.insert(stable_id);
                }
            }
            quota_reservations
                .try_reserve_exact(reservation_ids.len())
                .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
            for recovered in import
                .recovered
                .objects
                .iter()
                .filter(|object| reservation_ids.contains(&object.object_id.get()))
            {
                let reservation =
                    self.reserve_blob_quota(principal, recovered.bytes.len() as u64)?;
                quota_reservations.push((recovered.object_id.get(), reservation));
            }
            quota_reservations.sort_unstable_by_key(|(stable_id, _)| *stable_id);
        }
        // Reconstruct promotion assignments for every unbound logical object
        // in stable-ID order, including objects which are not currently
        // admitted. This prevents a later same-content stable object from
        // stealing an earlier object's anonymous mapping, while still making
        // a retry after an interrupted import deterministic.
        let mut promoted = Vec::new();
        promoted
            .try_reserve_exact(import.recovered.objects.len())
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        for recovered in &import.recovered.objects {
            if reusable_bindings
                .binary_search_by_key(&recovered.object_id.get(), |binding| {
                    binding.stable_object_id
                })
                .is_ok()
            {
                continue;
            }
            let reservation_index = quota_reservations
                .binary_search_by_key(&recovered.object_id.get(), |(stable_id, _)| *stable_id)
                .ok();
            let mut reservation = reservation_index.map(|index| quota_reservations.remove(index).1);
            let require_active_candidate = admission_principal.is_some()
                && import.is_admitted(recovered.object_id.get())
                && reservation.is_none();
            let root = *logical_roots
                .get(&recovered.object_id.get())
                .ok_or(PersistentAuthorityError::PolicyMismatch)?;
            if let Some(object) = self
                .promote_existing_logical_object(
                    recovered,
                    &claimed_v2_object_ids,
                    require_active_candidate,
                    &mut reservation,
                    root,
                )
                .await?
            {
                claimed_v2_object_ids.insert(object.backend_handle().persistent_binding_parts().0);
                promoted.push((recovered.object_id.get(), object));
            }
            if let Some(reservation) = reservation {
                quota_reservations.push((recovered.object_id.get(), reservation));
                quota_reservations.sort_unstable_by_key(|(stable_id, _)| *stable_id);
            }
        }
        // Fused fast path: exactly one logical object needs a fresh CAS
        // commit — the shape of every ordinary durable append. Stage its blob
        // payload, then publish the object mapping and the authority snapshot
        // under one metadata segment and one checkpoint instead of two
        // independent durable segment transactions and checkpoint pairs.
        let mut fresh = Vec::new();
        for recovered in &import.recovered.objects {
            let stable_id = recovered.object_id.get();
            if !(import.is_admitted(stable_id) || transient_ids.contains(&stable_id)) {
                continue;
            }
            if reusable_bindings
                .binary_search_by_key(&stable_id, |binding| binding.stable_object_id)
                .is_ok()
                || promoted
                    .binary_search_by_key(&stable_id, |(id, _)| *id)
                    .is_ok()
            {
                continue;
            }
            fresh.push(recovered);
        }
        if fresh.len() == 1 {
            let recovered = fresh[0];
            let stable_id = recovered.object_id.get();
            // Reusable bindings get the same validation as the general path.
            for admitted in import.admitted_objects() {
                if let Ok(index) = reusable_bindings.binary_search_by_key(
                    &admitted.object_id.get(),
                    |binding| binding.stable_object_id,
                ) {
                    let root = *logical_roots
                        .get(&admitted.object_id.get())
                        .ok_or(PersistentAuthorityError::PolicyMismatch)?;
                    Self::validate_reusable_binding(
                        self.require_current_generation()?,
                        reusable_bindings[index],
                        admitted,
                        root,
                    )?;
                }
            }
            // Partition already-promoted objects into admitted bindings and
            // transient handles; other promotions only reserved claim order.
            let mut committed = Vec::new();
            let mut transient_promoted = Vec::new();
            for (stable, object) in promoted.drain(..) {
                if import.is_admitted(stable) {
                    committed.push((stable, object));
                } else if transient_ids.contains(&stable) {
                    transient_promoted.push((stable, object));
                }
            }
            let (generation, staged_v2_object_id) = {
                let current = self.require_current_generation()?;
                (
                    current
                        .generation
                        .checked_add(1)
                        .ok_or(PersistentAuthorityError::Gc(GcError::InvalidGeneration))?,
                    current.next_object_id,
                )
            };
            let mut writer = if let Ok(index) =
                quota_reservations.binary_search_by_key(&stable_id, |(id, _)| *id)
            {
                let (_, reservation) = quota_reservations.remove(index);
                self.begin_blob_with_quota_reservation(
                    recovered.object_kind.get(),
                    recovered.bytes.len() as u64,
                    reservation,
                )?
            } else {
                match admission_principal {
                    Some(_) => return Err(PersistentAuthorityError::InvalidQuotaPolicy),
                    None => self.begin_blob_for_persistent_import(
                        recovered.object_kind.get(),
                        recovered.bytes.len() as u64,
                    )?,
                }
            };
            writer.enable_staged_batching();
            for chunk in recovered.bytes.chunks(LEAF_SIZE) {
                writer.write_chunk(chunk).await?;
            }
            let staged = Box::pin(writer.stage_commit()).await?;
            let mut bindings: Vec<PersistentObjectBinding> = reusable_bindings
                .into_iter()
                .filter(|binding| import.is_admitted(binding.stable_object_id))
                .collect();
            bindings
                .try_reserve_exact(committed.len() + 1)
                .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
            for (stable, object) in &committed {
                let (v2_object_id, commit_generation, object_kind) =
                    object.backend_handle().persistent_binding_parts();
                bindings.push(PersistentObjectBinding {
                    stable_object_id: *stable,
                    v2_object_id,
                    commit_generation,
                    object_kind,
                });
            }
            if import.is_admitted(stable_id) {
                bindings.push(PersistentObjectBinding {
                    stable_object_id: stable_id,
                    v2_object_id: staged_v2_object_id,
                    commit_generation: generation,
                    object_kind: staged.object_kind,
                });
            }
            bindings.sort_unstable_by_key(|binding| binding.stable_object_id);
            let snapshot = PersistentAuthoritySnapshot::from_validated_import_parts(
                generation,
                import.root_policy_sha256,
                import.record_stream,
                bindings,
                import.principals,
                external_roots,
            )
            .map_err(PersistentAuthorityError::Snapshot)?;
            let authority_bytes = encode_persistent_authority_snapshot(&snapshot)
                .map_err(PersistentAuthorityError::Snapshot)?;
            let mut root_entries: Vec<PersistentRootEntry> = snapshot
                .objects
                .iter()
                .map(|binding| PersistentRootEntry {
                    object_id: binding.v2_object_id,
                    commit_generation: binding.commit_generation,
                    object_kind: binding.object_kind,
                })
                .collect();
            root_entries.extend_from_slice(snapshot.external_roots());
            root_entries.sort_unstable_by_key(|entry| entry.object_id);
            let persistent_roots = PersistentRootSet::new(generation, root_entries)
                .map_err(|_| PersistentAuthorityError::Store(StoreError::Corrupt))?;
            // Same ordering contract as publish_persistent_snapshot: the pure
            // quota installation precedes the first media mutation of the
            // fused publication.
            self.install_persistent_quota_snapshot(&snapshot)?;
            let object = self
                .publish_staged_object_with_authority(
                    staged,
                    crate::cas::FusedAuthorityPublication {
                        authority_bytes,
                        persistent_authority: snapshot.clone(),
                        persistent_roots,
                    },
                )
                .await?;
            object
                .backend_handle()
                .bind_persistent_quota_candidate(stable_id)
                .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?;
            let mut transient_objects = Vec::new();
            transient_objects
                .try_reserve_exact(transient_promoted.len() + 1)
                .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
            for (stable, object) in transient_promoted {
                transient_objects.push(PersistentObjectHandle {
                    stable_object_id: stable,
                    object: Arc::new(object),
                });
            }
            if transient_ids.contains(&stable_id) {
                transient_objects.push(PersistentObjectHandle {
                    stable_object_id: stable_id,
                    object: Arc::new(object),
                });
            }
            self.committed_ids_cache = Some((generation, imported_committed_ids));
            // Admitted fused objects are durably named by the checkpoint's
            // authority snapshot and root set; their runtime handles may drop.
            drop(committed);
            let view = self
                .build_persistent_view(self.require_current_generation()?, snapshot, false)
                .await?;
            return Ok((view, transient_objects));
        }
        let mut committed = Vec::new();
        committed
            .try_reserve_exact(import.admitted_object_count())
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        for recovered in import.admitted_objects() {
            if let Some(binding) = reusable_bindings
                .binary_search_by_key(&recovered.object_id.get(), |binding| {
                    binding.stable_object_id
                })
                .ok()
                .map(|index| reusable_bindings[index])
            {
                let root = *logical_roots
                    .get(&recovered.object_id.get())
                    .ok_or(PersistentAuthorityError::PolicyMismatch)?;
                Self::validate_reusable_binding(
                    self.require_current_generation()?,
                    binding,
                    recovered,
                    root,
                )?;
                continue;
            }
            if let Ok(index) = promoted
                .binary_search_by_key(&recovered.object_id.get(), |(stable_id, _)| *stable_id)
            {
                let (_, object) = promoted.remove(index);
                committed.push((recovered.object_id.get(), object));
                continue;
            }
            let mut writer = if let Ok(index) = quota_reservations
                .binary_search_by_key(&recovered.object_id.get(), |(stable_id, _)| *stable_id)
            {
                let (_, reservation) = quota_reservations.remove(index);
                self.begin_blob_with_quota_reservation(
                    recovered.object_kind.get(),
                    recovered.bytes.len() as u64,
                    reservation,
                )?
            } else {
                match admission_principal {
                    Some(_) => return Err(PersistentAuthorityError::InvalidQuotaPolicy),
                    None => self.begin_blob_for_persistent_import(
                        recovered.object_kind.get(),
                        recovered.bytes.len() as u64,
                    )?,
                }
            };
            for chunk in recovered.bytes.chunks(LEAF_SIZE) {
                writer.write_chunk(chunk).await?;
            }
            // `BlobWriter::commit` is already split into sub-16 KiB raw
            // phases. Pin that bounded future on the heap so the import
            // coroutine does not retain its own authority state beside it.
            let object = Box::pin(writer.commit()).await?;
            object
                .backend_handle()
                .bind_persistent_quota_candidate(recovered.object_id.get())
                .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?;
            claimed_v2_object_ids.insert(object.backend_handle().persistent_binding_parts().0);
            committed.push((recovered.object_id.get(), object));
        }
        let mut transient_objects = Vec::new();
        transient_objects
            .try_reserve_exact(transient_ids.len())
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        for recovered in import
            .recovered
            .objects
            .iter()
            .filter(|object| transient_ids.contains(&object.object_id.get()))
        {
            let object = if let Ok(index) = promoted
                .binary_search_by_key(&recovered.object_id.get(), |(stable_id, _)| *stable_id)
            {
                promoted.remove(index).1
            } else {
                let mut writer = if let Ok(index) = quota_reservations
                    .binary_search_by_key(&recovered.object_id.get(), |(stable_id, _)| *stable_id)
                {
                    let (_, reservation) = quota_reservations.remove(index);
                    self.begin_blob_with_quota_reservation(
                        recovered.object_kind.get(),
                        recovered.bytes.len() as u64,
                        reservation,
                    )?
                } else {
                    match admission_principal {
                        Some(_) => return Err(PersistentAuthorityError::InvalidQuotaPolicy),
                        None => self.begin_blob_for_persistent_import(
                            recovered.object_kind.get(),
                            recovered.bytes.len() as u64,
                        )?,
                    }
                };
                for chunk in recovered.bytes.chunks(LEAF_SIZE) {
                    writer.write_chunk(chunk).await?;
                }
                let object = Box::pin(writer.commit()).await?;
                object
                    .backend_handle()
                    .bind_persistent_quota_candidate(recovered.object_id.get())
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?;
                object
            };
            claimed_v2_object_ids.insert(object.backend_handle().persistent_binding_parts().0);
            transient_objects.push(PersistentObjectHandle {
                stable_object_id: recovered.object_id.get(),
                object: Arc::new(object),
            });
        }
        let state = self.require_current_generation()?.clone();
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(PersistentAuthorityError::Gc(GcError::InvalidGeneration))?;
        let mut bindings: Vec<PersistentObjectBinding> = reusable_bindings
            .into_iter()
            .filter(|binding| import.is_admitted(binding.stable_object_id))
            .collect();
        bindings
            .try_reserve_exact(committed.len())
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        for (stable_object_id, object) in &committed {
            let (v2_object_id, commit_generation, object_kind) =
                object.backend_handle().persistent_binding_parts();
            bindings.push(PersistentObjectBinding {
                stable_object_id: *stable_object_id,
                v2_object_id,
                commit_generation,
                object_kind,
            });
        }
        bindings.sort_unstable_by_key(|binding| binding.stable_object_id);
        let snapshot = PersistentAuthoritySnapshot::from_validated_import_parts(
            generation,
            import.root_policy_sha256,
            import.record_stream,
            bindings,
            import.principals,
            external_roots,
        )
        .map_err(PersistentAuthorityError::Snapshot)?;
        let authority_bytes = encode_persistent_authority_snapshot(&snapshot)
            .map_err(PersistentAuthorityError::Snapshot)?;
        // Keep fresh object-resource roots until the new checkpoint seal has
        // durably named every binding. No crash before that point can expose a
        // partially imported authority graph.
        self.publish_persistent_snapshot(state, generation, authority_bytes, &snapshot)
            .await?;
        self.committed_ids_cache = Some((generation, imported_committed_ids));
        drop(committed);
        let view = self
            .build_persistent_view(self.require_current_generation()?, snapshot, false)
            .await?;
        Ok((view, transient_objects))
    }

    async fn publish_persistent_snapshot(
        &mut self,
        state: MountedState,
        generation: u64,
        authority_bytes: Vec<u8>,
        snapshot: &PersistentAuthoritySnapshot,
    ) -> Result<(), PersistentAuthorityError<D::Error>> {
        let counts = state
            .allocation
            .counts()
            .map_err(GcError::from)
            .map_err(PersistentAuthorityError::Gc)?;
        if counts.free <= u64::from(state.cleaner_reserve_segments) {
            return Err(PersistentAuthorityError::Gc(GcError::Capacity));
        }
        let free =
            select_free_segments(&state.allocation, 1).map_err(PersistentAuthorityError::Gc)?;
        let next_segment_generation = state
            .next_segment_generation
            .checked_add(1)
            .ok_or(PersistentAuthorityError::Gc(GcError::InvalidGeneration))?;
        let allocation = state
            .allocation
            .apply_transition(AllocationTransition {
                checkpoint_generation: generation,
                next_segment_generation,
                allocate: &free,
                retire: &[],
                reclaim: &[],
            })
            .map_err(GcError::from)
            .map_err(PersistentAuthorityError::Gc)?;
        let allocation_bytes = encode_allocation_v2(&allocation)
            .map_err(GcError::from)
            .map_err(PersistentAuthorityError::Gc)?;
        let empty_cas_snapshot = if state.catalog_root == PhysicalPointer::Null {
            let context = crate::cas_codec::CasCodecContext::new(
                state.superblock.binding.store_uuid,
                state.admitted_segments,
                next_segment_generation,
            )
            .map_err(|_| PersistentAuthorityError::Store(StoreError::Corrupt))?;
            Some(
                crate::cas_codec::encode_cas_snapshot(
                    &crate::cas_codec::CasSnapshot {
                        checkpoint_generation: generation,
                        objects: Vec::new(),
                        blobs: Vec::new(),
                    },
                    context,
                )
                .map_err(|_| PersistentAuthorityError::Store(StoreError::Corrupt))?,
            )
        } else {
            None
        };
        // Repeat the pure admission plan with the final stable/V2 assignments,
        // then install it atomically before the authority checkpoint can begin
        // mutation. Every fallible allocation, capacity calculation, and codec
        // operation above leaves the old accounting untouched. Any I/O failure
        // below poisons the store and a subsequent mount reconstructs quota from
        // whichever complete checkpoint is actually durable.
        self.install_persistent_quota_snapshot(snapshot)?;
        self.mounted = None;
        self.poisoned = true;
        let mut builder = SegmentBuilder::begin(&self.device, &state, generation, free).await?;
        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(3)
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        if let Some(bytes) = empty_cas_snapshot.as_ref() {
            payloads.push(SegmentPayload {
                extent_kind: ExtentKind::Catalog,
                object_kind: 0xffff_0011,
                extent_index: 0,
                extent_count: 1,
                content_byte_len: bytes.len() as u64,
                encoded_blob_len: bytes.len() as u64,
                encoded_offset: 0,
                merkle_root: payload_sha256(bytes),
                bytes,
            });
        }
        let authority_index = payloads.len();
        payloads.push(SegmentPayload {
            extent_kind: ExtentKind::Authority,
            object_kind: METADATA_KIND_PERSISTENT_AUTHORITY,
            extent_index: 0,
            extent_count: 1,
            content_byte_len: authority_bytes.len() as u64,
            encoded_blob_len: authority_bytes.len() as u64,
            encoded_offset: 0,
            merkle_root: payload_sha256(&authority_bytes),
            bytes: &authority_bytes,
        });
        let allocation_index = payloads.len();
        payloads.push(SegmentPayload {
            extent_kind: ExtentKind::Allocation,
            object_kind: METADATA_KIND_ALLOCATION,
            extent_index: 0,
            extent_count: 1,
            content_byte_len: allocation_bytes.len() as u64,
            encoded_blob_len: allocation_bytes.len() as u64,
            encoded_offset: 0,
            merkle_root: payload_sha256(&allocation_bytes),
            bytes: &allocation_bytes,
        });
        let pointers = builder.payload_batch(&self.device, &payloads).await?;
        let catalog_root = if empty_cas_snapshot.is_some() {
            pointers
                .first()
                .copied()
                .ok_or(PersistentAuthorityError::Store(StoreError::Corrupt))?
        } else {
            state.catalog_root
        };
        let authority_root = pointers
            .get(authority_index)
            .copied()
            .ok_or(PersistentAuthorityError::Store(StoreError::Corrupt))?;
        let allocation_root = pointers
            .get(allocation_index)
            .copied()
            .ok_or(PersistentAuthorityError::Store(StoreError::Corrupt))?;
        let last_segment = builder.finish_before_checkpoint(&self.device).await?;
        let checkpoint = publish_checkpoint(
            &self.device,
            &state,
            self.limits,
            generation,
            next_segment_generation,
            catalog_root,
            authority_root,
            allocation_root,
        )
        .await?;
        // All transaction payloads are verified after the checkpoint write is
        // durable, so a misdirected anchor write cannot evade the final
        // read-back. Unchanged CAS/catalog state remains covered by the
        // predecessor witness and the exact checkpoint transition.
        let mut staged = Vec::new();
        staged
            .try_reserve_exact(3)
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        if let (Some(bytes), PhysicalPointer::Value(_)) =
            (empty_cas_snapshot.as_ref(), catalog_root)
        {
            staged.push((catalog_root, ExtentKind::Catalog, bytes.as_slice()));
        }
        staged.push((
            authority_root,
            ExtentKind::Authority,
            authority_bytes.as_slice(),
        ));
        staged.push((
            allocation_root,
            ExtentKind::Allocation,
            allocation_bytes.as_slice(),
        ));
        verify_staged_payloads(
            &self.device,
            &state,
            generation,
            next_segment_generation,
            &staged,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        let mut root_entries: Vec<PersistentRootEntry> = snapshot
            .objects
            .iter()
            .map(|binding| PersistentRootEntry {
                object_id: binding.v2_object_id,
                commit_generation: binding.commit_generation,
                object_kind: binding.object_kind,
            })
            .collect();
        root_entries.extend_from_slice(snapshot.external_roots());
        root_entries.sort_unstable_by_key(|entry| entry.object_id);
        let persistent_roots = PersistentRootSet::new(generation, root_entries)
            .map_err(|_| PersistentAuthorityError::Store(StoreError::Corrupt))?;
        let next_physical_segment = (0..state.admitted_segments)
            .find(|segment_no| {
                allocation.segment_state(*segment_no) == Some(SegmentAllocation::Free)
            })
            .unwrap_or(state.admitted_segments);
        let mut successor = MountedState {
            superblock: state.superblock,
            generation,
            admitted_segments: state.admitted_segments,
            next_physical_segment,
            next_segment_generation,
            next_object_id: state.next_object_id.max(u128::from(generation)),
            cleaner_reserve_segments: state.cleaner_reserve_segments,
            replay_count: 0,
            catalog_root,
            replay_tail: PhysicalPointer::Null,
            authority_root,
            allocation_root,
            allocation,
            allocation_version: 2,
            persistent_roots: Some(persistent_roots),
            persistent_authority: Some(snapshot.clone()),
            catalog: state.catalog.clone(),
            cas: if empty_cas_snapshot.is_some() {
                Some(CasMountedState {
                    objects: Vec::new(),
                    blobs: Vec::new(),
                })
            } else {
                state.cas.clone()
            },
            recovery_peak_bytes: 0,
            last_segment: Some(last_segment),
            last_segment_previous: Some(state.last_segment.unwrap_or((
                ANCHOR_SEGMENT_NO,
                0,
                [0; 32],
            ))),
            last_segment_target_checkpoint_generation: generation,
        };
        successor.recovery_peak_bytes = successor
            .resident_heap_bytes()
            .ok_or(PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        if successor.recovery_peak_bytes > self.limits.recovery_memory_bytes {
            return Err(PersistentAuthorityError::Store(StoreError::MemoryLimit));
        }
        self.mount_verified_successor(state, checkpoint, successor, true)
            .await?;
        Ok(())
    }

    fn preflight_persistent_quota(
        &self,
        policies: &[PersistentPrincipalPolicy],
        bindings: &[PersistentObjectBinding],
    ) -> Result<(), PersistentAuthorityError<D::Error>> {
        match &self.quota {
            Some(table) => {
                let pairs = persistent_quota_binding_pairs(bindings)?;
                table
                    .preflight_persistent_with_bindings(policies, &pairs)
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)
            }
            None if policies.is_empty() => Ok(()),
            None => Err(PersistentAuthorityError::InvalidQuotaPolicy),
        }
    }

    fn install_persistent_quota_snapshot(
        &self,
        snapshot: &PersistentAuthoritySnapshot,
    ) -> Result<(), PersistentAuthorityError<D::Error>> {
        match &self.quota {
            Some(table) => {
                let pairs = persistent_quota_binding_pairs(&snapshot.objects)?;
                // Keep the immediately preceding call pure so an allocation or
                // late accounting mismatch cannot partially install a plan.
                table
                    .preflight_persistent_with_bindings(snapshot.principals(), &pairs)
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?;
                table
                    .restore_persistent_with_bindings(snapshot.principals(), &pairs)
                    .map(drop)
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)
            }
            None if snapshot.principals().is_empty() => Ok(()),
            None => Err(PersistentAuthorityError::InvalidQuotaPolicy),
        }
    }

    /// Return the Merkle root of one logical object, computing and caching it
    /// on first sight. A valid record stream never redefines an ObjectId's
    /// content, and non-successor installations clear the cache, so the hit
    /// path is sound without re-hashing the object bytes.
    fn cached_logical_root(
        &mut self,
        recovered: &vibeos_durable_format::RecoveredObject,
    ) -> Result<vibeos_blob_format::Hash, PersistentAuthorityError<D::Error>> {
        let stable_id = recovered.object_id.get();
        let kind = recovered.object_kind.get();
        let len = recovered.bytes.len() as u64;
        if let Some((cached_kind, cached_len, root)) = self.logical_roots.get(&stable_id) {
            if *cached_kind == kind && *cached_len == len {
                return Ok(*root);
            }
        }
        let descriptor = BlobDescriptor::from_content(kind, &recovered.bytes)
            .map_err(|_| PersistentAuthorityError::PolicyMismatch)?;
        self.logical_roots
            .insert(stable_id, (kind, len, descriptor.root));
        Ok(descriptor.root)
    }

    fn validate_reusable_binding(
        state: &MountedState,
        binding: PersistentObjectBinding,
        recovered: &vibeos_durable_format::RecoveredObject,
        root: vibeos_blob_format::Hash,
    ) -> Result<(), PersistentAuthorityError<D::Error>> {
        let descriptor_root = root;
        state
            .cas
            .as_ref()
            .and_then(|cas| {
                cas.objects
                    .binary_search_by_key(&binding.v2_object_id, |mapping| mapping.object_id)
                    .ok()
                    .map(|index| cas.objects[index])
            })
            .filter(|mapping| {
                mapping.commit_generation == binding.commit_generation
                    && mapping.reference_codec == crate::cas_codec::REFERENCE_CODEC_RAW
                    && mapping.blob_key.object_kind() == binding.object_kind
                    && binding.object_kind == recovered.object_kind.get()
                    && mapping.blob_key.exact_len() == recovered.bytes.len() as u64
                    && mapping.blob_key.merkle_root() == descriptor_root
            })
            .ok_or(PersistentAuthorityError::PolicyMismatch)?;
        Ok(())
    }

    async fn promote_existing_logical_object(
        &mut self,
        recovered: &vibeos_durable_format::RecoveredObject,
        claimed_v2_object_ids: &BTreeSet<u128>,
        require_active_quota_candidate: bool,
        quota_reservation: &mut Option<QuotaReservation>,
        root: vibeos_blob_format::Hash,
    ) -> Result<Option<AuthorizedObject<CasObjectHandle>>, PersistentAuthorityError<D::Error>> {
        let state = self.require_current_generation()?;
        let Some(cas) = state.cas.as_ref() else {
            return Ok(None);
        };
        let cas_payloads_verified = self.cas_payloads_verified(state.generation);
        for mapping in cas.objects.iter().copied().filter(|mapping| {
            !claimed_v2_object_ids.contains(&mapping.object_id)
                && (!require_active_quota_candidate
                    || self.quota.as_ref().is_some_and(|table| {
                        table.has_active_persistent_candidate(
                            recovered.object_id.get(),
                            mapping.object_id,
                        )
                    }))
                && mapping.reference_codec == crate::cas_codec::REFERENCE_CODEC_RAW
                && mapping.blob_key.object_kind() == recovered.object_kind.get()
                && mapping.blob_key.exact_len() == recovered.bytes.len() as u64
                && mapping.blob_key.merkle_root() == root
        }) {
            let mut object = recover_promotable_cas_object(
                state.superblock.binding.store_uuid,
                mapping,
                &self.pins,
            )
            .map_err(|_| PersistentAuthorityError::Store(StoreError::ObjectUnavailable))?;
            let previously_verified = self.promotion_verified.contains(&mapping.blob_key);
            if !cas_payloads_verified
                && !previously_verified
                && !self
                    .persistent_object_matches_recovered(&object, recovered)
                    .await?
            {
                continue;
            }
            if !previously_verified {
                self.promotion_verified.insert(mapping.blob_key);
            }
            if let Some(reservation) = quota_reservation.take() {
                if !object.backend_handle_mut().can_attach_quota_charge() {
                    return Err(PersistentAuthorityError::InvalidQuotaPolicy);
                }
                let table = self
                    .quota
                    .as_ref()
                    .cloned()
                    .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
                let charge = reservation
                    .commit_with_unique_physical(0)
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?;
                object
                    .backend_handle_mut()
                    .attach_quota_charge(table, charge);
                if object
                    .backend_handle()
                    .bind_persistent_quota_candidate(recovered.object_id.get())
                    .is_err()
                {
                    drop(object);
                    return Err(PersistentAuthorityError::InvalidQuotaPolicy);
                }
            }
            return Ok(Some(object));
        }
        Ok(None)
    }

    async fn build_persistent_view(
        &self,
        state: &MountedState,
        snapshot: PersistentAuthoritySnapshot,
        verify_media: bool,
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let cas_objects = match state.cas.as_ref() {
            Some(cas) => cas.objects.as_slice(),
            None if snapshot.objects.is_empty() => &[],
            None => {
                return Err(PersistentAuthorityError::Store(
                    StoreError::ObjectUnavailable,
                ));
            }
        };
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(snapshot.objects.len())
            .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
        for binding in &snapshot.objects {
            let mapping = cas_objects
                .binary_search_by_key(&binding.v2_object_id, |mapping| mapping.object_id)
                .ok()
                .map(|index| cas_objects[index])
                .filter(|mapping| {
                    mapping.commit_generation == binding.commit_generation
                        && mapping.reference_codec == crate::cas_codec::REFERENCE_CODEC_RAW
                        && mapping.blob_key.object_kind() == binding.object_kind
                })
                .ok_or(PersistentAuthorityError::Store(StoreError::Corrupt))?;
            let object = Arc::new(recover_persistent_cas_object(
                state.superblock.binding.store_uuid,
                mapping,
            ));
            if verify_media {
                self.verify_blob(object.as_ref()).await?;
            }
            objects.push(PersistentObjectHandle {
                stable_object_id: binding.stable_object_id,
                object,
            });
        }
        validate_quota_totals_from_handles(snapshot.principals(), &objects)?;
        let principals = match &self.quota {
            Some(table) => {
                // Consume exact boot-local charges for stable objects now
                // owned by this durable snapshot before installing its totals.
                // This also closes the seal-success/fault-before-return window:
                // every subsequent cold recovery repeats the same transfer.
                let bindings: Vec<(u128, u128)> = snapshot
                    .objects
                    .iter()
                    .map(|binding| (binding.stable_object_id, binding.v2_object_id))
                    .collect();
                table
                    .restore_persistent_with_bindings(snapshot.principals(), &bindings)
                    .map_err(|_| PersistentAuthorityError::InvalidQuotaPolicy)?
            }
            None if snapshot.principals().is_empty() => Vec::new(),
            None => return Err(PersistentAuthorityError::InvalidQuotaPolicy),
        };
        let encoded = encode_persistent_authority_snapshot(&snapshot)
            .map_err(PersistentAuthorityError::Snapshot)?;
        Ok(PersistentAuthorityView {
            store_uuid: state.superblock.binding.store_uuid.into_bytes(),
            snapshot_sha256: Sha256::digest(&encoded).into(),
            snapshot,
            objects,
            principals,
        })
    }

    #[cfg(test)]
    pub(crate) async fn test_build_persistent_view_with_reference_codec(
        &self,
        view: &PersistentAuthorityView,
        reference_codec: u16,
    ) -> Result<PersistentAuthorityView, PersistentAuthorityError<D::Error>> {
        let mut state = self.require_current_generation()?.clone();
        let cas = state.cas.as_mut().ok_or(PersistentAuthorityError::Store(
            StoreError::ObjectUnavailable,
        ))?;
        for binding in &view.snapshot.objects {
            let mapping = cas
                .objects
                .binary_search_by_key(&binding.v2_object_id, |mapping| mapping.object_id)
                .ok()
                .map(|index| &mut cas.objects[index])
                .ok_or(PersistentAuthorityError::Store(
                    StoreError::ObjectUnavailable,
                ))?;
            mapping.reference_codec = reference_codec;
        }
        self.build_persistent_view(&state, view.snapshot.clone(), true)
            .await
    }
}

fn validate_quota_totals<E>(
    import: &PersistentAuthorityImport,
    _unused: Option<E>,
) -> Result<(), PersistentAuthorityError<E>> {
    let logical = import
        .admitted_objects()
        .try_fold(0_u64, |total, object| {
            total.checked_add(object.bytes.len() as u64)
        })
        .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
    let physical = import
        .admitted_objects()
        .try_fold(0_u64, |total, object| {
            canonical_attributable_physical_bytes(object.bytes.len() as u64)
                .ok()
                .and_then(|bytes| total.checked_add(bytes))
        })
        .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
    validate_policy_sums(import.principals(), logical, physical)
}

fn validate_quota_totals_from_handles<E>(
    policies: &[PersistentPrincipalPolicy],
    objects: &[PersistentObjectHandle],
) -> Result<(), PersistentAuthorityError<E>> {
    let logical = objects
        .iter()
        .try_fold(0_u64, |total, object| total.checked_add(object.exact_len()))
        .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
    let physical = objects
        .iter()
        .try_fold(0_u64, |total, object| {
            canonical_attributable_physical_bytes(object.exact_len())
                .ok()
                .and_then(|bytes| total.checked_add(bytes))
        })
        .ok_or(PersistentAuthorityError::InvalidQuotaPolicy)?;
    validate_policy_sums(policies, logical, physical)
}

fn validate_policy_sums<E>(
    policies: &[PersistentPrincipalPolicy],
    logical: u64,
    physical: u64,
) -> Result<(), PersistentAuthorityError<E>> {
    let admitted_logical = policies.iter().try_fold(0_u64, |total, policy| {
        total.checked_add(policy.committed_logical_bytes)
    });
    let admitted_physical = policies.iter().try_fold(0_u64, |total, policy| {
        total.checked_add(policy.committed_physical_bytes)
    });
    if admitted_logical != Some(logical) || admitted_physical != Some(physical) {
        return Err(PersistentAuthorityError::InvalidQuotaPolicy);
    }
    Ok(())
}

fn decoded_store_id(
    sectors: &[[u8; vibeos_durable_format::RECORD_SIZE]],
) -> Option<vibeos_durable_format::StoreId> {
    sectors.first().and_then(|sector| {
        match vibeos_durable_format::LogRecord::decode(sector).ok()? {
            vibeos_durable_format::DecodeStatus::Valid(decoded) => Some(decoded.record.store_id),
            _ => None,
        }
    })
}

fn persistent_quota_binding_pairs<E>(
    bindings: &[PersistentObjectBinding],
) -> Result<Vec<(u128, u128)>, PersistentAuthorityError<E>> {
    let mut pairs = Vec::new();
    pairs
        .try_reserve_exact(bindings.len())
        .map_err(|_| PersistentAuthorityError::Store(StoreError::MemoryLimit))?;
    pairs.extend(
        bindings
            .iter()
            .map(|binding| (binding.stable_object_id, binding.v2_object_id)),
    );
    Ok(pairs)
}
