//! Exact durable root and recovery gate for one canonical Component artifact.
//!
//! The durable capability is deliberately read-only. Recovery joins the one
//! fixed root grant to its object by the grant's exact `ObjectId`; object kind,
//! hashes, aliases, and WIT names are never lookup authority. The resulting
//! typed witness remains private to the loader so later validation and
//! admission can derive only fresh volatile command authority.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceV1, ComponentArtifactSignerPolicyKind,
    ComponentArtifactV1, COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN,
    COMPONENT_ARTIFACT_HEADER_LEN, COMPONENT_ARTIFACT_OBJECT_KIND_RAW,
    COMPONENT_ARTIFACT_OPERATOR_EVIDENCE_OBJECT_KIND_RAW, MAX_COMPONENT_ARTIFACT_ENCODED_BYTES,
};
use vibeos_core::cap::{
    CSpace, PersistentDerivationWitness, PersistentInstallError, PersistentResourceWitness, Rights,
};
use vibeos_durable_format::{
    DerivationId, DurableRights, ObjectId, ObjectKind, RecoveredGrant, RecoveredObject,
    RecoveredSlot, RecoveredStore, ResourceKind, RootConstraint, RootPolicy, RootRightsConstraint,
    SpaceId, TransactionId,
};
use vibeos_object_store::{BoundAuthorityRecovery, StoredObject};

/// Fixed persistent namespace owned exclusively by Component artifact roots.
///
/// This value is policy metadata, not authority and not an object lookup key.
pub const COMPONENT_ARTIFACT_SPACE_ID_RAW: u128 = 0x5649_4245_4f53_2d43_4f4d_504f_4e45_4e54;

pub(crate) const COMPONENT_ARTIFACT_ROOT_SLOT: u32 = 0;
pub(crate) const COMPONENT_ARTIFACT_ROOT_GENERATION: u64 = 0;
const STORED_OBJECT_RESOURCE_KIND_RAW: u32 = 0x5354_4f52;
pub(crate) const COMPONENT_ARTIFACT_ROOT_RIGHTS: DurableRights = DurableRights::READ;

pub(crate) const fn component_artifact_space_id() -> SpaceId {
    match SpaceId::new(COMPONENT_ARTIFACT_SPACE_ID_RAW) {
        Some(space) => space,
        None => unreachable!(),
    }
}

pub(crate) const fn component_artifact_object_kind() -> ObjectKind {
    match ObjectKind::new(COMPONENT_ARTIFACT_OBJECT_KIND_RAW) {
        Some(kind) => kind,
        None => unreachable!(),
    }
}

pub(crate) const fn operator_evidence_object_kind() -> ObjectKind {
    match ObjectKind::new(COMPONENT_ARTIFACT_OPERATOR_EVIDENCE_OBJECT_KIND_RAW) {
        Some(kind) => kind,
        None => unreachable!(),
    }
}

pub(crate) const fn stored_object_resource_kind() -> ResourceKind {
    match ResourceKind::new(STORED_OBJECT_RESOURCE_KIND_RAW) {
        Some(kind) => kind,
        None => unreachable!(),
    }
}

/// The sole durable root shape which may confer read access to a Component
/// artifact object.
pub const fn root_constraint() -> RootConstraint {
    RootConstraint {
        space: component_artifact_space_id(),
        first_slot: COMPONENT_ARTIFACT_ROOT_SLOT,
        last_slot_inclusive: COMPONENT_ARTIFACT_ROOT_SLOT,
        rights: RootRightsConstraint::exact(COMPONENT_ARTIFACT_ROOT_RIGHTS),
        resource_kind: stored_object_resource_kind(),
        object_kind: component_artifact_object_kind(),
    }
}

/// Recheck the exact root grant after dynamic root selection.
///
/// `RootPolicy` does not retain an object kind. The recovery join below checks
/// that independently against the exact object named by `grant.object_id`.
pub fn root_policy_is_exact(root: &RootPolicy) -> bool {
    let grant = &root.grant;
    grant.parent_id.is_none()
        && grant.flags.is_root()
        && grant.target.space == component_artifact_space_id()
        && grant.target.slot == COMPONENT_ARTIFACT_ROOT_SLOT
        && grant.target.generation == COMPONENT_ARTIFACT_ROOT_GENERATION
        && grant.rights == COMPONENT_ARTIFACT_ROOT_RIGHTS
        && grant.resource_kind == stored_object_resource_kind()
}

/// Fail-closed classification for durable Component root recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentRootError {
    /// Slot history, grant shape, or exact object join was not the fixed graph.
    UnexpectedGraph,
    /// The root's exact object carried a different outer durable kind.
    ObjectKind,
    /// The declared artifact length is inconsistent or outside the C7 bound.
    ObjectSize,
    /// Prepare/commit ordering cannot prove object-before-root publication.
    CommitOrder,
    /// The root-relative durable ID layout is not the sealed C7.4 bundle.
    BundleIdentity,
    /// Operator evidence is missing, ambiguous, externally stored, granted, or
    /// otherwise not the sole exact root-relative attachment.
    EvidenceShape,
    /// The fixed-width evidence payload is not canonical.
    EvidenceEncoding,
    /// The rooted inline artifact is not one canonical ComponentArtifact.
    ArtifactEncoding,
    /// The object-store snapshot could not bind the selected recovered object.
    ObjectBinding,
    /// Atomic persistent-CSpace installation rejected the recovered graph.
    Install(PersistentInstallError),
    /// A post-install typed witness invariant failed; the CSpace was
    /// quarantined before this error was returned.
    Witness,
}

impl From<PersistentInstallError> for ComponentRootError {
    fn from(error: PersistentInstallError) -> Self {
        Self::Install(error)
    }
}

/// One fully authorized but still inert recovered Component artifact root.
///
/// This type intentionally implements neither `Clone` nor `Debug`. Its private
/// fields retain exactly one slot, root grant, typed resource witness, and
/// expected byte length until the consuming CSpace installation.
#[must_use = "an authorized Component artifact root must be installed or discarded"]
pub struct TrustedComponentArtifactRoot {
    slots: Vec<RecoveredSlot>,
    grants: Vec<RecoveredGrant>,
    resource: PersistentResourceWitness,
    expected_len: usize,
}

/// Typed read authority produced only by consuming an exact trusted root.
///
/// No durable ID, root policy, recovered record, raw capability, or object
/// reference is exposed on the public surface.
///
/// ```compile_fail
/// use vibeos_component_loader::ComponentArtifactPersistentRead;
///
/// fn raw_identity(read: &ComponentArtifactPersistentRead) {
///     let _ = read.object_id();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::ComponentArtifactPersistentRead;
///
/// fn require_clone<T: Clone>() {}
///
/// fn duplicate() {
///     require_clone::<ComponentArtifactPersistentRead>();
/// }
/// ```
#[must_use = "the recovered Component artifact read witness must be consumed by the loader"]
pub struct ComponentArtifactPersistentRead {
    witness: PersistentDerivationWitness<StoredObject>,
    expected_len: usize,
}

pub(crate) struct ValidatedRecoveredComponentRoot<'a> {
    pub(crate) slot: &'a RecoveredSlot,
    pub(crate) grant: &'a RecoveredGrant,
    pub(crate) object: &'a RecoveredObject,
    pub(crate) expected_len: usize,
}

impl ValidatedRecoveredComponentRoot<'_> {
    pub(crate) fn bind(self, resource: Arc<StoredObject>) -> TrustedComponentArtifactRoot {
        let resource = PersistentResourceWitness::new(
            self.grant.grant.object_id,
            stored_object_resource_kind(),
            resource,
        );
        TrustedComponentArtifactRoot {
            slots: alloc::vec![*self.slot],
            grants: alloc::vec![self.grant.clone()],
            resource,
            expected_len: self.expected_len,
        }
    }
}

/// Canonical durable operator evidence selected only through the exact root
/// bundle. It is inert data, not a StoredObject capability or an authentication
/// receipt. This type intentionally implements neither `Clone` nor `Debug`.
#[must_use = "root-bound operator evidence must be consumed by fresh authentication"]
pub struct DurableOperatorEvidence {
    encoded: [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN],
}

impl DurableOperatorEvidence {
    pub(crate) fn into_bytes(self) -> [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN] {
        self.encoded
    }
}

/// Move-only root plus its exact inert operator-evidence attachment.
///
/// ```compile_fail
/// use vibeos_component_loader::TrustedOperatorComponentArtifactBundle;
/// fn no_raw_identity(bundle: &TrustedOperatorComponentArtifactBundle) {
///     let _ = bundle.object_id();
///     let _ = bundle.evidence_bytes();
/// }
/// ```
#[must_use = "an authorized operator bundle must be installed or discarded"]
pub struct TrustedOperatorComponentArtifactBundle {
    root: TrustedComponentArtifactRoot,
    evidence: DurableOperatorEvidence,
}

/// Exact typed artifact READ witness paired with root-bound inert evidence.
#[must_use = "an installed operator bundle must be consumed by the authenticated loader"]
pub struct InstalledOperatorComponentArtifact {
    artifact: ComponentArtifactPersistentRead,
    evidence: DurableOperatorEvidence,
}

impl InstalledOperatorComponentArtifact {
    pub(crate) fn into_parts(self) -> (ComponentArtifactPersistentRead, DurableOperatorEvidence) {
        (self.artifact, self.evidence)
    }
}

impl TrustedOperatorComponentArtifactBundle {
    pub fn install(
        self,
        cspace: &mut CSpace,
        expected_incarnation: u64,
    ) -> Result<InstalledOperatorComponentArtifact, ComponentRootError> {
        let artifact = self.root.install(cspace, expected_incarnation)?;
        Ok(InstalledOperatorComponentArtifact {
            artifact,
            evidence: self.evidence,
        })
    }
}

pub(crate) struct ValidatedRecoveredOperatorBundle<'a> {
    pub(crate) root: ValidatedRecoveredComponentRoot<'a>,
    pub(crate) evidence: &'a RecoveredObject,
    pub(crate) evidence_bytes: [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN],
}

impl ValidatedRecoveredOperatorBundle<'_> {
    pub(crate) fn bind(
        self,
        resource: Arc<StoredObject>,
    ) -> TrustedOperatorComponentArtifactBundle {
        TrustedOperatorComponentArtifactBundle {
            root: self.root.bind(resource),
            evidence: DurableOperatorEvidence {
                encoded: self.evidence_bytes,
            },
        }
    }
}

impl ComponentArtifactPersistentRead {
    /// Hand the typed authority to the remainder of this crate without
    /// widening the public recovery surface.
    pub(crate) fn into_parts(self) -> (PersistentDerivationWitness<StoredObject>, usize) {
        (self.witness, self.expected_len)
    }
}

/// Authorize at most one live Component artifact root from one opaque, exact
/// object-store recovery.
///
/// Absence and the exact tombstoned slot-zero history return `Ok(None)`. Every
/// malformed or ambiguous same-space graph fails closed. The recovery can only
/// be created by [`vibeos_object_store::AuthorityJournal::recover_bound`],
/// which keeps the scanned preflight private while applying the complete
/// explicit root-policy partition union. An inert `AuthoritySnapshot` or a
/// caller-created durable-format preflight has no conversion into this type.
/// The selected record is then materialized from that same canonical recovered
/// view. No caller-provided graph, resource substitution, or object-ID lookup
/// hook exists.
///
/// ```compile_fail
/// use vibeos_component_loader::authorize_recovered;
/// use vibeos_durable_format::RecoveredStore;
///
/// fn substitute(recovered: &RecoveredStore) {
///     let _ = authorize_recovered(recovered);
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::authorize_recovered;
/// use vibeos_object_store::AuthoritySnapshot;
///
/// fn substitute(snapshot: &AuthoritySnapshot) {
///     let _ = authorize_recovered(snapshot);
/// }
/// ```
pub fn authorize_recovered(
    recovery: &BoundAuthorityRecovery,
) -> Result<Option<TrustedComponentArtifactRoot>, ComponentRootError> {
    let recovered = recovery.recovered();
    let Some(validated) = validate_recovered(recovered)? else {
        return Ok(None);
    };
    let resource = recovery
        .stored_object(validated.object)
        .map_err(|_| ComponentRootError::ObjectBinding)?;
    Ok(Some(validated.bind(resource)))
}

/// Authorize one operator bundle only when the fixed root, root-relative six-ID
/// layout, canonical inline evidence, and record order all agree. The evidence
/// object is selected by its exact root-relative ID, never by newest kind.
pub fn authorize_recovered_operator_bundle(
    recovery: &BoundAuthorityRecovery,
) -> Result<Option<TrustedOperatorComponentArtifactBundle>, ComponentRootError> {
    let Some(validated) = validate_recovered_operator_bundle(recovery.recovered())? else {
        return Ok(None);
    };
    if recovery
        .exact_object_has_grant_history(validated.evidence)
        .map_err(|_| ComponentRootError::ObjectBinding)?
    {
        return Err(ComponentRootError::EvidenceShape);
    }
    let resource = recovery
        .stored_object(validated.root.object)
        .map_err(|_| ComponentRootError::ObjectBinding)?;
    Ok(Some(validated.bind(resource)))
}

/// Inert semantic hook for the global authority-policy coordinator. It confers
/// no capability and returns only root presence. Inline artifacts must select
/// exactly one disjoint development or operator layout from their canonical
/// signer-policy kind; mixed Component/evidence orphan objects fail closed.
pub fn validate_recovered_bundle_shape(
    recovered: &RecoveredStore,
) -> Result<bool, ComponentRootError> {
    let component_history = recovered
        .slots
        .iter()
        .any(|slot| slot.space == component_artifact_space_id())
        || recovered
            .grants
            .iter()
            .any(|grant| grant.grant.target.space == component_artifact_space_id())
        || recovered.objects.iter().any(|object| {
            object.object_kind == component_artifact_object_kind()
                || object.object_kind == operator_evidence_object_kind()
        });
    let Some(root) = validate_recovered(recovered)? else {
        return if component_history {
            Err(ComponentRootError::UnexpectedGraph)
        } else {
            Ok(false)
        };
    };
    validate_single_artifact_object(recovered, root.object)?;
    validate_c74_artifact_root_layout(&root)?;

    if root.object.is_external() {
        // C7.4's sealed initial-install protocol is deliberately one complete
        // inline batch. C7.2 generic root recovery remains external-capable.
        return Err(ComponentRootError::BundleIdentity);
    }

    let artifact = decode_canonical_artifact(root.object)?;
    match artifact.signer_policy().kind() {
        ComponentArtifactSignerPolicyKind::DevelopmentImagePin => {
            validate_c74_reservation_end(recovered, &root, 2, 4)?;
            reject_any_evidence_object(recovered)?;
        }
        ComponentArtifactSignerPolicyKind::OperatorRequired => {
            let _ = validate_recovered_operator_from_root(recovered, root)?;
        }
    }
    Ok(true)
}

pub(crate) fn validate_recovered(
    recovered: &RecoveredStore,
) -> Result<Option<ValidatedRecoveredComponentRoot<'_>>, ComponentRootError> {
    let space = component_artifact_space_id();
    let mut slots = recovered.slots.iter().filter(|slot| slot.space == space);
    let first_slot = slots.next();
    if slots.next().is_some() {
        return Err(ComponentRootError::UnexpectedGraph);
    }

    let mut grants = recovered
        .grants
        .iter()
        .filter(|grant| grant.grant.target.space == space);
    let first_grant = grants.next();
    if grants.next().is_some() {
        return Err(ComponentRootError::UnexpectedGraph);
    }

    let Some(slot) = first_slot else {
        return if first_grant.is_none() {
            Ok(None)
        } else {
            Err(ComponentRootError::UnexpectedGraph)
        };
    };
    if slot.slot != COMPONENT_ARTIFACT_ROOT_SLOT
        || slot.max_generation != COMPONENT_ARTIFACT_ROOT_GENERATION
    {
        return Err(ComponentRootError::UnexpectedGraph);
    }

    let Some(recovered_grant) = first_grant else {
        return if slot.live_derivation.is_none() {
            // The only accepted absent history is generation-zero slot zero
            // after its root was durably tombstoned.
            Ok(None)
        } else {
            Err(ComponentRootError::UnexpectedGraph)
        };
    };
    let grant = &recovered_grant.grant;
    if slot.live_derivation != Some(grant.derivation_id)
        || recovered.tombstones.contains(&grant.derivation_id)
        || !root_policy_is_exact(&RootPolicy {
            grant: grant.clone(),
        })
    {
        return Err(ComponentRootError::UnexpectedGraph);
    }

    // The root grant's exact object identity is the only join key. A matching
    // kind elsewhere in the store is intentionally irrelevant.
    let mut objects = recovered
        .objects
        .iter()
        .filter(|object| object.object_id == grant.object_id);
    let object = objects.next().ok_or(ComponentRootError::UnexpectedGraph)?;
    if objects.next().is_some() {
        return Err(ComponentRootError::UnexpectedGraph);
    }
    if object.object_kind != component_artifact_object_kind() {
        return Err(ComponentRootError::ObjectKind);
    }

    let expected_len =
        usize::try_from(object.byte_len()).map_err(|_| ComponentRootError::ObjectSize)?;
    let inline_length_exact = object.is_external() || object.bytes.len() == expected_len;
    if !(COMPONENT_ARTIFACT_HEADER_LEN..=MAX_COMPONENT_ARTIFACT_ENCODED_BYTES)
        .contains(&expected_len)
        || !inline_length_exact
        || (object.is_external() && !object.bytes.is_empty())
    {
        return Err(ComponentRootError::ObjectSize);
    }
    let object_transaction_is_canonical = if object.is_external() {
        object.prepare_sequence == object.commit_sequence
    } else {
        object.prepare_sequence < object.commit_sequence
    };
    if object.prepare_sequence == 0
        || !object_transaction_is_canonical
        || recovered_grant.prepare_sequence == 0
        || recovered_grant.prepare_sequence >= recovered_grant.commit_sequence
        || object.commit_sequence >= recovered_grant.commit_sequence
    {
        return Err(ComponentRootError::CommitOrder);
    }

    Ok(Some(ValidatedRecoveredComponentRoot {
        slot,
        grant: recovered_grant,
        object,
        expected_len,
    }))
}

pub(crate) fn validate_recovered_operator_bundle(
    recovered: &RecoveredStore,
) -> Result<Option<ValidatedRecoveredOperatorBundle<'_>>, ComponentRootError> {
    let Some(root) = validate_recovered(recovered)? else {
        return Ok(None);
    };
    validate_single_artifact_object(recovered, root.object)?;
    if decode_canonical_artifact(root.object)?
        .signer_policy()
        .kind()
        != ComponentArtifactSignerPolicyKind::OperatorRequired
    {
        return Err(ComponentRootError::ArtifactEncoding);
    }
    validate_recovered_operator_from_root(recovered, root).map(Some)
}

fn decode_canonical_artifact(
    object: &RecoveredObject,
) -> Result<ComponentArtifactV1, ComponentRootError> {
    let artifact = ComponentArtifactV1::decode(&object.bytes)
        .map_err(|_| ComponentRootError::ArtifactEncoding)?;
    let canonical = artifact
        .encode()
        .map_err(|_| ComponentRootError::ArtifactEncoding)?;
    if canonical != object.bytes {
        return Err(ComponentRootError::ArtifactEncoding);
    }
    Ok(artifact)
}

fn validate_recovered_operator_from_root<'a>(
    recovered: &'a RecoveredStore,
    root: ValidatedRecoveredComponentRoot<'a>,
) -> Result<ValidatedRecoveredOperatorBundle<'a>, ComponentRootError> {
    if root.object.is_external() {
        return Err(ComponentRootError::BundleIdentity);
    }
    validate_c74_artifact_root_layout(&root)?;
    let root_transaction = root.grant.transaction_id.get();
    let first = root_transaction
        .checked_sub(4)
        .ok_or(ComponentRootError::BundleIdentity)?;
    validate_c74_reservation_end(recovered, &root, 4, 6)?;
    let evidence_transaction =
        TransactionId::new(first).ok_or(ComponentRootError::BundleIdentity)?;
    let evidence_object = ObjectId::new(
        first
            .checked_add(1)
            .ok_or(ComponentRootError::BundleIdentity)?,
    )
    .ok_or(ComponentRootError::BundleIdentity)?;

    let mut exact = recovered
        .objects
        .iter()
        .filter(|object| object.object_id == evidence_object);
    let evidence = exact.next().ok_or(ComponentRootError::EvidenceShape)?;
    if exact.next().is_some()
        || evidence.transaction_id != evidence_transaction
        || evidence.object_kind != operator_evidence_object_kind()
        || evidence.is_external()
        || evidence.byte_len() != COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN as u64
        || evidence.bytes.len() != COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN
        || evidence.prepare_sequence == 0
        || evidence
            .prepare_sequence
            .checked_add(2)
            .is_none_or(|commit| commit != evidence.commit_sequence)
        || evidence
            .commit_sequence
            .checked_add(1)
            .is_none_or(|prepare| prepare != root.object.prepare_sequence)
        || recovered
            .grants
            .iter()
            .any(|grant| grant.grant.object_id == evidence_object)
    {
        return Err(ComponentRootError::EvidenceShape);
    }

    let evidence_count = recovered
        .objects
        .iter()
        .filter(|object| object.object_kind == operator_evidence_object_kind())
        .count();
    if evidence_count != 1 {
        return Err(ComponentRootError::EvidenceShape);
    }

    let encoded: [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN] = evidence
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| ComponentRootError::EvidenceEncoding)?;
    let canonical = ComponentArtifactAuthenticationEvidenceV1::decode(&encoded)
        .map_err(|_| ComponentRootError::EvidenceEncoding)?
        .encode();
    if canonical != encoded {
        return Err(ComponentRootError::EvidenceEncoding);
    }

    Ok(ValidatedRecoveredOperatorBundle {
        root,
        evidence,
        evidence_bytes: canonical,
    })
}

fn validate_c74_reservation_end(
    recovered: &RecoveredStore,
    root: &ValidatedRecoveredComponentRoot<'_>,
    root_transaction_offset: u128,
    id_count: u128,
) -> Result<(), ComponentRootError> {
    let base = root
        .grant
        .transaction_id
        .get()
        .checked_sub(root_transaction_offset)
        .ok_or(ComponentRootError::BundleIdentity)?;
    let id_end = base
        .checked_add(id_count)
        .ok_or(ComponentRootError::BundleIdentity)?;
    let space_end = COMPONENT_ARTIFACT_SPACE_ID_RAW
        .checked_add(1)
        .ok_or(ComponentRootError::BundleIdentity)?;
    if recovered.id_high_water != id_end.max(space_end)
        || recovered.last_sequence != root.grant.commit_sequence
    {
        return Err(ComponentRootError::BundleIdentity);
    }
    Ok(())
}

fn validate_single_artifact_object(
    recovered: &RecoveredStore,
    selected: &RecoveredObject,
) -> Result<(), ComponentRootError> {
    let mut artifacts = recovered
        .objects
        .iter()
        .filter(|object| object.object_kind == component_artifact_object_kind());
    let exact = artifacts
        .next()
        .ok_or(ComponentRootError::UnexpectedGraph)?;
    if artifacts.next().is_some() || exact.object_id != selected.object_id {
        return Err(ComponentRootError::UnexpectedGraph);
    }
    Ok(())
}

fn reject_any_evidence_object(recovered: &RecoveredStore) -> Result<(), ComponentRootError> {
    if recovered
        .objects
        .iter()
        .any(|object| object.object_kind == operator_evidence_object_kind())
    {
        Err(ComponentRootError::EvidenceShape)
    } else {
        Ok(())
    }
}

fn validate_c74_artifact_root_layout(
    root: &ValidatedRecoveredComponentRoot<'_>,
) -> Result<(), ComponentRootError> {
    let root_transaction = root.grant.transaction_id.get();
    let expected_artifact_transaction = root_transaction
        .checked_sub(2)
        .and_then(TransactionId::new)
        .ok_or(ComponentRootError::BundleIdentity)?;
    let expected_artifact_object = root_transaction
        .checked_sub(1)
        .and_then(ObjectId::new)
        .ok_or(ComponentRootError::BundleIdentity)?;
    let expected_derivation = root_transaction
        .checked_add(1)
        .and_then(DerivationId::new)
        .ok_or(ComponentRootError::BundleIdentity)?;
    if root.object.transaction_id != expected_artifact_transaction
        || root.object.object_id != expected_artifact_object
        || root.grant.grant.object_id != expected_artifact_object
        || root.grant.grant.derivation_id != expected_derivation
    {
        return Err(ComponentRootError::BundleIdentity);
    }
    if root
        .object
        .commit_sequence
        .checked_add(1)
        .is_none_or(|prepare| prepare != root.grant.prepare_sequence)
        || root
            .grant
            .prepare_sequence
            .checked_add(1)
            .is_none_or(|commit| commit != root.grant.commit_sequence)
    {
        return Err(ComponentRootError::CommitOrder);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn authorize_recovered_for_test(
    recovered: &RecoveredStore,
) -> Result<Option<TrustedComponentArtifactRoot>, ComponentRootError> {
    Ok(validate_recovered(recovered)?.map(|validated| {
        let resource = StoredObject::from_recovered(validated.object);
        validated.bind(resource)
    }))
}

impl TrustedComponentArtifactRoot {
    /// Atomically install the exact recovered root and return only its typed
    /// read witness plus the privately retained expected artifact length.
    pub fn install(
        self,
        cspace: &mut CSpace,
        expected_incarnation: u64,
    ) -> Result<ComponentArtifactPersistentRead, ComponentRootError> {
        let Self {
            slots,
            grants,
            resource,
            expected_len,
        } = self;
        let resources = [resource];
        let identities =
            cspace.install_recovered_graph(expected_incarnation, &slots, &grants, &resources)?;
        let [identity] = identities.as_slice() else {
            let _ = cspace.quarantine_persistent();
            return Err(ComponentRootError::Witness);
        };
        let identity = *identity;
        let grant = &grants[0].grant;
        if identity.space() != component_artifact_space_id()
            || identity.slot() != COMPONENT_ARTIFACT_ROOT_SLOT
            || identity.generation() != COMPONENT_ARTIFACT_ROOT_GENERATION
            || identity.derivation_id() != grant.derivation_id
            || identity.object_id() != grant.object_id
            || identity.resource_kind() != stored_object_resource_kind()
            || identity.rights() != Rights::READ
        {
            let _ = cspace.quarantine_persistent();
            return Err(ComponentRootError::Witness);
        }
        let witness =
            match cspace.persistent_witness_for_identity::<StoredObject>(identity, Rights::READ) {
                Ok(witness) => witness,
                Err(_) => {
                    let _ = cspace.quarantine_persistent();
                    return Err(ComponentRootError::Witness);
                }
            };
        Ok(ComponentArtifactPersistentRead {
            witness,
            expected_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_durable_format::{
        preflight_recovery, preview_external_object_transaction, preview_grant_transaction,
        preview_id_high_water, DerivationId, GrantFlags, GrantRecord, ObjectId, RecordBody,
        RecordChain, StoreId, TransactionId,
    };

    const ROOT_DERIVATION_RAW: u128 = 0x101;
    const ROOT_OBJECT_RAW: u128 = 0x201;
    const UNREFERENCED_OBJECT_RAW: u128 = 0x202;
    const OBJECT_STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;

    fn derivation(value: u128) -> DerivationId {
        DerivationId::new(value).expect("test derivation ID is non-zero")
    }

    fn object_id(value: u128) -> ObjectId {
        ObjectId::new(value).expect("test object ID is non-zero")
    }

    fn transaction(value: u128) -> TransactionId {
        TransactionId::new(value).expect("test transaction ID is non-zero")
    }

    fn store_id() -> StoreId {
        StoreId::new(0x301).expect("test store ID is non-zero")
    }

    fn other_space() -> SpaceId {
        SpaceId::new(0x401).expect("test SpaceId is non-zero")
    }

    fn valid_object(object_id: ObjectId) -> RecoveredObject {
        let bytes = alloc::vec![0_u8; COMPONENT_ARTIFACT_HEADER_LEN];
        RecoveredObject {
            object_id,
            object_kind: component_artifact_object_kind(),
            byte_len: bytes.len() as u64,
            bytes,
            external_root: None,
            transaction_id: transaction(0x501),
            prepare_sequence: 1,
            commit_sequence: 2,
        }
    }

    fn valid_grant(object_id: ObjectId) -> RecoveredGrant {
        RecoveredGrant {
            grant: GrantRecord {
                derivation_id: derivation(ROOT_DERIVATION_RAW),
                parent_id: None,
                object_id,
                target: vibeos_durable_format::SlotIdentity {
                    space: component_artifact_space_id(),
                    slot: COMPONENT_ARTIFACT_ROOT_SLOT,
                    generation: COMPONENT_ARTIFACT_ROOT_GENERATION,
                },
                rights: COMPONENT_ARTIFACT_ROOT_RIGHTS,
                resource_kind: stored_object_resource_kind(),
                flags: GrantFlags::ROOT,
            },
            transaction_id: transaction(0x502),
            prepare_sequence: 3,
            commit_sequence: 4,
        }
    }

    fn valid_slot() -> RecoveredSlot {
        RecoveredSlot {
            space: component_artifact_space_id(),
            slot: COMPONENT_ARTIFACT_ROOT_SLOT,
            max_generation: COMPONENT_ARTIFACT_ROOT_GENERATION,
            live_derivation: Some(derivation(ROOT_DERIVATION_RAW)),
        }
    }

    fn valid_store() -> RecoveredStore {
        let root_object = object_id(ROOT_OBJECT_RAW);
        RecoveredStore {
            store_id: store_id(),
            id_high_water: 0x600,
            grants: alloc::vec![valid_grant(root_object)],
            objects: alloc::vec![valid_object(root_object)],
            slots: alloc::vec![valid_slot()],
            tombstones: Vec::new(),
            last_sequence: 4,
            last_crc32c: 0x1234_5678,
        }
    }

    fn exact_external_recovery() -> RecoveredStore {
        let durable_store = StoreId::new(OBJECT_STORE_ID_RAW).unwrap();
        let mut chain = RecordChain::new(durable_store);
        let mut records = alloc::vec![chain.append(None, RecordBody::Format).unwrap()];
        let (high_water, next) = preview_id_high_water(&chain, u128::MAX).unwrap();
        records.extend(high_water.records);
        chain = next;
        let root_object = object_id(ROOT_OBJECT_RAW);
        let (object_transaction, next) = preview_external_object_transaction(
            &chain,
            transaction(0x501),
            root_object,
            component_artifact_object_kind(),
            COMPONENT_ARTIFACT_HEADER_LEN as u64,
            [0xa5; 32],
        )
        .unwrap();
        records.extend(object_transaction.records);
        chain = next;
        let grant = valid_grant(root_object);
        let (grant_transaction, _next) =
            preview_grant_transaction(&chain, grant.transaction_id, grant.grant).unwrap();
        records.extend(grant_transaction.records);

        let preflight = preflight_recovery(&records, durable_store).unwrap();
        let roots = preflight.select_roots(&[root_constraint()]).unwrap();
        preflight.finish(&roots).unwrap()
    }

    fn authorize(store: &RecoveredStore) -> TrustedComponentArtifactRoot {
        authorize_recovered_for_test(store)
            .expect("valid root authorization must not fail")
            .expect("valid root must be present")
    }

    fn authorization_error(store: &RecoveredStore) -> ComponentRootError {
        match authorize_recovered_for_test(store) {
            Err(error) => error,
            Ok(_) => panic!("invalid root unexpectedly authorized"),
        }
    }

    fn install_error(
        trusted: TrustedComponentArtifactRoot,
        cspace: &mut CSpace,
        expected_incarnation: u64,
    ) -> ComponentRootError {
        match trusted.install(cspace, expected_incarnation) {
            Err(error) => error,
            Ok(_) => panic!("invalid persistent installation unexpectedly succeeded"),
        }
    }

    #[test]
    fn fixed_constraint_binds_every_root_field_and_exact_read_only() {
        let constraint = root_constraint();
        assert_eq!(constraint.space, component_artifact_space_id());
        assert_eq!(constraint.first_slot, COMPONENT_ARTIFACT_ROOT_SLOT);
        assert_eq!(constraint.last_slot_inclusive, COMPONENT_ARTIFACT_ROOT_SLOT);
        assert_eq!(constraint.rights.required, DurableRights::READ);
        assert_eq!(constraint.rights.allowed, DurableRights::READ);
        assert_eq!(constraint.resource_kind, stored_object_resource_kind());
        assert_eq!(constraint.object_kind, component_artifact_object_kind());
        assert_eq!(
            constraint.object_kind.get(),
            COMPONENT_ARTIFACT_OBJECT_KIND_RAW
        );
        assert_eq!(
            constraint.resource_kind.get(),
            STORED_OBJECT_RESOURCE_KIND_RAW
        );
        assert_ne!(constraint.space.get(), 0);
    }

    #[test]
    fn exact_root_policy_rejects_every_wrong_field_and_extra_right() {
        let exact = valid_grant(object_id(ROOT_OBJECT_RAW)).grant;
        assert!(root_policy_is_exact(&RootPolicy {
            grant: exact.clone(),
        }));

        let mut wrong = exact.clone();
        wrong.parent_id = Some(derivation(0x102));
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        let mut wrong = exact.clone();
        wrong.flags = GrantFlags::DERIVED;
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        let mut wrong = exact.clone();
        wrong.target.space = other_space();
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        let mut wrong = exact.clone();
        wrong.target.slot = 1;
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        let mut wrong = exact.clone();
        wrong.target.generation = 1;
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        let mut wrong = exact.clone();
        wrong.rights = DurableRights::NONE;
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));

        for extra in [
            DurableRights::WRITE,
            DurableRights::SEND,
            DurableRights::RECV,
            DurableRights::GRANT,
            DurableRights::REVOKE,
        ] {
            let mut wrong = exact.clone();
            wrong.rights = DurableRights::READ.union(extra);
            assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));
        }

        let mut wrong = exact;
        wrong.resource_kind = ResourceKind::new(STORED_OBJECT_RESOURCE_KIND_RAW + 1).unwrap();
        assert!(!root_policy_is_exact(&RootPolicy { grant: wrong }));
    }

    #[test]
    fn no_root_and_canonical_generation_zero_tombstone_are_absent() {
        let mut empty = valid_store();
        empty.slots.clear();
        empty.grants.clear();
        empty.objects.clear();
        let result = validate_recovered(&empty);
        assert!(matches!(result, Ok(None)));

        let mut tombstoned = valid_store();
        tombstoned.slots[0].live_derivation = None;
        tombstoned.grants.clear();
        tombstoned.objects.clear();
        tombstoned.tombstones.push(derivation(ROOT_DERIVATION_RAW));
        let result = validate_recovered(&tombstoned);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn malformed_absence_and_nonzero_slot_history_fail_closed() {
        let mut grant_without_slot = valid_store();
        grant_without_slot.slots.clear();
        assert_eq!(
            authorization_error(&grant_without_slot),
            ComponentRootError::UnexpectedGraph
        );

        let mut live_slot_without_grant = valid_store();
        live_slot_without_grant.grants.clear();
        assert_eq!(
            authorization_error(&live_slot_without_grant),
            ComponentRootError::UnexpectedGraph
        );

        let mut reused_tombstone = valid_store();
        reused_tombstone.slots[0].max_generation = 1;
        reused_tombstone.slots[0].live_derivation = None;
        reused_tombstone.grants.clear();
        assert_eq!(
            authorization_error(&reused_tombstone),
            ComponentRootError::UnexpectedGraph
        );

        let mut contradictory_tombstone = valid_store();
        contradictory_tombstone
            .tombstones
            .push(derivation(ROOT_DERIVATION_RAW));
        assert_eq!(
            authorization_error(&contradictory_tombstone),
            ComponentRootError::UnexpectedGraph
        );
    }

    #[test]
    fn duplicate_same_space_slot_or_root_is_rejected() {
        let mut duplicate_slot = valid_store();
        duplicate_slot.slots.push(valid_slot());
        assert_eq!(
            authorization_error(&duplicate_slot),
            ComponentRootError::UnexpectedGraph
        );

        let mut duplicate_root = valid_store();
        duplicate_root
            .grants
            .push(valid_grant(object_id(ROOT_OBJECT_RAW)));
        assert_eq!(
            authorization_error(&duplicate_root),
            ComponentRootError::UnexpectedGraph
        );

        let mut wrong_slot = valid_store();
        wrong_slot.slots[0].slot = 1;
        assert_eq!(
            authorization_error(&wrong_slot),
            ComponentRootError::UnexpectedGraph
        );
    }

    #[test]
    fn wrong_outer_kind_fails_before_object_binding() {
        let mut recovered = valid_store();
        recovered.objects[0].object_kind = ObjectKind::new(0x7f00_0001).unwrap();
        let result = validate_recovered(&recovered);
        assert!(matches!(result, Err(ComponentRootError::ObjectKind)));
    }

    #[test]
    fn exact_bad_object_cannot_fallback_to_unreferenced_good_kind() {
        let mut recovered = valid_store();
        recovered.objects[0].object_kind = ObjectKind::new(0x7f00_0002).unwrap();
        recovered
            .objects
            .push(valid_object(object_id(UNREFERENCED_OBJECT_RAW)));
        let result = validate_recovered(&recovered);
        assert!(matches!(result, Err(ComponentRootError::ObjectKind)));
    }

    #[test]
    fn missing_or_duplicate_exact_object_is_rejected_without_fallback() {
        let mut missing = valid_store();
        missing.objects[0] = valid_object(object_id(UNREFERENCED_OBJECT_RAW));
        assert_eq!(
            authorization_error(&missing),
            ComponentRootError::UnexpectedGraph
        );

        let mut duplicate = valid_store();
        duplicate.objects.push(duplicate.objects[0].clone());
        assert_eq!(
            authorization_error(&duplicate),
            ComponentRootError::UnexpectedGraph
        );
    }

    #[test]
    fn inline_length_must_match_and_stay_inside_component_envelope() {
        let recovered = valid_store();
        assert!(authorize_recovered_for_test(&recovered)
            .expect("exact inline length must authorize")
            .is_some());

        let mut mismatch = valid_store();
        mismatch.objects[0].byte_len += 1;
        assert_eq!(
            authorization_error(&mismatch),
            ComponentRootError::ObjectSize
        );

        let mut short = valid_store();
        short.objects[0]
            .bytes
            .truncate(COMPONENT_ARTIFACT_HEADER_LEN - 1);
        short.objects[0].byte_len = short.objects[0].bytes.len() as u64;
        assert_eq!(authorization_error(&short), ComponentRootError::ObjectSize);

        let mut oversized = valid_store();
        oversized.objects[0].bytes.clear();
        oversized.objects[0].external_root = Some([0x5a; 32]);
        oversized.objects[0].byte_len = MAX_COMPONENT_ARTIFACT_ENCODED_BYTES as u64 + 1;
        assert_eq!(
            authorization_error(&oversized),
            ComponentRootError::ObjectSize
        );
    }

    #[test]
    fn external_length_is_exact_bounded_and_has_no_inline_alias() {
        let recovered = exact_external_recovery();
        assert_eq!(recovered.objects[0].prepare_sequence, 3);
        assert_eq!(recovered.objects[0].commit_sequence, 3);
        assert_eq!(recovered.grants[0].prepare_sequence, 4);
        assert_eq!(recovered.grants[0].commit_sequence, 5);
        assert!(validate_recovered(&recovered)
            .expect("real single-record external recovery must validate")
            .is_some());

        let mut external = valid_store();
        external.objects[0].bytes.clear();
        external.objects[0].external_root = Some([0xa5; 32]);
        external.objects[0].byte_len = COMPONENT_ARTIFACT_HEADER_LEN as u64;
        external.objects[0].prepare_sequence = external.objects[0].commit_sequence;
        let validated = validate_recovered(&external)
            .expect("bounded external object must authorize")
            .expect("external root must remain live");
        assert_eq!(
            validated.object.byte_len(),
            COMPONENT_ARTIFACT_HEADER_LEN as u64
        );

        let mut inline_alias = external.clone();
        inline_alias.objects[0].bytes.push(0xff);
        assert_eq!(
            authorization_error(&inline_alias),
            ComponentRootError::ObjectSize
        );

        let mut short = external;
        short.objects[0].byte_len = (COMPONENT_ARTIFACT_HEADER_LEN - 1) as u64;
        assert_eq!(authorization_error(&short), ComponentRootError::ObjectSize);
    }

    #[test]
    fn object_and_root_prepare_commit_order_is_strict() {
        let mut object_prepare_late = valid_store();
        object_prepare_late.objects[0].prepare_sequence = 2;
        assert_eq!(
            authorization_error(&object_prepare_late),
            ComponentRootError::CommitOrder
        );

        let mut external_split_transaction = valid_store();
        external_split_transaction.objects[0].bytes.clear();
        external_split_transaction.objects[0].external_root = Some([0xa5; 32]);
        assert_eq!(
            authorization_error(&external_split_transaction),
            ComponentRootError::CommitOrder
        );

        let mut zero_sequence = valid_store();
        zero_sequence.objects[0].prepare_sequence = 0;
        assert_eq!(
            authorization_error(&zero_sequence),
            ComponentRootError::CommitOrder
        );

        let mut root_prepare_late = valid_store();
        root_prepare_late.grants[0].prepare_sequence = 4;
        assert_eq!(
            authorization_error(&root_prepare_late),
            ComponentRootError::CommitOrder
        );

        let mut same_commit = valid_store();
        same_commit.grants[0].commit_sequence = same_commit.objects[0].commit_sequence;
        assert_eq!(
            authorization_error(&same_commit),
            ComponentRootError::CommitOrder
        );

        let mut root_committed_first = valid_store();
        root_committed_first.objects[0].commit_sequence = 5;
        assert_eq!(
            authorization_error(&root_committed_first),
            ComponentRootError::CommitOrder
        );
    }

    #[test]
    fn exact_join_selects_only_the_root_objects_record() {
        let mut recovered = valid_store();
        let mut unreferenced = valid_object(object_id(UNREFERENCED_OBJECT_RAW));
        unreferenced.commit_sequence = 20;
        recovered.objects.push(unreferenced);
        let validated = validate_recovered(&recovered)
            .expect("selected root must authorize")
            .expect("selected root must be present");
        assert_eq!(validated.object.object_id, object_id(ROOT_OBJECT_RAW));
        assert_eq!(validated.object.commit_sequence, 2);
    }

    #[test]
    fn consuming_install_returns_exact_typed_read_witness_and_length() {
        let recovered = valid_store();
        let trusted = authorize(&recovered);
        let mut cspace = CSpace::new_persistent(
            "component-artifact-root-test",
            component_artifact_space_id(),
        );
        let incarnation = cspace.incarnation();
        let read = trusted
            .install(&mut cspace, incarnation)
            .expect("exact recovered graph must install atomically");
        assert_eq!(cspace.live_count(), 1);
        assert_eq!(
            cspace.singleton_live_shape(),
            Some(("stored-object", Rights::READ))
        );
        assert!(!cspace.is_persistent_quarantined());

        let (witness, expected_len) = read.into_parts();
        assert_eq!(expected_len, COMPONENT_ARTIFACT_HEADER_LEN);
        let identity = witness.identity();
        assert_eq!(identity.space(), component_artifact_space_id());
        assert_eq!(identity.slot(), COMPONENT_ARTIFACT_ROOT_SLOT);
        assert_eq!(identity.generation(), COMPONENT_ARTIFACT_ROOT_GENERATION);
        assert_eq!(identity.derivation_id(), derivation(ROOT_DERIVATION_RAW));
        assert_eq!(identity.object_id(), object_id(ROOT_OBJECT_RAW));
        assert_eq!(identity.resource_kind(), stored_object_resource_kind());
        assert_eq!(identity.rights(), Rights::READ);
        assert!(cspace
            .persistent_witness_for_identity::<StoredObject>(identity, Rights::READ)
            .is_ok());
    }

    #[test]
    fn install_failures_leave_an_unpublished_target_unchanged() {
        let recovered = valid_store();

        let mut volatile = CSpace::new("component-artifact-volatile-test");
        let incarnation = volatile.incarnation();
        assert_eq!(
            install_error(authorize(&recovered), &mut volatile, incarnation),
            ComponentRootError::Install(PersistentInstallError::NotPersistentSpace)
        );
        assert_eq!(volatile.live_count(), 0);

        let mut foreign = CSpace::new_persistent("component-artifact-foreign-test", other_space());
        let incarnation = foreign.incarnation();
        assert_eq!(
            install_error(authorize(&recovered), &mut foreign, incarnation),
            ComponentRootError::Install(PersistentInstallError::ForeignSpace)
        );
        assert_eq!(foreign.live_count(), 0);
        assert!(!foreign.is_persistent_quarantined());

        let mut restarted = CSpace::new_persistent(
            "component-artifact-incarnation-test",
            component_artifact_space_id(),
        );
        let stale = restarted.incarnation() + 1;
        assert_eq!(
            install_error(authorize(&recovered), &mut restarted, stale),
            ComponentRootError::Install(PersistentInstallError::IncarnationChanged)
        );
        assert_eq!(restarted.live_count(), 0);
        assert!(!restarted.is_persistent_quarantined());
    }

    #[test]
    fn second_install_is_refused_without_replacing_the_live_root() {
        let recovered = valid_store();
        let mut cspace = CSpace::new_persistent(
            "component-artifact-single-root-test",
            component_artifact_space_id(),
        );
        let incarnation = cspace.incarnation();
        let first = authorize(&recovered)
            .install(&mut cspace, incarnation)
            .expect("first exact graph must install");
        assert_eq!(cspace.live_count(), 1);
        assert_eq!(
            install_error(authorize(&recovered), &mut cspace, incarnation),
            ComponentRootError::Install(PersistentInstallError::SlotBusy)
        );
        assert_eq!(cspace.live_count(), 1);
        assert_eq!(
            cspace.singleton_live_shape(),
            Some(("stored-object", Rights::READ))
        );
        assert!(!cspace.is_persistent_quarantined());
        drop(first);
    }
}
