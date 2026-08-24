//! Sealed C7.6 graph-history persistence.
//!
//! This module deliberately does not share the C7.4/C7.5 Component namespace
//! validator.  A V3 checkpoint owns one graph root in slot zero and retains a
//! complete, root-relative set of inline inputs for generation zero and, at
//! most once, generation one.

use super::{
    authority, erase_bytes, finish_recovered_snapshot, require_storage_v2_selection, store_id,
    AuthorityJournal, AuthoritySnapshot, StorageV2OnlyAuthorityJournal,
    StorageV2RecoveredAuthorityHead, StoreError, C74_PERSISTENT_OBJECT_KIND_RAW,
    C74_PERSISTENT_SPACE_ID_RAW, C74_PROGRAM_OBJECT_KIND_RAW, C74_PROGRAM_SPACE_ID_RAW,
    C74_STORED_OBJECT_RESOURCE_KIND_RAW, FIRST_ALLOCATABLE_ID,
};
use alloc::vec::Vec;

/// Frozen V3 external root policy test vector. Production integration receives
/// only the SHA-256 commitment below; these raw bytes are not compiled into a
/// public seam.
#[cfg(test)]
const C76_STORAGE_V2_EXTERNAL_POLICY: &[u8] = b"vibeos.storage-v2.external-policy.v3\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0graph-space=0x564942454f532d47524150482d563100,slot=0,generations=0..1,rights=r,kind=0x43475631\0graph-attachments=exact-root-relative,per-generation=3*0x434d5031+3*0x434d4531+1*0x43474531,inline=1,ungranted=1,max-replacement=1";

/// SHA-256 of the frozen V3 external root policy.
const C76_STORAGE_V2_EXTERNAL_POLICY_SHA256: [u8; 32] = [
    0xf5, 0x1d, 0x38, 0x1c, 0x13, 0x23, 0xf5, 0x1b, 0x6b, 0xc7, 0x52, 0x86, 0xcc, 0x43, 0xbe, 0x1a,
    0xab, 0xf7, 0xfe, 0x63, 0x75, 0x4c, 0x1a, 0x75, 0xfc, 0x67, 0xa0, 0x57, 0x80, 0xaa, 0x52, 0x1a,
];

pub const C76_GRAPH_COMPONENT_COUNT: usize = 3;

const C76_GRAPH_SPACE_ID_RAW: u128 = 0x5649_4245_4f53_2d47_5241_5048_2d56_3100;
const C76_GRAPH_VERSION_OBJECT_KIND_RAW: u32 = 0x4347_5631; // CGV1
const C76_GRAPH_EVIDENCE_OBJECT_KIND_RAW: u32 = 0x4347_4531; // CGE1
const C76_COMPONENT_ARTIFACT_OBJECT_KIND_RAW: u32 = 0x434d_5031; // CMP1
const C76_COMPONENT_EVIDENCE_OBJECT_KIND_RAW: u32 = 0x434d_4531; // CME1
const C76_COMPONENT_EVIDENCE_LEN: usize = 112;
const C76_GRAPH_EVIDENCE_LEN: usize = 112;
const C76_ATTACHMENTS_PER_VERSION: usize = 7;
const C76_OBJECTS_PER_VERSION: usize = C76_ATTACHMENTS_PER_VERSION + 1;
const C76_INITIAL_ID_COUNT: u128 = 18;
const C76_SUCCESSOR_ID_COUNT: u128 = 19;
const C76_BOOT_RECOVERY_ATTEMPTS: usize = 120_000;

/// Frozen V3 policy commitment without exposing the canonical policy bytes,
/// raw SpaceId, or raw ObjectKind values.
///
/// ```compile_fail
/// use vibeos_object_store::{
///     C76_GRAPH_SPACE_ID_RAW, C76_GRAPH_VERSION_OBJECT_KIND_RAW,
///     C76_STORAGE_V2_EXTERNAL_POLICY,
/// };
/// ```
pub const fn c76_storage_v2_external_policy_sha256() -> [u8; 32] {
    C76_STORAGE_V2_EXTERNAL_POLICY_SHA256
}

/// Sealed C7.6 view of the authority journal. This type is intentionally not
/// cloneable and exposes only exact V3 recovery: no generic recovery, append,
/// snapshot, checkpoint, or durable-object lookup operation crosses the boot
/// handoff.
///
/// ```compile_fail
/// use vibeos_object_store::C76AuthorityJournal;
/// fn require_clone<T: Clone>() {}
/// fn cannot_duplicate() { require_clone::<C76AuthorityJournal>(); }
/// ```
///
/// ```compile_fail
/// use vibeos_object_store::C76AuthorityJournal;
/// async fn no_generic_seams(journal: C76AuthorityJournal) {
///     let _ = journal.recover().await;
///     let _ = journal.recover_storage_v2_only().await;
///     let _ = journal.append(&[]).await;
///     let _ = journal.snapshot();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_object_store::C76AuthorityJournal;
/// async fn exactly_once(journal: C76AuthorityJournal) {
///     let _ = journal.recover_exact_v3().await;
///     let _ = journal.recover_exact_v3().await;
/// }
/// ```
#[must_use = "the sealed C7.6 journal must be exactly recovered or discarded"]
pub struct C76AuthorityJournal {
    journal: AuthorityJournal,
}

/// C7.7's private cancellation-safe terminal revoker.  It is minted before
/// the first asynchronous poll and follows the boot typestate through both
/// logical recovery and independent physical readback.  Dropping any future
/// or intermediate checkpoint therefore closes the same boot proof as an
/// explicit success or error.
pub(super) struct C77BootProofRevocation {
    journal: AuthorityJournal,
}

impl Drop for C77BootProofRevocation {
    fn drop(&mut self) {
        self.journal.revoke_storage_v2_authority_boot_proof();
    }
}

impl C76AuthorityJournal {
    pub(super) const fn new(journal: AuthorityJournal) -> Self {
        Self { journal }
    }

    pub(super) fn c77_terminal_revocation(&self) -> C77BootProofRevocation {
        C77BootProofRevocation {
            journal: self.journal.clone(),
        }
    }

    /// Consume this boot probe, recover and classify the selected physical
    /// Storage V2 authority stream under the exact V3 policy, and release no
    /// generic recovered head.
    pub async fn recover_exact_v3(self) -> Result<C76RecoveredState, C76StorageV2Error> {
        let mut last_transient = StoreError::Busy;
        for _ in 0..C76_BOOT_RECOVERY_ATTEMPTS {
            match self.journal.recover_storage_v2_only().await {
                Ok(head) => return c76_recover_state(head),
                Err(
                    error @ (StoreError::Busy
                    | StoreError::BackendAuthority
                    | StoreError::Unformatted),
                ) => {
                    last_transient = error;
                    vibeos_core::exec::sleep_ms(1).await;
                }
                Err(error) => {
                    self.journal.revoke_storage_v2_authority_boot_proof();
                    return Err(C76StorageV2Error::Recovery(error));
                }
            }
        }
        self.journal.revoke_storage_v2_authority_boot_proof();
        Err(C76StorageV2Error::Recovery(last_transient))
    }
}

fn c76_space() -> authority::SpaceId {
    authority::SpaceId::new(C76_GRAPH_SPACE_ID_RAW).expect("C7.6 graph space is non-zero")
}

fn c76_resource_kind() -> authority::ResourceKind {
    authority::ResourceKind::new(C74_STORED_OBJECT_RESOURCE_KIND_RAW)
        .expect("stored-object resource kind is non-zero")
}

fn c76_graph_version_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C76_GRAPH_VERSION_OBJECT_KIND_RAW)
        .expect("CGV1 object kind is non-zero")
}

fn c76_graph_evidence_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C76_GRAPH_EVIDENCE_OBJECT_KIND_RAW)
        .expect("CGE1 object kind is non-zero")
}

fn c76_component_artifact_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C76_COMPONENT_ARTIFACT_OBJECT_KIND_RAW)
        .expect("CMP1 object kind is non-zero")
}

fn c76_component_evidence_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C76_COMPONENT_EVIDENCE_OBJECT_KIND_RAW)
        .expect("CME1 object kind is non-zero")
}

fn c76_relevant_kind(kind: authority::ObjectKind) -> bool {
    kind == c76_graph_version_kind()
        || kind == c76_graph_evidence_kind()
        || kind == c76_component_artifact_kind()
        || kind == c76_component_evidence_kind()
}

fn c76_attachment_kind(index: usize) -> authority::ObjectKind {
    match index {
        0..=2 => c76_component_artifact_kind(),
        3..=5 => c76_component_evidence_kind(),
        6 => c76_graph_evidence_kind(),
        _ => unreachable!("C7.6 attachment index is fixed"),
    }
}

/// Borrowed, authority-free input for one complete graph version.
///
/// The descriptor is the sole granted CGV1 object.  All seven attachments are
/// inline, retained-only records and can never be materialized by this API.
pub struct C76GraphVersionInput<'a> {
    pub descriptor_bytes: &'a [u8],
    pub component_artifact_bytes: [&'a [u8]; C76_GRAPH_COMPONENT_COUNT],
    pub component_evidence_bytes: [&'a [u8]; C76_GRAPH_COMPONENT_COUNT],
    pub graph_evidence_bytes: &'a [u8],
}

impl<'a> C76GraphVersionInput<'a> {
    fn attachment_bytes(&self, index: usize) -> &[u8] {
        match index {
            0..=2 => self.component_artifact_bytes[index],
            3..=5 => self.component_evidence_bytes[index - 3],
            6 => self.graph_evidence_bytes,
            _ => unreachable!("C7.6 attachment index is fixed"),
        }
    }

    fn validate(&self) -> Result<(), C76StorageV2Error> {
        let valid_inline =
            |bytes: &[u8]| !bytes.is_empty() && bytes.len() <= authority::MAX_OBJECT_SIZE;
        if !valid_inline(self.descriptor_bytes)
            || self.graph_evidence_bytes.len() != C76_GRAPH_EVIDENCE_LEN
            || self
                .component_artifact_bytes
                .iter()
                .any(|bytes| !valid_inline(bytes))
            || self
                .component_evidence_bytes
                .iter()
                .any(|bytes| bytes.len() != C76_COMPONENT_EVIDENCE_LEN || !valid_inline(bytes))
        {
            return Err(C76StorageV2Error::InvalidVersion);
        }
        Ok(())
    }
}

/// Owned bytes copied from one exact physical V3 checkpoint.  No checkpoint,
/// token, stable ID, root record, policy witness, or capability is exposed.
#[must_use = "physically recovered graph bytes must be freshly admitted or discarded"]
pub struct C76GraphVersionBytes {
    descriptor_bytes: Vec<u8>,
    component_artifact_bytes: [Vec<u8>; C76_GRAPH_COMPONENT_COUNT],
    component_evidence_bytes: [Vec<u8>; C76_GRAPH_COMPONENT_COUNT],
    graph_evidence_bytes: Vec<u8>,
}

impl C76GraphVersionBytes {
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    pub fn component_artifact_bytes(&self, index: usize) -> Option<&[u8]> {
        self.component_artifact_bytes.get(index).map(Vec::as_slice)
    }

    pub fn component_evidence_bytes(&self, index: usize) -> Option<&[u8]> {
        self.component_evidence_bytes.get(index).map(Vec::as_slice)
    }

    pub fn graph_evidence_bytes(&self) -> &[u8] {
        &self.graph_evidence_bytes
    }
}

/// Single consuming C7.6 boot probe.
#[must_use = "the recovered C7.6 state must be installed, physically checked, or discarded"]
pub enum C76RecoveredState {
    Vacant(C76VacantHead),
    Existing(C76PendingPhysicalReadback),
}

/// A boot-proved V3 checkpoint with no C7.6 graph history.
#[must_use = "a vacant C7.6 head must be installed or discarded"]
pub struct C76VacantHead {
    journal: StorageV2OnlyAuthorityJournal,
    snapshot: AuthoritySnapshot,
}

/// An acknowledged exact G0 or G1 checkpoint awaiting independent physical
/// readback.  The expected history and journal provenance remain private.
#[must_use = "a pending C7.6 graph must be physically recovered or discarded"]
pub struct C76PendingPhysicalReadback {
    journal: StorageV2OnlyAuthorityJournal,
    expected: C76ExactHistory,
    persistent_root_present: bool,
    program_root_present: bool,
    /// Sealed result of checking the complete logical namespace, not merely
    /// the live-root union.  C7.7 requires this to reject even tombstoned
    /// persistent/program history before performing its one physical readback.
    exact_final_graph_only: bool,
}

/// Result of independent physical readback.  Only G0 retains the one-shot
/// linear append authority needed to create G1.
#[must_use = "the recovered graph must be freshly admitted or discarded"]
pub enum C76RecoveredGraphState {
    G0(C76ReplaceableGraph),
    G1(C76FinalGraph),
}

/// Physically recovered G0 plus the sole one-shot replacement transition.
#[must_use = "G0 must be admitted, replaced, or discarded"]
pub struct C76ReplaceableGraph {
    journal: StorageV2OnlyAuthorityJournal,
    expected: C76ExactHistory,
    current: C76GraphVersionBytes,
}

impl C76ReplaceableGraph {
    pub fn current(&self) -> &C76GraphVersionBytes {
        &self.current
    }

    /// Append one complete successor version, tombstone G0, and commit the G1
    /// root in the same policy-bound Storage V2 checkpoint.
    pub async fn replace(
        self,
        successor: C76GraphVersionInput<'_>,
    ) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
        c76_replace(self, successor).await
    }
}

/// Physically recovered final history.  Both complete versions come from the
/// same exact G1 checkpoint so replacement admission can revalidate them as a
/// pair; this type has no further write transition.
///
/// ```compile_fail
/// use vibeos_object_store::{C76FinalGraph, C76GraphVersionInput};
/// async fn cold_g1_cannot_write(graph: C76FinalGraph, next: C76GraphVersionInput<'_>) {
///     let _ = graph.replace(next).await;
/// }
/// ```
#[must_use = "G1 history must be freshly admitted or discarded"]
pub struct C76FinalGraph {
    predecessor: C76GraphVersionBytes,
    successor: C76GraphVersionBytes,
}

impl C76FinalGraph {
    pub fn predecessor(&self) -> &C76GraphVersionBytes {
        &self.predecessor
    }

    pub fn successor(&self) -> &C76GraphVersionBytes {
        &self.successor
    }
}

/// Redacted V3 state-machine errors.  No stable identity or recovered record
/// crosses this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C76StorageV2Error {
    Recovery(StoreError),
    Unformatted,
    ExternalPolicyMismatch,
    ExistingGraphHistory,
    InvalidVersion,
    IdExhausted,
    Encode,
    Append(StoreError),
    PostflightMismatch,
}

/// Kernel policy result for an inert durable preflight.  This is the only
/// public bridge which releases C7.6 recovered records: its payload is meant
/// to be passed directly to `PersistentAuthorityImport`, never to a runtime or
/// loader namespace.
pub enum C76PreflightPolicyState {
    Vacant,
    G0(C76PreflightPolicyHistory),
    G1(C76PreflightPolicyHistory),
}

/// Opaque exact current graph selection. G1 contains fourteen retained-only
/// attachments in stable ObjectId order. The root record is never released;
/// callers can only compare the complete-union selection against it, then
/// consume this value into the import-only attachment payload.
///
/// ```compile_fail
/// use vibeos_object_store::C76PreflightPolicyHistory;
/// fn no_raw_history(history: C76PreflightPolicyHistory) {
///     let _ = history.root_policy();
///     let _ = history.retained_inline_attachments();
/// }
/// ```
#[must_use = "validated policy records must be imported or discarded"]
pub struct C76PreflightPolicyHistory {
    root_policy: authority::RootPolicy,
    retained_inline_attachments: Vec<authority::RecoveredObject>,
}

impl C76PreflightPolicyState {
    /// Whether the exact validator selected a live V3 graph root.
    pub const fn has_graph_root(&self) -> bool {
        !matches!(self, Self::Vacant)
    }

    /// Compare a root selected by the kernel's complete policy union without
    /// releasing the recovered root record through this bridge.
    pub fn graph_root_matches(&self, candidate: Option<&authority::RootPolicy>) -> bool {
        match (self, candidate) {
            (Self::Vacant, None) => true,
            (Self::G0(history) | Self::G1(history), Some(candidate)) => {
                history.root_policy == *candidate
            }
            _ => false,
        }
    }

    /// Consume the policy result into the exact retained-only attachment set
    /// required by the inert import, but only when the kernel's independently
    /// selected complete-union graph root is identical. No borrowed raw
    /// history view or root record is exposed.
    pub fn into_import_attachments_for_root(
        self,
        candidate: Option<&authority::RootPolicy>,
    ) -> Result<Vec<authority::RecoveredObject>, C76PreflightPolicyError> {
        if !self.graph_root_matches(candidate) {
            return Err(C76PreflightPolicyError::InvalidHistory);
        }
        match self {
            Self::Vacant => Ok(Vec::new()),
            Self::G0(history) | Self::G1(history) => Ok(history.retained_inline_attachments),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C76PreflightPolicyError {
    InvalidHistory,
    Allocation,
}

/// Validate exactly zero, one, or two fixed-layout C7.6 versions before
/// authority finish.  Every reserved-kind object must occupy its unique
/// root-relative position; attachments must be inline and ungranted; every
/// descriptor must have exactly its matching graph-root history; and G1 must
/// be the sole live root after the tombstone-first same-slot transition.
pub fn validate_c76_preflight_policy(
    preflight: &authority::RecoveryPreflight,
) -> Result<C76PreflightPolicyState, C76PreflightPolicyError> {
    let history = c76_exact_history_preflight(preflight).map_err(|error| match error {
        C76StorageV2Error::InvalidVersion => C76PreflightPolicyError::Allocation,
        _ => C76PreflightPolicyError::InvalidHistory,
    })?;
    let Some(history) = history else {
        return Ok(C76PreflightPolicyState::Vacant);
    };
    let current = history.current();
    let mut attachments = Vec::new();
    attachments
        .try_reserve_exact(history.versions.len() * C76_ATTACHMENTS_PER_VERSION)
        .map_err(|_| C76PreflightPolicyError::Allocation)?;
    for version in &history.versions {
        attachments.extend_from_slice(&version.attachments);
    }
    let selected = C76PreflightPolicyHistory {
        root_policy: authority::RootPolicy {
            grant: current.root.grant.clone(),
        },
        retained_inline_attachments: attachments,
    };
    Ok(if history.versions.len() == 1 {
        C76PreflightPolicyState::G0(selected)
    } else {
        C76PreflightPolicyState::G1(selected)
    })
}

/// Fixed graph root constraint for the kernel-owned complete policy union.
pub fn c76_graph_root_constraint() -> authority::RootConstraint {
    authority::RootConstraint {
        space: c76_space(),
        first_slot: 0,
        last_slot_inclusive: 0,
        rights: authority::RootRightsConstraint::exact(authority::DurableRights::READ),
        resource_kind: c76_resource_kind(),
        object_kind: c76_graph_version_kind(),
    }
}

impl C76VacantHead {
    pub async fn install_initial(
        self,
        initial: C76GraphVersionInput<'_>,
    ) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
        c76_install_initial(self, initial).await
    }
}

impl C76PendingPhysicalReadback {
    /// Re-read the selected checkpoint, apply the complete fixed root union,
    /// verify that only the live CGV1 descriptor has a physical object binding,
    /// and release bytes only after exact descriptor readback.
    pub async fn recover_payload(self) -> Result<C76RecoveredGraphState, StoreError> {
        c76_recover_payload(self).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct C76ExpectedVersion {
    generation: u32,
    attachments: [authority::RecoveredObject; C76_ATTACHMENTS_PER_VERSION],
    descriptor: authority::RecoveredObject,
    root: authority::RecoveredGrant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct C76ExactHistory {
    versions: Vec<C76ExpectedVersion>,
    id_high_water: u128,
    last_sequence: u64,
}

impl C76ExactHistory {
    fn current(&self) -> &C76ExpectedVersion {
        self.versions
            .last()
            .expect("an exact C7.6 history is non-empty")
    }
}

fn c76_recover_state(
    head: StorageV2RecoveredAuthorityHead,
) -> Result<C76RecoveredState, C76StorageV2Error> {
    let revoker = head.journal.backend.clone();
    let result = c76_recover_state_inner(head);
    if result.is_err() {
        revoker.revoke_authority_boot_proof();
    }
    result
}

/// Consume a generic C7.6 classification into C7.7's narrower terminal gate.
/// A mismatch revokes the backend's boot proof so a caller cannot obtain a
/// fresh journal and retry a namespace that has already failed this boot.
pub(super) fn c77_take_exact_final_g1(
    state: C76RecoveredState,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let revoker = match &state {
        C76RecoveredState::Vacant(vacant) => vacant.journal.backend.clone(),
        C76RecoveredState::Existing(pending) => pending.journal.backend.clone(),
    };
    let result = match state {
        C76RecoveredState::Existing(pending) if pending.exact_final_graph_only => Ok(pending),
        C76RecoveredState::Vacant(_) | C76RecoveredState::Existing(_) => {
            Err(C76StorageV2Error::ExistingGraphHistory)
        }
    };
    if result.is_err() {
        revoker.revoke_authority_boot_proof();
    }
    result
}

fn c76_recover_state_inner(
    head: StorageV2RecoveredAuthorityHead,
) -> Result<C76RecoveredState, C76StorageV2Error> {
    let StorageV2RecoveredAuthorityHead { journal, snapshot } = head;
    c76_validate_sealed_head(&journal, &snapshot)?;
    match c76_exact_history(&snapshot)? {
        None => Ok(C76RecoveredState::Vacant(C76VacantHead {
            journal,
            snapshot,
        })),
        Some(expected) => {
            let (persistent, program, graph) = c76_root_presence(&snapshot)?;
            if !graph {
                return Err(C76StorageV2Error::ExistingGraphHistory);
            }
            let exact_final_graph_only = c76_exact_final_graph_only(&snapshot, &expected)?;
            Ok(C76RecoveredState::Existing(C76PendingPhysicalReadback {
                journal,
                expected,
                persistent_root_present: persistent,
                program_root_present: program,
                exact_final_graph_only,
            }))
        }
    }
}

fn c76_validate_sealed_head(
    journal: &StorageV2OnlyAuthorityJournal,
    snapshot: &AuthoritySnapshot,
) -> Result<(), C76StorageV2Error> {
    if journal.external_root_policy_sha256 != C76_STORAGE_V2_EXTERNAL_POLICY_SHA256 {
        return Err(C76StorageV2Error::ExternalPolicyMismatch);
    }
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C76StorageV2Error::Unformatted)?;
    if !snapshot.formatted
        || journal.checkpoint != snapshot.checkpoint
        || preflight.store_id() != store_id()
        || preflight.chain_checkpoint().ok() != Some(snapshot.checkpoint)
    {
        return Err(C76StorageV2Error::Unformatted);
    }
    Ok(())
}

fn c76_has_any_history(preflight: &authority::RecoveryPreflight) -> bool {
    preflight
        .slots()
        .iter()
        .any(|slot| slot.space == c76_space())
        || preflight
            .committed_grants()
            .iter()
            .any(|grant| grant.grant.target.space == c76_space())
        || preflight
            .committed_objects()
            .iter()
            .any(|object| c76_relevant_kind(object.object_kind))
}

fn c76_policy_space(space: authority::SpaceId) -> bool {
    space.get() == C74_PERSISTENT_SPACE_ID_RAW
        || space.get() == C74_PROGRAM_SPACE_ID_RAW
        || space == c76_space()
}

/// Close the V3 policy over the complete inert record set. Graph records are
/// admitted only through the exact root-relative history validator; every
/// other object must be named by persistent/program authority owned by the
/// other fixed policy partitions. This rejects singleton/latest-kind seams,
/// orphan objects, and grants or slot history in any foreign space.
fn c76_validate_policy_closure(
    preflight: &authority::RecoveryPreflight,
    history: Option<&C76ExactHistory>,
) -> Result<(), C76StorageV2Error> {
    if preflight
        .slots()
        .iter()
        .any(|slot| !c76_policy_space(slot.space))
        || preflight
            .committed_grants()
            .iter()
            .any(|grant| !c76_policy_space(grant.grant.target.space))
    {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }

    for object in preflight.committed_objects() {
        let exact_graph_object = history.is_some_and(|history| {
            history.versions.iter().any(|version| {
                version.descriptor.object_id == object.object_id
                    || version
                        .attachments
                        .iter()
                        .any(|attachment| attachment.object_id == object.object_id)
            })
        });
        if exact_graph_object {
            continue;
        }
        let mut owners = preflight
            .committed_grants()
            .iter()
            .filter(|grant| grant.grant.object_id == object.object_id);
        let Some(first) = owners.next() else {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        };
        let owner_space = first.grant.target.space;
        let allowed_owner = |grant: &authority::RecoveredGrant| {
            grant.grant.target.space.get() == C74_PERSISTENT_SPACE_ID_RAW
                || grant.grant.target.space.get() == C74_PROGRAM_SPACE_ID_RAW
        };
        if !allowed_owner(first)
            || owners.any(|grant| !allowed_owner(grant) || grant.grant.target.space != owner_space)
        {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }
    }
    Ok(())
}

fn c76_root_presence(
    snapshot: &AuthoritySnapshot,
) -> Result<(bool, bool, bool), C76StorageV2Error> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C76StorageV2Error::Unformatted)?;
    let live = |space_raw| {
        preflight
            .slots()
            .iter()
            .any(|slot| slot.space.get() == space_raw && slot.live_derivation.is_some())
    };
    Ok((
        live(C74_PERSISTENT_SPACE_ID_RAW),
        live(C74_PROGRAM_SPACE_ID_RAW),
        live(C76_GRAPH_SPACE_ID_RAW),
    ))
}

/// Whether the complete logical namespace is exactly the terminal two-version
/// graph history used by C7.7.  The live-root booleans are insufficient here:
/// a tombstoned persistent/program grant still leaves durable object, grant,
/// and slot history.  Exact G1 validation already fixes the identities,
/// ordering, high-water value, and one graph tombstone; the global cardinality
/// checks below therefore prove that no other partition or object remains.
/// The canonical base/first-prepare check also rejects an otherwise invisible
/// ID-high-water-only prefix carrying an extra durable numeric token.
fn c76_exact_final_graph_only(
    snapshot: &AuthoritySnapshot,
    history: &C76ExactHistory,
) -> Result<bool, C76StorageV2Error> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C76StorageV2Error::Unformatted)?;
    let [initial, current] = history.versions.as_slice() else {
        return Ok(false);
    };
    let canonical_origin = initial.root.transaction_id.get() == FIRST_ALLOCATABLE_ID + 16
        && initial
            .attachments
            .first()
            .is_some_and(|object| object.prepare_sequence == 3);
    let initial_high_water = checked_add(FIRST_ALLOCATABLE_ID, C76_INITIAL_ID_COUNT)?
        .max(checked_add(C76_GRAPH_SPACE_ID_RAW, 1)?);
    let second_high_water_sequence = initial
        .root
        .commit_sequence
        .checked_add(1)
        .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
    let first_high_water_event = (2, initial_high_water);
    let second_high_water_event = (second_high_water_sequence, history.id_high_water);
    let tombstone_transaction = current
        .root
        .transaction_id
        .get()
        .checked_sub(1)
        .and_then(authority::TransactionId::new);
    let tombstone_sequence = current.root.prepare_sequence.checked_sub(1);
    let exact_transition_records =
        tombstone_transaction
            .zip(tombstone_sequence)
            .is_some_and(|(transaction, sequence)| {
                preflight.has_only_exact_tombstone(
                    initial.root.grant.derivation_id,
                    transaction,
                    sequence,
                )
            })
            && preflight.has_only_exact_two_id_high_water_events(
                first_high_water_event,
                second_high_water_event,
            );
    let only_slot = preflight.slots().first().is_some_and(|slot| {
        slot.space == c76_space()
            && slot.slot == 0
            && slot.max_generation == 1
            && slot.live_derivation == Some(current.root.grant.derivation_id)
    });
    Ok(canonical_origin
        && exact_transition_records
        && history.versions.len() == 2
        && preflight.committed_objects().len() == 2 * C76_OBJECTS_PER_VERSION
        && preflight.committed_grants().len() == 2
        && preflight.slots().len() == 1
        && only_slot
        && c76_root_presence(snapshot)? == (false, false, true))
}

fn c76_exact_history(
    snapshot: &AuthoritySnapshot,
) -> Result<Option<C76ExactHistory>, C76StorageV2Error> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C76StorageV2Error::Unformatted)?;
    c76_exact_history_preflight(preflight)
}

fn c76_exact_history_preflight(
    preflight: &authority::RecoveryPreflight,
) -> Result<Option<C76ExactHistory>, C76StorageV2Error> {
    if !c76_has_any_history(preflight) {
        c76_validate_policy_closure(preflight, None)?;
        return Ok(None);
    }

    let mut graph_slots = preflight
        .slots()
        .iter()
        .filter(|slot| slot.space == c76_space());
    let slot = graph_slots
        .next()
        .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
    if graph_slots.next().is_some()
        || slot.slot != 0
        || slot.max_generation > 1
        || slot.live_derivation.is_none()
    {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }

    let mut graph_roots = preflight
        .committed_grants()
        .iter()
        .filter(|grant| grant.grant.target.space == c76_space());
    let expected_count = slot.max_generation as usize + 1;
    if graph_roots.clone().count() != expected_count || !(1..=2).contains(&expected_count) {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }

    let relevant_object_count = preflight
        .committed_objects()
        .iter()
        .filter(|object| c76_relevant_kind(object.object_kind))
        .count();
    if relevant_object_count != expected_count * C76_OBJECTS_PER_VERSION {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }

    let mut versions = Vec::new();
    versions
        .try_reserve_exact(expected_count)
        .map_err(|_| C76StorageV2Error::InvalidVersion)?;
    let mut predecessor_end = None;
    let mut predecessor_high_water = None;

    for index in 0..expected_count {
        let root = graph_roots
            .next()
            .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
        let generation = index as u32;
        let grant = &root.grant;
        let root_transaction_raw = root.transaction_id.get();
        let (base, root_transaction_offset, root_derivation_offset) = match generation {
            0 => (
                root_transaction_raw
                    .checked_sub(16)
                    .ok_or(C76StorageV2Error::ExistingGraphHistory)?,
                16,
                17,
            ),
            1 => (
                root_transaction_raw
                    .checked_sub(17)
                    .ok_or(C76StorageV2Error::ExistingGraphHistory)?,
                17,
                18,
            ),
            _ => return Err(C76StorageV2Error::ExistingGraphHistory),
        };
        if base == 0
            || root_transaction_raw != checked_add(base, root_transaction_offset)?
            || grant.derivation_id.get() != checked_add(base, root_derivation_offset)?
            || grant.parent_id.is_some()
            || grant.flags != authority::GrantFlags::ROOT
            || grant.target.space != c76_space()
            || grant.target.slot != 0
            || grant.target.generation != u64::from(generation)
            || grant.rights != authority::DurableRights::READ
            || grant.resource_kind != c76_resource_kind()
        {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }
        if generation == 1 && predecessor_high_water != Some(base) {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }

        let mut selected = Vec::new();
        selected
            .try_reserve_exact(C76_OBJECTS_PER_VERSION)
            .map_err(|_| C76StorageV2Error::InvalidVersion)?;
        for object_index in 0..C76_OBJECTS_PER_VERSION {
            let transaction_raw = checked_add(base, (object_index * 2) as u128)?;
            let object_raw = checked_add(transaction_raw, 1)?;
            let transaction = authority::TransactionId::new(transaction_raw)
                .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
            let object_id = authority::ObjectId::new(object_raw)
                .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
            let expected_kind = if object_index == C76_ATTACHMENTS_PER_VERSION {
                c76_graph_version_kind()
            } else {
                c76_attachment_kind(object_index)
            };
            let mut matches = preflight.committed_objects().iter().filter(|object| {
                object.object_id == object_id && object.transaction_id == transaction
            });
            let object = matches
                .next()
                .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
            if matches.next().is_some()
                || object.object_kind != expected_kind
                || object.is_external()
                || object.bytes.is_empty()
                || object.byte_len() != object.bytes.len() as u64
                || object.bytes.len() > authority::MAX_OBJECT_SIZE
                || (expected_kind == c76_component_evidence_kind()
                    && object.bytes.len() != C76_COMPONENT_EVIDENCE_LEN)
                || (expected_kind == c76_graph_evidence_kind()
                    && object.bytes.len() != C76_GRAPH_EVIDENCE_LEN)
            {
                return Err(C76StorageV2Error::ExistingGraphHistory);
            }
            selected.push(object.clone());
        }

        let mut next_sequence = selected[0].prepare_sequence;
        if next_sequence == 0 {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }
        if generation == 1
            && predecessor_end.and_then(|sequence: u64| sequence.checked_add(2))
                != Some(next_sequence)
        {
            // The sole record between G0 commit and the first G1 object is the
            // mandatory high-water advance.  There is no location here for an
            // early tombstone.
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }
        for object in &selected {
            let chunk_count = object.bytes.len().div_ceil(authority::CHUNK_DATA_SIZE) as u64;
            let expected_commit = object
                .prepare_sequence
                .checked_add(chunk_count)
                .and_then(|sequence| sequence.checked_add(1))
                .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
            if object.prepare_sequence != next_sequence || object.commit_sequence != expected_commit
            {
                return Err(C76StorageV2Error::ExistingGraphHistory);
            }
            next_sequence = object
                .commit_sequence
                .checked_add(1)
                .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
        }

        let descriptor = selected
            .pop()
            .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
        let attachments: [authority::RecoveredObject; C76_ATTACHMENTS_PER_VERSION] = selected
            .try_into()
            .map_err(|_| C76StorageV2Error::ExistingGraphHistory)?;
        if grant.object_id != descriptor.object_id
            || root.prepare_sequence
                != if generation == 0 {
                    next_sequence
                } else {
                    // Durable same-slot replay proves that the intervening
                    // record tombstones G0 before this prepare is accepted.
                    next_sequence
                        .checked_add(1)
                        .ok_or(C76StorageV2Error::ExistingGraphHistory)?
                }
            || root.commit_sequence
                != root
                    .prepare_sequence
                    .checked_add(1)
                    .ok_or(C76StorageV2Error::ExistingGraphHistory)?
        {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }

        let mut descriptor_grants = preflight
            .committed_grants()
            .iter()
            .filter(|candidate| candidate.grant.object_id == descriptor.object_id);
        if descriptor_grants.next() != Some(root)
            || descriptor_grants.next().is_some()
            || attachments.iter().any(|attachment| {
                preflight
                    .committed_grants()
                    .iter()
                    .any(|candidate| candidate.grant.object_id == attachment.object_id)
            })
        {
            return Err(C76StorageV2Error::ExistingGraphHistory);
        }

        let high_water = if generation == 0 {
            checked_add(base, C76_INITIAL_ID_COUNT)?.max(checked_add(C76_GRAPH_SPACE_ID_RAW, 1)?)
        } else {
            checked_add(base, C76_SUCCESSOR_ID_COUNT)?
        };
        predecessor_end = Some(root.commit_sequence);
        predecessor_high_water = Some(high_water);
        versions.push(C76ExpectedVersion {
            generation,
            attachments,
            descriptor,
            root: root.clone(),
        });
    }

    let current = versions
        .last()
        .ok_or(C76StorageV2Error::ExistingGraphHistory)?;
    if slot.live_derivation != Some(current.root.grant.derivation_id)
        || preflight.id_high_water()
            != predecessor_high_water.ok_or(C76StorageV2Error::ExistingGraphHistory)?
        || preflight.last_sequence() != current.root.commit_sequence
    {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }

    let history = C76ExactHistory {
        versions,
        id_high_water: preflight.id_high_water(),
        last_sequence: preflight.last_sequence(),
    };
    c76_validate_policy_closure(preflight, Some(&history))?;
    Ok(Some(history))
}

fn checked_add(base: u128, amount: u128) -> Result<u128, C76StorageV2Error> {
    base.checked_add(amount)
        .ok_or(C76StorageV2Error::IdExhausted)
}

fn c76_transaction(raw: u128) -> Result<authority::TransactionId, C76StorageV2Error> {
    authority::TransactionId::new(raw).ok_or(C76StorageV2Error::IdExhausted)
}

fn c76_object(raw: u128) -> Result<authority::ObjectId, C76StorageV2Error> {
    authority::ObjectId::new(raw).ok_or(C76StorageV2Error::IdExhausted)
}

fn c76_derivation(raw: u128) -> Result<authority::DerivationId, C76StorageV2Error> {
    authority::DerivationId::new(raw).ok_or(C76StorageV2Error::IdExhausted)
}

fn append_version_objects(
    chain: &mut authority::RecordChain,
    records: &mut Vec<[u8; authority::RECORD_SIZE]>,
    base: u128,
    input: &C76GraphVersionInput<'_>,
) -> Result<authority::ObjectId, C76StorageV2Error> {
    for index in 0..C76_OBJECTS_PER_VERSION {
        let transaction_raw = checked_add(base, (index * 2) as u128)?;
        let object_raw = checked_add(transaction_raw, 1)?;
        let kind = if index == C76_ATTACHMENTS_PER_VERSION {
            c76_graph_version_kind()
        } else {
            c76_attachment_kind(index)
        };
        let bytes = if index == C76_ATTACHMENTS_PER_VERSION {
            input.descriptor_bytes
        } else {
            input.attachment_bytes(index)
        };
        let (encoded, next) = authority::preview_object_transaction(
            chain,
            c76_transaction(transaction_raw)?,
            c76_object(object_raw)?,
            kind,
            bytes,
        )
        .map_err(|_| C76StorageV2Error::Encode)?;
        records.extend(encoded.records);
        *chain = next;
    }
    c76_object(checked_add(base, 15)?)
}

fn c76_encode_initial_records(
    snapshot: &AuthoritySnapshot,
    input: &C76GraphVersionInput<'_>,
) -> Result<Vec<[u8; authority::RECORD_SIZE]>, C76StorageV2Error> {
    input.validate()?;
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C76StorageV2Error::Unformatted)?;
    let base = preflight.id_high_water().max(FIRST_ALLOCATABLE_ID);
    let id_end = checked_add(base, C76_INITIAL_ID_COUNT)?;
    let space_end = checked_add(C76_GRAPH_SPACE_ID_RAW, 1)?;
    let mut chain = authority::RecordChain::from_checkpoint(store_id(), snapshot.checkpoint)
        .map_err(|_| C76StorageV2Error::Encode)?;
    let (high_water, next) = authority::preview_id_high_water(&chain, id_end.max(space_end))
        .map_err(|_| C76StorageV2Error::Encode)?;
    let mut records = high_water.records;
    chain = next;
    let descriptor = append_version_objects(&mut chain, &mut records, base, input)?;
    let root = authority::GrantRecord {
        derivation_id: c76_derivation(checked_add(base, 17)?)?,
        parent_id: None,
        object_id: descriptor,
        target: authority::SlotIdentity {
            space: c76_space(),
            slot: 0,
            generation: 0,
        },
        rights: authority::DurableRights::READ,
        resource_kind: c76_resource_kind(),
        flags: authority::GrantFlags::ROOT,
    };
    let (root, _) = authority::preview_grant_transaction(
        &chain,
        c76_transaction(checked_add(base, 16)?)?,
        root,
    )
    .map_err(|_| C76StorageV2Error::Encode)?;
    records.extend(root.records);
    Ok(records)
}

fn c76_encode_successor_records(
    checkpoint: authority::ChainCheckpoint,
    history: &C76ExactHistory,
    input: &C76GraphVersionInput<'_>,
) -> Result<Vec<[u8; authority::RECORD_SIZE]>, C76StorageV2Error> {
    input.validate()?;
    if history.versions.len() != 1 || history.current().generation != 0 {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }
    let base = history.id_high_water;
    let id_end = checked_add(base, C76_SUCCESSOR_ID_COUNT)?;
    let mut chain = authority::RecordChain::from_checkpoint(store_id(), checkpoint)
        .map_err(|_| C76StorageV2Error::Encode)?;
    let (high_water, next) =
        authority::preview_id_high_water(&chain, id_end).map_err(|_| C76StorageV2Error::Encode)?;
    let mut records = high_water.records;
    chain = next;
    let descriptor = append_version_objects(&mut chain, &mut records, base, input)?;
    let (revoke, next) = authority::preview_revoke_transaction(
        &chain,
        c76_transaction(checked_add(base, 16)?)?,
        history.current().root.grant.derivation_id,
    )
    .map_err(|_| C76StorageV2Error::Encode)?;
    records.extend(revoke.records);
    chain = next;
    let root = authority::GrantRecord {
        derivation_id: c76_derivation(checked_add(base, 18)?)?,
        parent_id: None,
        object_id: descriptor,
        target: authority::SlotIdentity {
            space: c76_space(),
            slot: 0,
            generation: 1,
        },
        rights: authority::DurableRights::READ,
        resource_kind: c76_resource_kind(),
        flags: authority::GrantFlags::ROOT,
    };
    let (root, _) = authority::preview_grant_transaction(
        &chain,
        c76_transaction(checked_add(base, 17)?)?,
        root,
    )
    .map_err(|_| C76StorageV2Error::Encode)?;
    records.extend(root.records);
    Ok(records)
}

async fn c76_install_initial(
    vacant: C76VacantHead,
    input: C76GraphVersionInput<'_>,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let revoker = vacant.journal.backend.clone();
    let result = c76_install_initial_inner(vacant, input).await;
    if result.is_err() {
        revoker.revoke_authority_boot_proof();
    }
    result
}

async fn c76_install_initial_inner(
    vacant: C76VacantHead,
    input: C76GraphVersionInput<'_>,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let C76VacantHead { journal, snapshot } = vacant;
    c76_validate_sealed_head(&journal, &snapshot)?;
    if c76_exact_history(&snapshot)?.is_some() {
        return Err(C76StorageV2Error::ExistingGraphHistory);
    }
    let records = c76_encode_initial_records(&snapshot, &input)?;
    let (journal, successor) = journal
        .append(&records)
        .await
        .map_err(C76StorageV2Error::Append)?;
    let expected = c76_exact_history(&successor)?.ok_or(C76StorageV2Error::PostflightMismatch)?;
    if expected.versions.len() != 1 || !c76_version_matches_input(&expected.versions[0], &input) {
        return Err(C76StorageV2Error::PostflightMismatch);
    }
    c76_pending(journal, successor, expected)
}

async fn c76_replace(
    replaceable: C76ReplaceableGraph,
    input: C76GraphVersionInput<'_>,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let revoker = replaceable.journal.backend.clone();
    let result = c76_replace_inner(replaceable, input).await;
    if result.is_err() {
        revoker.revoke_authority_boot_proof();
    }
    result
}

async fn c76_replace_inner(
    replaceable: C76ReplaceableGraph,
    input: C76GraphVersionInput<'_>,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let C76ReplaceableGraph {
        journal,
        expected,
        current: _,
    } = replaceable;
    if journal.external_root_policy_sha256 != C76_STORAGE_V2_EXTERNAL_POLICY_SHA256 {
        return Err(C76StorageV2Error::ExternalPolicyMismatch);
    }
    let records = c76_encode_successor_records(journal.checkpoint, &expected, &input)?;
    let (journal, successor) = journal
        .append(&records)
        .await
        .map_err(C76StorageV2Error::Append)?;
    let next = c76_exact_history(&successor)?.ok_or(C76StorageV2Error::PostflightMismatch)?;
    if next.versions.len() != 2
        || next.versions[0] != expected.versions[0]
        || !c76_version_matches_input(&next.versions[1], &input)
    {
        return Err(C76StorageV2Error::PostflightMismatch);
    }
    c76_pending(journal, successor, next)
}

fn c76_version_matches_input(
    version: &C76ExpectedVersion,
    input: &C76GraphVersionInput<'_>,
) -> bool {
    version.descriptor.bytes.as_slice() == input.descriptor_bytes
        && version
            .attachments
            .iter()
            .enumerate()
            .all(|(index, object)| object.bytes.as_slice() == input.attachment_bytes(index))
}

fn c76_pending(
    journal: StorageV2OnlyAuthorityJournal,
    snapshot: AuthoritySnapshot,
    expected: C76ExactHistory,
) -> Result<C76PendingPhysicalReadback, C76StorageV2Error> {
    let (persistent, program, graph) = c76_root_presence(&snapshot)?;
    if !graph {
        return Err(C76StorageV2Error::PostflightMismatch);
    }
    let exact_final_graph_only = c76_exact_final_graph_only(&snapshot, &expected)?;
    Ok(C76PendingPhysicalReadback {
        journal,
        expected,
        persistent_root_present: persistent,
        program_root_present: program,
        exact_final_graph_only,
    })
}

struct C76FixedRootPolicyUnion {
    persistent_present: bool,
    program_present: bool,
    persistent: [authority::RootConstraint; 1],
    program: [authority::RootConstraint; 1],
    graph: [authority::RootConstraint; 1],
}

impl C76FixedRootPolicyUnion {
    fn new(persistent_present: bool, program_present: bool) -> Self {
        let fixed = |space_raw, rights, object_kind_raw| authority::RootConstraint {
            space: authority::SpaceId::new(space_raw).expect("fixed root space is non-zero"),
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(rights),
            resource_kind: c76_resource_kind(),
            object_kind: authority::ObjectKind::new(object_kind_raw)
                .expect("fixed root object kind is non-zero"),
        };
        Self {
            persistent_present,
            program_present,
            persistent: [fixed(
                C74_PERSISTENT_SPACE_ID_RAW,
                authority::DurableRights::READ
                    .union(authority::DurableRights::GRANT)
                    .union(authority::DurableRights::REVOKE),
                C74_PERSISTENT_OBJECT_KIND_RAW,
            )],
            program: [fixed(
                C74_PROGRAM_SPACE_ID_RAW,
                authority::DurableRights::READ,
                C74_PROGRAM_OBJECT_KIND_RAW,
            )],
            graph: [fixed(
                C76_GRAPH_SPACE_ID_RAW,
                authority::DurableRights::READ,
                C76_GRAPH_VERSION_OBJECT_KIND_RAW,
            )],
        }
    }

    fn partitions(&self) -> Vec<authority::RootPolicyPartition<'_>> {
        let mut partitions = Vec::with_capacity(3);
        if self.persistent_present {
            partitions.push(authority::RootPolicyPartition {
                space: self.persistent[0].space,
                constraints: &self.persistent,
            });
        }
        if self.program_present {
            partitions.push(authority::RootPolicyPartition {
                space: self.program[0].space,
                constraints: &self.program,
            });
        }
        partitions.push(authority::RootPolicyPartition {
            space: self.graph[0].space,
            constraints: &self.graph,
        });
        partitions
    }
}

async fn c76_recover_payload(
    pending: C76PendingPhysicalReadback,
) -> Result<C76RecoveredGraphState, StoreError> {
    c76_recover_payload_inner(pending, false).await
}

/// C7.7's second, independent physical gate.  Unlike the general C7.6
/// readback, this accepts only the already-final, graph-only two-version
/// namespace and returns no replacement authority.
pub(super) async fn c77_recover_exact_final_g1(
    pending: C76PendingPhysicalReadback,
) -> Result<C76FinalGraph, StoreError> {
    let revoker = pending.journal.backend.clone();
    let result = match c76_recover_payload_inner(pending, true).await {
        Err(error) => Err(error),
        Ok(C76RecoveredGraphState::G1(graph)) => Ok(graph),
        Ok(C76RecoveredGraphState::G0(graph)) => {
            graph.journal.backend.revoke_authority_boot_proof();
            Err(StoreError::Corrupt)
        }
    };
    // C7.7 is a terminal, read-only boot transition.  Revoke even a successful
    // physical proof so neither a later semantic-revalidation failure nor any
    // other TCB caller can re-mint the broader C7.6 journal in this boot.
    revoker.revoke_authority_boot_proof();
    result
}

async fn c76_recover_payload_inner(
    pending: C76PendingPhysicalReadback,
    require_exact_final_graph_only: bool,
) -> Result<C76RecoveredGraphState, StoreError> {
    let C76PendingPhysicalReadback {
        journal,
        expected,
        persistent_root_present,
        program_root_present,
        exact_final_graph_only,
    } = pending;
    let revoker = journal.backend.clone();
    let result = async {
        if require_exact_final_graph_only && !exact_final_graph_only {
            return Err(StoreError::Corrupt);
        }
        require_storage_v2_selection(journal.backend.as_ref())?;
        if journal.external_root_policy_sha256 != C76_STORAGE_V2_EXTERNAL_POLICY_SHA256 {
            return Err(StoreError::Corrupt);
        }
        let readback = journal.backend.readback_authority().await?;
        if readback.external_root_policy_sha256() != C76_STORAGE_V2_EXTERNAL_POLICY_SHA256 {
            return Err(StoreError::Corrupt);
        }
        let snapshot = readback.into_facade()?;
        if snapshot.checkpoint != journal.checkpoint {
            return Err(StoreError::JournalChanged);
        }
        let observed = c76_exact_history(&snapshot)
            .map_err(|_| StoreError::Corrupt)?
            .ok_or(StoreError::Corrupt)?;
        if require_exact_final_graph_only
            && !c76_exact_final_graph_only(&snapshot, &observed).map_err(|_| StoreError::Corrupt)?
        {
            return Err(StoreError::Corrupt);
        }
        if observed != expected {
            return Err(StoreError::Corrupt);
        }
        let union = if require_exact_final_graph_only {
            C76FixedRootPolicyUnion::new(false, false)
        } else {
            C76FixedRootPolicyUnion::new(persistent_root_present, program_root_present)
        };
        let partitions = union.partitions();
        let mut recovery = finish_recovered_snapshot(snapshot, &partitions)?;
        c76_validate_physical_history(&recovery, &expected)?;
        let current_token = c76_current_descriptor_token(&recovery, &expected)?;
        let mut physical_descriptor = journal.backend.read_object(&current_token).await?;
        let current = expected.current();
        if physical_descriptor.as_slice() != current.descriptor.bytes.as_slice() {
            erase_bytes(&mut physical_descriptor);
            return Err(StoreError::Corrupt);
        }

        let mut payloads = Vec::new();
        payloads
            .try_reserve_exact(expected.versions.len())
            .map_err(|_| StoreError::InsufficientMemory)?;
        for version in &expected.versions {
            let descriptor = if version.generation == current.generation {
                Some(core::mem::take(&mut physical_descriptor))
            } else {
                None
            };
            payloads.push(c76_take_version_bytes(&mut recovery, version, descriptor)?);
        }
        match payloads.len() {
            1 if !require_exact_final_graph_only => {
                Ok(C76RecoveredGraphState::G0(C76ReplaceableGraph {
                    journal,
                    expected,
                    current: payloads.pop().expect("one C7.6 payload"),
                }))
            }
            2 => {
                let successor = payloads.pop().expect("two C7.6 payloads");
                let predecessor = payloads.pop().expect("two C7.6 payloads");
                drop(journal);
                Ok(C76RecoveredGraphState::G1(C76FinalGraph {
                    predecessor,
                    successor,
                }))
            }
            _ => Err(StoreError::Corrupt),
        }
    }
    .await;
    if result.is_err() {
        revoker.revoke_authority_boot_proof();
    }
    result
}

fn c76_validate_physical_history(
    recovery: &super::BoundAuthorityRecovery,
    expected: &C76ExactHistory,
) -> Result<(), StoreError> {
    if recovery.recovered.id_high_water != expected.id_high_water
        || recovery.recovered.last_sequence != expected.last_sequence
    {
        return Err(StoreError::Corrupt);
    }
    let bindings = recovery.v2_objects.as_deref().ok_or(StoreError::Corrupt)?;
    let current = expected.current();
    for version in &expected.versions {
        let descriptor = recovery.exact_object(&version.descriptor)?;
        let mut descriptor_history = recovery
            .grant_history
            .iter()
            .filter(|grant| grant.grant.object_id == descriptor.object_id);
        if descriptor_history.next() != Some(&version.root) || descriptor_history.next().is_some() {
            return Err(StoreError::Corrupt);
        }
        let descriptor_bindings = bindings
            .iter()
            .filter(|binding| binding.stable_object_id == descriptor.object_id)
            .count();
        if (version.generation == current.generation && descriptor_bindings != 1)
            || (version.generation != current.generation && descriptor_bindings != 0)
        {
            return Err(StoreError::Corrupt);
        }
        for attachment in &version.attachments {
            let exact = recovery.exact_object(attachment)?;
            if recovery
                .grant_history
                .iter()
                .any(|grant| grant.grant.object_id == exact.object_id)
                || bindings
                    .iter()
                    .any(|binding| binding.stable_object_id == exact.object_id)
            {
                return Err(StoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn c76_current_descriptor_token(
    recovery: &super::BoundAuthorityRecovery,
    expected: &C76ExactHistory,
) -> Result<super::StorageV2ObjectToken, StoreError> {
    let descriptor = recovery.exact_object(&expected.current().descriptor)?;
    recovery
        .v2_objects
        .as_deref()
        .ok_or(StoreError::Corrupt)?
        .iter()
        .find(|binding| binding.matches(descriptor))
        .map(|binding| binding.token.clone())
        .ok_or(StoreError::ObjectUnavailable)
}

fn c76_take_version_bytes(
    recovery: &mut super::BoundAuthorityRecovery,
    expected: &C76ExpectedVersion,
    physical_descriptor: Option<Vec<u8>>,
) -> Result<C76GraphVersionBytes, StoreError> {
    let take = |recovery: &mut super::BoundAuthorityRecovery,
                object: &authority::RecoveredObject|
     -> Result<Vec<u8>, StoreError> {
        let index = recovery
            .recovered
            .objects
            .iter()
            .position(|candidate| candidate == object)
            .ok_or(StoreError::Corrupt)?;
        Ok(core::mem::take(
            &mut recovery.recovered.objects[index].bytes,
        ))
    };

    let mut logical_descriptor = take(recovery, &expected.descriptor)?;
    let descriptor_bytes = match physical_descriptor {
        Some(bytes) => {
            if bytes.as_slice() != logical_descriptor.as_slice() {
                erase_bytes(&mut logical_descriptor);
                return Err(StoreError::Corrupt);
            }
            erase_bytes(&mut logical_descriptor);
            bytes
        }
        None => logical_descriptor,
    };

    let mut attachments = Vec::new();
    attachments
        .try_reserve_exact(C76_ATTACHMENTS_PER_VERSION)
        .map_err(|_| StoreError::InsufficientMemory)?;
    for attachment in &expected.attachments {
        attachments.push(take(recovery, attachment)?);
    }
    let graph_evidence_bytes = attachments.pop().ok_or(StoreError::Corrupt)?;
    let evidence: Vec<Vec<u8>> = attachments.drain(3..).collect();
    let component_artifact_bytes = attachments.try_into().map_err(|_| StoreError::Corrupt)?;
    let component_evidence_bytes = evidence.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(C76GraphVersionBytes {
        descriptor_bytes,
        component_artifact_bytes,
        component_evidence_bytes,
        graph_evidence_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        StorageBackendSelection, StorageV2AuthoritySnapshot, StorageV2Backend,
        StorageV2BackendInfo, StorageV2Future, StorageV2ObjectToken, StorageV2RecoveredObject,
    };
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly yielded"),
        }
    }

    fn input<'a>(
        tag: u8,
        evidence: &'a [[u8; C76_COMPONENT_EVIDENCE_LEN]; 3],
    ) -> C76GraphVersionInput<'a> {
        let _ = tag;
        C76GraphVersionInput {
            descriptor_bytes: &evidence[0][..4],
            component_artifact_bytes: [&evidence[0][..8], &evidence[1][..8], &evidence[2][..8]],
            component_evidence_bytes: [&evidence[0], &evidence[1], &evidence[2]],
            graph_evidence_bytes: &evidence[2],
        }
    }

    fn format_only() -> AuthoritySnapshot {
        let mut chain = authority::RecordChain::new(store_id());
        let records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let preflight = authority::preflight_recovery(&records, store_id()).unwrap();
        AuthoritySnapshot {
            formatted: true,
            checkpoint: preflight.chain_checkpoint().unwrap(),
            used_sectors: records.len(),
            preflight: Some(preflight),
            v2_objects: Some(alloc::sync::Arc::new(Vec::new())),
        }
    }

    struct C76TestBackend {
        boot_proved: AtomicBool,
        bind_retained: AtomicBool,
        corrupt_descriptor_token: AtomicBool,
        records: super::super::SpinLock<Vec<[u8; authority::RECORD_SIZE]>>,
        append_calls: AtomicUsize,
        readback_calls: AtomicUsize,
        revoke_calls: AtomicUsize,
    }

    impl C76TestBackend {
        fn formatted() -> Arc<Self> {
            let mut chain = authority::RecordChain::new(store_id());
            Arc::new(Self {
                boot_proved: AtomicBool::new(true),
                bind_retained: AtomicBool::new(false),
                corrupt_descriptor_token: AtomicBool::new(false),
                records: super::super::SpinLock::new(alloc::vec![chain
                    .append(None, authority::RecordBody::Format)
                    .unwrap()]),
                append_calls: AtomicUsize::new(0),
                readback_calls: AtomicUsize::new(0),
                revoke_calls: AtomicUsize::new(0),
            })
        }

        fn snapshot(&self) -> Result<StorageV2AuthoritySnapshot, StoreError> {
            let records = self.records.lock().clone();
            let preflight = authority::preflight_recovery(&records, store_id())
                .map_err(|_| StoreError::Corrupt)?;
            let current_object = preflight
                .slots()
                .iter()
                .find(|slot| slot.space == c76_space())
                .and_then(|slot| slot.live_derivation)
                .and_then(|derivation| {
                    preflight
                        .committed_grants()
                        .iter()
                        .find(|grant| grant.grant.derivation_id == derivation)
                })
                .and_then(|grant| {
                    preflight
                        .committed_objects()
                        .iter()
                        .find(|object| object.object_id == grant.grant.object_id)
                });
            let mut bindings = Vec::new();
            for object in preflight.committed_objects() {
                if Some(object.object_id) == current_object.map(|current| current.object_id)
                    || (self.bind_retained.load(Ordering::Acquire)
                        && c76_relevant_kind(object.object_kind))
                {
                    let mut bytes = object.bytes.clone();
                    if Some(object.object_id) == current_object.map(|current| current.object_id)
                        && self.corrupt_descriptor_token.load(Ordering::Acquire)
                    {
                        bytes[0] ^= 1;
                    }
                    bindings.push(StorageV2RecoveredObject::new(
                        object,
                        StorageV2ObjectToken::new(bytes),
                    ));
                }
            }
            StorageV2AuthoritySnapshot::new(
                records.len(),
                preflight,
                C76_STORAGE_V2_EXTERNAL_POLICY_SHA256,
                bindings,
            )
        }

        fn head(self: &Arc<Self>) -> StorageV2RecoveredAuthorityHead {
            let snapshot = self.snapshot().unwrap().into_facade().unwrap();
            let backend: Arc<dyn StorageV2Backend> = self.clone();
            StorageV2RecoveredAuthorityHead {
                journal: StorageV2OnlyAuthorityJournal {
                    backend,
                    checkpoint: snapshot.checkpoint,
                    external_root_policy_sha256: C76_STORAGE_V2_EXTERNAL_POLICY_SHA256,
                },
                snapshot,
            }
        }
    }

    impl StorageV2Backend for C76TestBackend {
        fn selection(&self) -> StorageBackendSelection {
            StorageBackendSelection::StorageV2
        }

        fn info(&self) -> StorageV2BackendInfo {
            StorageV2BackendInfo::default()
        }

        fn revoke_authority_boot_proof(&self) {
            self.revoke_calls.fetch_add(1, Ordering::AcqRel);
            self.boot_proved.store(false, Ordering::Release);
        }

        fn recover_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            Box::pin(async move {
                if !self.boot_proved.load(Ordering::Acquire) {
                    return Err(StoreError::Corrupt);
                }
                self.snapshot()
            })
        }

        fn readback_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            self.readback_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if !self.boot_proved.load(Ordering::Acquire) {
                    return Err(StoreError::Corrupt);
                }
                self.snapshot()
            })
        }

        fn append_authority<'a>(
            &'a self,
            expected: authority::ChainCheckpoint,
            records: &'a [[u8; authority::RECORD_SIZE]],
        ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
            self.append_authority_bound_to_policy(
                expected,
                C76_STORAGE_V2_EXTERNAL_POLICY_SHA256,
                records,
            )
        }

        fn append_authority_bound_to_policy<'a>(
            &'a self,
            expected: authority::ChainCheckpoint,
            policy: [u8; 32],
            records: &'a [[u8; authority::RECORD_SIZE]],
        ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
            self.append_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if !self.boot_proved.load(Ordering::Acquire)
                    || policy != C76_STORAGE_V2_EXTERNAL_POLICY_SHA256
                {
                    return Err(StoreError::Corrupt);
                }
                {
                    let mut media = self.records.lock();
                    let preflight = authority::preflight_recovery(&media, store_id())
                        .map_err(|_| StoreError::Corrupt)?;
                    if preflight.chain_checkpoint().ok() != Some(expected) {
                        return Err(StoreError::JournalChanged);
                    }
                    media.extend_from_slice(records);
                }
                self.snapshot()
            })
        }

        fn read_object<'a>(
            &'a self,
            object: &'a StorageV2ObjectToken,
        ) -> StorageV2Future<'a, Vec<u8>> {
            Box::pin(async move {
                object
                    .downcast_ref::<Vec<u8>>()
                    .cloned()
                    .ok_or(StoreError::ObjectUnavailable)
            })
        }
    }

    #[derive(Clone, Copy)]
    enum OptionalPartition {
        Persistent,
        Program,
    }

    /// Add policy-valid non-graph history directly to the physical test log.
    /// The bytes deliberately resemble boot-local execution state: C7.7 must
    /// exclude them by namespace shape, not by guessing at payload content.
    fn append_optional_partition_history(
        backend: &Arc<C76TestBackend>,
        partition: OptionalPartition,
        tombstone_root: bool,
        derived_child: bool,
    ) {
        let (space_raw, object_kind_raw, root_rights) = match partition {
            OptionalPartition::Persistent => (
                C74_PERSISTENT_SPACE_ID_RAW,
                C74_PERSISTENT_OBJECT_KIND_RAW,
                authority::DurableRights::READ
                    .union(authority::DurableRights::GRANT)
                    .union(authority::DurableRights::REVOKE),
            ),
            OptionalPartition::Program => (
                C74_PROGRAM_SPACE_ID_RAW,
                C74_PROGRAM_OBJECT_KIND_RAW,
                authority::DurableRights::READ,
            ),
        };
        assert!(
            !derived_child || matches!(partition, OptionalPartition::Persistent),
            "the fixed program root has no GRANT right"
        );

        let mut media = backend.records.lock();
        let preflight = authority::preflight_recovery(&media, store_id()).unwrap();
        let base = preflight.id_high_water().max(FIRST_ALLOCATABLE_ID);
        let exclusive_end = base
            .checked_add(7)
            .unwrap()
            .max(space_raw.checked_add(1).unwrap());
        let mut chain = authority::RecordChain::from_checkpoint(
            store_id(),
            preflight.chain_checkpoint().unwrap(),
        )
        .unwrap();
        let (high_water, next) = authority::preview_id_high_water(&chain, exclusive_end).unwrap();
        let mut records = high_water.records;
        chain = next;

        let object_id = authority::ObjectId::new(base.checked_add(1).unwrap()).unwrap();
        let (object, next) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(base).unwrap(),
            object_id,
            authority::ObjectKind::new(object_kind_raw).unwrap(),
            b"TaskId=41;arena=9;fuel=7;pending-call=1",
        )
        .unwrap();
        records.extend(object.records);
        chain = next;

        let root_derivation = authority::DerivationId::new(base.checked_add(3).unwrap()).unwrap();
        let (root, next) = authority::preview_grant_transaction(
            &chain,
            authority::TransactionId::new(base.checked_add(2).unwrap()).unwrap(),
            authority::GrantRecord {
                derivation_id: root_derivation,
                parent_id: None,
                object_id,
                target: authority::SlotIdentity {
                    space: authority::SpaceId::new(space_raw).unwrap(),
                    slot: 0,
                    generation: 0,
                },
                rights: root_rights,
                resource_kind: c76_resource_kind(),
                flags: authority::GrantFlags::ROOT,
            },
        )
        .unwrap();
        records.extend(root.records);
        chain = next;

        if derived_child {
            let (child, next) = authority::preview_grant_transaction(
                &chain,
                authority::TransactionId::new(base.checked_add(4).unwrap()).unwrap(),
                authority::GrantRecord {
                    derivation_id: authority::DerivationId::new(base.checked_add(5).unwrap())
                        .unwrap(),
                    parent_id: Some(root_derivation),
                    object_id,
                    target: authority::SlotIdentity {
                        space: authority::SpaceId::new(space_raw).unwrap(),
                        slot: 1,
                        generation: 0,
                    },
                    rights: authority::DurableRights::READ,
                    resource_kind: c76_resource_kind(),
                    flags: authority::GrantFlags::DERIVED,
                },
            )
            .unwrap();
            records.extend(child.records);
            chain = next;
        }

        if tombstone_root {
            let (revoke, _) = authority::preview_revoke_transaction(
                &chain,
                authority::TransactionId::new(base.checked_add(6).unwrap()).unwrap(),
                root_derivation,
            )
            .unwrap();
            records.extend(revoke.records);
        }
        media.extend(records);
    }

    fn append_numeric_high_water_prefix(backend: &Arc<C76TestBackend>) {
        let mut media = backend.records.lock();
        let preflight = authority::preflight_recovery(&media, store_id()).unwrap();
        let chain = authority::RecordChain::from_checkpoint(
            store_id(),
            preflight.chain_checkpoint().unwrap(),
        )
        .unwrap();
        let (high_water, _) = authority::preview_id_high_water(&chain, 1).unwrap();
        media.extend(high_water.records);
    }

    #[derive(Clone, Copy)]
    enum C77RecordMutation {
        WrongTombstoneTransaction,
        WrongInitialHighWater,
        OrphanInsteadOfSecondHighWater,
    }

    fn c77_mutated_two_version_records(
        evidence0: &[[u8; C76_COMPONENT_EVIDENCE_LEN]; 3],
        evidence1: &[[u8; C76_COMPONENT_EVIDENCE_LEN]; 3],
        mutation: C77RecordMutation,
    ) -> Vec<[u8; authority::RECORD_SIZE]> {
        let initial_base = FIRST_ALLOCATABLE_ID;
        let successor_base = checked_add(initial_base, C76_INITIAL_ID_COUNT)
            .unwrap()
            .max(checked_add(C76_GRAPH_SPACE_ID_RAW, 1).unwrap());
        let final_high_water = checked_add(successor_base, C76_SUCCESSOR_ID_COUNT).unwrap();
        let first_high_water = match mutation {
            C77RecordMutation::WrongInitialHighWater => checked_add(successor_base, 1).unwrap(),
            C77RecordMutation::OrphanInsteadOfSecondHighWater => final_high_water,
            C77RecordMutation::WrongTombstoneTransaction => successor_base,
        };

        let mut chain = authority::RecordChain::new(store_id());
        let mut records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let (high_water, next) =
            authority::preview_id_high_water(&chain, first_high_water).unwrap();
        records.extend(high_water.records);
        chain = next;

        let descriptor = append_version_objects(
            &mut chain,
            &mut records,
            initial_base,
            &input(0x81, evidence0),
        )
        .unwrap();
        let initial_derivation =
            c76_derivation(checked_add(initial_base, C76_INITIAL_ID_COUNT - 1).unwrap()).unwrap();
        let (initial_root, next) = authority::preview_grant_transaction(
            &chain,
            c76_transaction(
                checked_add(initial_base, C76_OBJECTS_PER_VERSION as u128 * 2).unwrap(),
            )
            .unwrap(),
            authority::GrantRecord {
                derivation_id: initial_derivation,
                parent_id: None,
                object_id: descriptor,
                target: authority::SlotIdentity {
                    space: c76_space(),
                    slot: 0,
                    generation: 0,
                },
                rights: authority::DurableRights::READ,
                resource_kind: c76_resource_kind(),
                flags: authority::GrantFlags::ROOT,
            },
        )
        .unwrap();
        records.extend(initial_root.records);
        chain = next;

        match mutation {
            C77RecordMutation::OrphanInsteadOfSecondHighWater => {
                let orphan_transaction =
                    authority::TransactionId::new(initial_base + C76_INITIAL_ID_COUNT).unwrap();
                let orphan_derivation =
                    authority::DerivationId::new(initial_base + C76_INITIAL_ID_COUNT + 1).unwrap();
                records.push(
                    chain
                        .append(
                            Some(orphan_transaction),
                            authority::RecordBody::GrantCommit {
                                prepare_sequence: 1,
                                prepare_crc32c: 0,
                                derivation_id: orphan_derivation,
                            },
                        )
                        .unwrap(),
                );
            }
            C77RecordMutation::WrongInitialHighWater
            | C77RecordMutation::WrongTombstoneTransaction => {
                let (high_water, next) =
                    authority::preview_id_high_water(&chain, final_high_water).unwrap();
                records.extend(high_water.records);
                chain = next;
            }
        }

        let descriptor = append_version_objects(
            &mut chain,
            &mut records,
            successor_base,
            &input(0x82, evidence1),
        )
        .unwrap();
        let tombstone_transaction = match mutation {
            C77RecordMutation::WrongTombstoneTransaction => {
                c76_transaction(initial_base + C76_INITIAL_ID_COUNT).unwrap()
            }
            C77RecordMutation::WrongInitialHighWater
            | C77RecordMutation::OrphanInsteadOfSecondHighWater => c76_transaction(
                checked_add(successor_base, C76_OBJECTS_PER_VERSION as u128 * 2).unwrap(),
            )
            .unwrap(),
        };
        let (tombstone, next) = authority::preview_revoke_transaction(
            &chain,
            tombstone_transaction,
            initial_derivation,
        )
        .unwrap();
        records.extend(tombstone.records);
        chain = next;
        let (successor_root, _) = authority::preview_grant_transaction(
            &chain,
            c76_transaction(
                checked_add(successor_base, C76_OBJECTS_PER_VERSION as u128 * 2 + 1).unwrap(),
            )
            .unwrap(),
            authority::GrantRecord {
                derivation_id: c76_derivation(
                    checked_add(successor_base, C76_SUCCESSOR_ID_COUNT - 1).unwrap(),
                )
                .unwrap(),
                parent_id: None,
                object_id: descriptor,
                target: authority::SlotIdentity {
                    space: c76_space(),
                    slot: 0,
                    generation: 1,
                },
                rights: authority::DurableRights::READ,
                resource_kind: c76_resource_kind(),
                flags: authority::GrantFlags::ROOT,
            },
        )
        .unwrap();
        records.extend(successor_root.records);
        records
    }

    fn install_two_version_graph(
        backend: &Arc<C76TestBackend>,
        evidence0: &[[u8; C76_COMPONENT_EVIDENCE_LEN]; 3],
        evidence1: &[[u8; C76_COMPONENT_EVIDENCE_LEN]; 3],
    ) {
        let vacant = match c76_recover_state(backend.head()).unwrap() {
            C76RecoveredState::Vacant(vacant) => vacant,
            C76RecoveredState::Existing(_) => panic!("fixture already has graph history"),
        };
        let pending = poll_ready(vacant.install_initial(input(0x10, evidence0))).unwrap();
        let g0 = match poll_ready(pending.recover_payload()).unwrap() {
            C76RecoveredGraphState::G0(graph) => graph,
            C76RecoveredGraphState::G1(_) => panic!("initial fixture recovered as G1"),
        };
        let pending = poll_ready(g0.replace(input(0x20, evidence1))).unwrap();
        assert!(matches!(
            poll_ready(pending.recover_payload()).unwrap(),
            C76RecoveredGraphState::G1(_)
        ));
    }

    fn append_snapshot(
        snapshot: AuthoritySnapshot,
        records: &[[u8; authority::RECORD_SIZE]],
    ) -> AuthoritySnapshot {
        let preflight = snapshot.preflight.unwrap();
        let checkpoint = preflight.chain_checkpoint().unwrap();
        let mut chain = authority::RecordChain::from_checkpoint(store_id(), checkpoint).unwrap();
        let mut all = Vec::new();
        all.push(
            authority::RecordChain::new(store_id())
                .append(None, authority::RecordBody::Format)
                .unwrap(),
        );
        // Decode/re-encode is unnecessary for the fixed format-only fixture:
        // all successors are already exact chain continuations.
        let _ = &mut chain;
        all.extend_from_slice(records);
        let preflight = authority::preflight_recovery(&all, store_id()).unwrap();
        AuthoritySnapshot {
            formatted: true,
            checkpoint: preflight.chain_checkpoint().unwrap(),
            used_sectors: all.len(),
            preflight: Some(preflight),
            v2_objects: Some(alloc::sync::Arc::new(Vec::new())),
        }
    }

    #[test]
    fn frozen_v3_policy_digest_matches_bytes() {
        assert_eq!(
            vibeos_blob_format::sha256(C76_STORAGE_V2_EXTERNAL_POLICY),
            C76_STORAGE_V2_EXTERNAL_POLICY_SHA256
        );
    }

    #[test]
    fn exact_g0_and_g1_layouts_and_every_logical_prefix_fail_closed() {
        let evidence0 = [[0x10; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x20; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let empty = format_only();
        let initial = c76_encode_initial_records(&empty, &input(0x10, &evidence0)).unwrap();
        let g0 = append_snapshot(empty, &initial);
        let history0 = c76_exact_history(&g0).unwrap().unwrap();
        assert_eq!(history0.versions.len(), 1);
        let selected = validate_c76_preflight_policy(g0.preflight.as_ref().unwrap()).unwrap();
        assert!(matches!(&selected, C76PreflightPolicyState::G0(_)));
        let selected_root = authority::RootPolicy {
            grant: history0.current().root.grant.clone(),
        };
        assert_eq!(
            selected
                .into_import_attachments_for_root(Some(&selected_root))
                .unwrap()
                .len(),
            7
        );
        assert!(
            validate_c76_preflight_policy(g0.preflight.as_ref().unwrap())
                .unwrap()
                .into_import_attachments_for_root(None)
                .is_err()
        );

        let successor =
            c76_encode_successor_records(g0.checkpoint, &history0, &input(0x20, &evidence1))
                .unwrap();

        let mut prefix_stream = Vec::new();
        prefix_stream.push(
            authority::RecordChain::new(store_id())
                .append(None, authority::RecordBody::Format)
                .unwrap(),
        );
        prefix_stream.extend_from_slice(&initial);
        for cut in 0..successor.len() {
            let mut records = prefix_stream.clone();
            records.extend_from_slice(&successor[..cut]);
            if let Ok(preflight) = authority::preflight_recovery(&records, store_id()) {
                let snapshot = AuthoritySnapshot {
                    formatted: true,
                    checkpoint: preflight.chain_checkpoint().unwrap(),
                    used_sectors: records.len(),
                    preflight: Some(preflight),
                    v2_objects: Some(alloc::sync::Arc::new(Vec::new())),
                };
                if cut == 0 {
                    assert_eq!(
                        c76_exact_history(&snapshot)
                            .unwrap()
                            .unwrap()
                            .versions
                            .len(),
                        1
                    );
                } else {
                    assert!(c76_exact_history(&snapshot).is_err());
                }
            }
        }

        let mut full = prefix_stream;
        full.extend_from_slice(&successor);
        let preflight = authority::preflight_recovery(&full, store_id()).unwrap();
        let snapshot = AuthoritySnapshot {
            formatted: true,
            checkpoint: preflight.chain_checkpoint().unwrap(),
            used_sectors: full.len(),
            preflight: Some(preflight),
            v2_objects: Some(alloc::sync::Arc::new(Vec::new())),
        };
        let history1 = c76_exact_history(&snapshot).unwrap().unwrap();
        assert_eq!(history1.versions.len(), 2);
        let selected = validate_c76_preflight_policy(snapshot.preflight.as_ref().unwrap()).unwrap();
        assert!(matches!(&selected, C76PreflightPolicyState::G1(_)));
        let selected_root = authority::RootPolicy {
            grant: history1.current().root.grant.clone(),
        };
        assert_eq!(
            selected
                .into_import_attachments_for_root(Some(&selected_root))
                .unwrap()
                .len(),
            14
        );
        assert!(c76_encode_successor_records(
            snapshot.checkpoint,
            &history1,
            &input(0x30, &evidence1)
        )
        .is_err());
    }

    #[test]
    fn preflight_policy_rejects_orphans_ssh_and_foreign_authority_closure() {
        let vacant = format_only();
        assert!(matches!(
            validate_c76_preflight_policy(vacant.preflight.as_ref().unwrap()).unwrap(),
            C76PreflightPolicyState::Vacant
        ));

        let preflight = vacant.preflight.as_ref().unwrap();
        let mut chain = authority::RecordChain::from_checkpoint(
            store_id(),
            preflight.chain_checkpoint().unwrap(),
        )
        .unwrap();
        let (high_water, next) = authority::preview_id_high_water(&chain, 4).unwrap();
        chain = next;
        let (orphan, _) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(2).unwrap(),
            authority::ObjectId::new(3).unwrap(),
            c76_graph_evidence_kind(),
            b"orphan",
        )
        .unwrap();
        let mut records = alloc::vec![authority::RecordChain::new(store_id())
            .append(None, authority::RecordBody::Format)
            .unwrap()];
        records.extend(high_water.records);
        records.extend(orphan.records);
        let orphan = authority::preflight_recovery(&records, store_id()).unwrap();
        assert_eq!(
            validate_c76_preflight_policy(&orphan).err(),
            Some(C76PreflightPolicyError::InvalidHistory)
        );

        for raw_kind in [0xdead_beef, 0x5353_4801] {
            let mut chain = authority::RecordChain::new(store_id());
            let format = chain.append(None, authority::RecordBody::Format).unwrap();
            let (high_water, next) = authority::preview_id_high_water(&chain, 4).unwrap();
            chain = next;
            let (foreign, _) = authority::preview_object_transaction(
                &chain,
                authority::TransactionId::new(2).unwrap(),
                authority::ObjectId::new(3).unwrap(),
                authority::ObjectKind::new(raw_kind).unwrap(),
                b"foreign",
            )
            .unwrap();
            let mut records = alloc::vec![format];
            records.extend(high_water.records);
            records.extend(foreign.records);
            let foreign = authority::preflight_recovery(&records, store_id()).unwrap();
            assert_eq!(
                validate_c76_preflight_policy(&foreign).err(),
                Some(C76PreflightPolicyError::InvalidHistory)
            );
        }

        let foreign_space = authority::SpaceId::new(0x6001).unwrap();
        let mut chain = authority::RecordChain::new(store_id());
        let format = chain.append(None, authority::RecordBody::Format).unwrap();
        let (high_water, next) = authority::preview_id_high_water(&chain, 0x6002).unwrap();
        chain = next;
        let (object, next) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(2).unwrap(),
            authority::ObjectId::new(3).unwrap(),
            authority::ObjectKind::new(0xdead_beef).unwrap(),
            b"foreign-root",
        )
        .unwrap();
        chain = next;
        let (grant, _) = authority::preview_grant_transaction(
            &chain,
            authority::TransactionId::new(4).unwrap(),
            authority::GrantRecord {
                derivation_id: authority::DerivationId::new(5).unwrap(),
                parent_id: None,
                object_id: authority::ObjectId::new(3).unwrap(),
                target: authority::SlotIdentity {
                    space: foreign_space,
                    slot: 0,
                    generation: 0,
                },
                rights: authority::DurableRights::READ,
                resource_kind: c76_resource_kind(),
                flags: authority::GrantFlags::ROOT,
            },
        )
        .unwrap();
        let mut records = alloc::vec![format];
        records.extend(high_water.records);
        records.extend(object.records);
        records.extend(grant.records);
        let foreign_authority = authority::preflight_recovery(&records, store_id()).unwrap();
        assert_eq!(
            validate_c76_preflight_policy(&foreign_authority).err(),
            Some(C76PreflightPolicyError::InvalidHistory)
        );
    }

    #[test]
    fn physical_typestate_releases_g0_then_exact_two_version_g1() {
        let evidence0 = [[0x10; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x20; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let backend = C76TestBackend::formatted();
        let vacant = match c76_recover_state(backend.head()).unwrap() {
            C76RecoveredState::Vacant(vacant) => vacant,
            C76RecoveredState::Existing(_) => panic!("fresh V3 media is not vacant"),
        };
        let pending = poll_ready(vacant.install_initial(input(0x10, &evidence0))).unwrap();
        let g0 = match poll_ready(pending.recover_payload()).unwrap() {
            C76RecoveredGraphState::G0(g0) => g0,
            C76RecoveredGraphState::G1(_) => panic!("initial install recovered as G1"),
        };
        assert_eq!(g0.current().descriptor_bytes(), &evidence0[0][..4]);
        assert_eq!(
            g0.current().component_evidence_bytes(2),
            Some(evidence0[2].as_slice())
        );

        let pending = poll_ready(g0.replace(input(0x20, &evidence1))).unwrap();
        let final_graph = match poll_ready(pending.recover_payload()).unwrap() {
            C76RecoveredGraphState::G1(graph) => graph,
            C76RecoveredGraphState::G0(_) => panic!("replacement recovered as G0"),
        };
        assert_eq!(
            final_graph.predecessor().descriptor_bytes(),
            &evidence0[0][..4]
        );
        assert_eq!(
            final_graph.successor().descriptor_bytes(),
            &evidence1[0][..4]
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 2);

        let existing = match c76_recover_state(backend.head()).unwrap() {
            C76RecoveredState::Existing(pending) => pending,
            C76RecoveredState::Vacant(_) => panic!("G1 media became vacant"),
        };
        assert!(matches!(
            poll_ready(existing.recover_payload()).unwrap(),
            C76RecoveredGraphState::G1(_)
        ));
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn c77_exact_final_g1_performs_one_readback_and_has_no_write_transition() {
        let evidence0 = [[0x71; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x72; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let backend = C76TestBackend::formatted();
        install_two_version_graph(&backend, &evidence0, &evidence1);

        let state = c76_recover_state(backend.head()).unwrap();
        let pending = c77_take_exact_final_g1(state).expect("exact graph-only G1");
        let readbacks_before = backend.readback_calls.load(Ordering::Acquire);
        let appends_before = backend.append_calls.load(Ordering::Acquire);
        let graph = poll_ready(c77_recover_exact_final_g1(pending)).unwrap();

        assert_eq!(graph.predecessor().descriptor_bytes(), &evidence0[0][..4]);
        assert_eq!(graph.successor().descriptor_bytes(), &evidence1[0][..4]);
        assert_eq!(
            backend.readback_calls.load(Ordering::Acquire),
            readbacks_before + 1
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), appends_before);
        assert!(!backend.boot_proved.load(Ordering::Acquire));
        assert!(backend.revoke_calls.load(Ordering::Acquire) >= 1);
    }

    #[test]
    fn c77_rejects_vacant_and_g0_before_physical_readback() {
        let vacant_backend = C76TestBackend::formatted();
        let vacant_state = c76_recover_state(vacant_backend.head()).unwrap();
        let readbacks_before = vacant_backend.readback_calls.load(Ordering::Acquire);
        assert!(matches!(
            c77_take_exact_final_g1(vacant_state),
            Err(C76StorageV2Error::ExistingGraphHistory)
        ));
        assert_eq!(
            vacant_backend.readback_calls.load(Ordering::Acquire),
            readbacks_before
        );
        assert!(!vacant_backend.boot_proved.load(Ordering::Acquire));

        let evidence = [[0x73; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let g0_backend = C76TestBackend::formatted();
        let vacant = match c76_recover_state(g0_backend.head()).unwrap() {
            C76RecoveredState::Vacant(vacant) => vacant,
            C76RecoveredState::Existing(_) => panic!("fresh media is not vacant"),
        };
        drop(poll_ready(vacant.install_initial(input(0x73, &evidence))).unwrap());
        let g0_state = c76_recover_state(g0_backend.head()).unwrap();
        let readbacks_before = g0_backend.readback_calls.load(Ordering::Acquire);
        assert!(matches!(
            c77_take_exact_final_g1(g0_state),
            Err(C76StorageV2Error::ExistingGraphHistory)
        ));
        assert_eq!(
            g0_backend.readback_calls.load(Ordering::Acquire),
            readbacks_before
        );
        assert!(!g0_backend.boot_proved.load(Ordering::Acquire));
    }

    #[test]
    fn c77_rejects_live_tombstoned_and_derived_optional_partition_history() {
        let cases = [
            (OptionalPartition::Persistent, false, false),
            (OptionalPartition::Program, false, false),
            (OptionalPartition::Persistent, true, false),
            (OptionalPartition::Program, true, false),
            (OptionalPartition::Persistent, false, true),
        ];
        for (partition, tombstone_root, derived_child) in cases {
            let evidence0 = [[0x74; C76_COMPONENT_EVIDENCE_LEN]; 3];
            let evidence1 = [[0x75; C76_COMPONENT_EVIDENCE_LEN]; 3];
            let backend = C76TestBackend::formatted();
            append_optional_partition_history(&backend, partition, tombstone_root, derived_child);
            install_two_version_graph(&backend, &evidence0, &evidence1);

            let head = backend.head();
            let expected_presence = if tombstone_root {
                (false, false, true)
            } else {
                match partition {
                    OptionalPartition::Persistent => (true, false, true),
                    OptionalPartition::Program => (false, true, true),
                }
            };
            assert_eq!(
                c76_root_presence(&head.snapshot).unwrap(),
                expected_presence
            );
            let history = c76_exact_history(&head.snapshot).unwrap().unwrap();
            assert_eq!(history.versions.len(), 2);
            assert!(!c76_exact_final_graph_only(&head.snapshot, &history).unwrap());

            let state = c76_recover_state(head).unwrap();
            let readbacks_before = backend.readback_calls.load(Ordering::Acquire);
            assert!(matches!(
                c77_take_exact_final_g1(state),
                Err(C76StorageV2Error::ExistingGraphHistory)
            ));
            assert_eq!(
                backend.readback_calls.load(Ordering::Acquire),
                readbacks_before
            );
            assert!(!backend.boot_proved.load(Ordering::Acquire));
        }
    }

    #[test]
    fn c77_rejects_numeric_high_water_only_prefix_history() {
        let evidence0 = [[0x78; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x79; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let backend = C76TestBackend::formatted();
        append_numeric_high_water_prefix(&backend);
        install_two_version_graph(&backend, &evidence0, &evidence1);

        let head = backend.head();
        let history = c76_exact_history(&head.snapshot).unwrap().unwrap();
        assert_eq!(history.versions.len(), 2);
        assert_eq!(
            head.snapshot
                .preflight
                .as_ref()
                .unwrap()
                .committed_objects()
                .len(),
            2 * C76_OBJECTS_PER_VERSION
        );
        assert!(!c76_exact_final_graph_only(&head.snapshot, &history).unwrap());

        let readbacks_before = backend.readback_calls.load(Ordering::Acquire);
        assert!(matches!(
            c77_take_exact_final_g1(c76_recover_state(head).unwrap()),
            Err(C76StorageV2Error::ExistingGraphHistory)
        ));
        assert_eq!(
            backend.readback_calls.load(Ordering::Acquire),
            readbacks_before
        );
        assert!(!backend.boot_proved.load(Ordering::Acquire));
    }

    #[test]
    fn c77_binds_both_high_water_events_and_the_exact_tombstone_transaction() {
        let evidence0 = [[0x7a; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x7b; C76_COMPONENT_EVIDENCE_LEN]; 3];
        for mutation in [
            C77RecordMutation::WrongTombstoneTransaction,
            C77RecordMutation::WrongInitialHighWater,
            C77RecordMutation::OrphanInsteadOfSecondHighWater,
        ] {
            let backend = C76TestBackend::formatted();
            *backend.records.lock() =
                c77_mutated_two_version_records(&evidence0, &evidence1, mutation);
            let head = backend.head();
            let history = c76_exact_history(&head.snapshot).unwrap().unwrap();
            assert_eq!(history.versions.len(), 2);
            assert!(!c76_exact_final_graph_only(&head.snapshot, &history).unwrap());

            let readbacks_before = backend.readback_calls.load(Ordering::Acquire);
            assert!(matches!(
                c77_take_exact_final_g1(c76_recover_state(head).unwrap()),
                Err(C76StorageV2Error::ExistingGraphHistory)
            ));
            assert_eq!(
                backend.readback_calls.load(Ordering::Acquire),
                readbacks_before
            );
            assert!(!backend.boot_proved.load(Ordering::Acquire));
        }
    }

    #[test]
    fn c77_second_gate_rejects_toctou_and_noncurrent_physical_bindings() {
        let evidence0 = [[0x76; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let evidence1 = [[0x77; C76_COMPONENT_EVIDENCE_LEN]; 3];

        let changed = C76TestBackend::formatted();
        install_two_version_graph(&changed, &evidence0, &evidence1);
        let pending = c77_take_exact_final_g1(c76_recover_state(changed.head()).unwrap()).unwrap();
        let appends_before = changed.append_calls.load(Ordering::Acquire);
        let readbacks_before = changed.readback_calls.load(Ordering::Acquire);
        append_optional_partition_history(&changed, OptionalPartition::Persistent, false, false);
        assert_eq!(
            poll_ready(c77_recover_exact_final_g1(pending)).err(),
            Some(StoreError::JournalChanged)
        );
        assert_eq!(
            changed.readback_calls.load(Ordering::Acquire),
            readbacks_before + 1
        );
        assert_eq!(changed.append_calls.load(Ordering::Acquire), appends_before);
        assert!(!changed.boot_proved.load(Ordering::Acquire));

        let bound_retained = C76TestBackend::formatted();
        install_two_version_graph(&bound_retained, &evidence0, &evidence1);
        let pending =
            c77_take_exact_final_g1(c76_recover_state(bound_retained.head()).unwrap()).unwrap();
        let readbacks_before = bound_retained.readback_calls.load(Ordering::Acquire);
        bound_retained.bind_retained.store(true, Ordering::Release);
        assert!(poll_ready(c77_recover_exact_final_g1(pending)).is_err());
        assert_eq!(
            bound_retained.readback_calls.load(Ordering::Acquire),
            readbacks_before + 1
        );
        assert!(!bound_retained.boot_proved.load(Ordering::Acquire));
    }

    #[test]
    fn physical_readback_rejects_retained_binding_and_descriptor_byte_mismatch() {
        let evidence = [[0x33; C76_COMPONENT_EVIDENCE_LEN]; 3];
        let backend = C76TestBackend::formatted();
        let vacant = match c76_recover_state(backend.head()).unwrap() {
            C76RecoveredState::Vacant(vacant) => vacant,
            C76RecoveredState::Existing(_) => panic!("fresh V3 media is not vacant"),
        };
        let pending = poll_ready(vacant.install_initial(input(0x33, &evidence))).unwrap();
        backend.bind_retained.store(true, Ordering::Release);
        assert!(poll_ready(pending.recover_payload()).is_err());
        assert!(!backend.boot_proved.load(Ordering::Acquire));

        backend.boot_proved.store(true, Ordering::Release);
        backend.bind_retained.store(false, Ordering::Release);
        let pending = match c76_recover_state(backend.head()).unwrap() {
            C76RecoveredState::Existing(pending) => pending,
            C76RecoveredState::Vacant(_) => panic!("G0 media became vacant"),
        };
        backend
            .corrupt_descriptor_token
            .store(true, Ordering::Release);
        assert!(poll_ready(pending.recover_payload()).is_err());
        assert!(!backend.boot_proved.load(Ordering::Acquire));
        assert!(backend.revoke_calls.load(Ordering::Acquire) >= 2);
    }
}
