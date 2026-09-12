//! Canonical persistent authority, object-binding, and quota-policy snapshot.
//!
//! The durable-format record stream remains the logical CSpace graph codec.
//! Storage V2 stores that stream together with a private stable-object to CAS
//! binding table and stable principal accounting policy as one immutable
//! authority payload.  Decoding this payload is inert: external root policy
//! must still authenticate `root_policy_sha256` before any live capability is
//! reconstructed.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_durable_format::{
    preflight_recovery, DecodeStatus, LogRecord, RecordBody, RecordChain, RecoveredStore,
    RootPolicy, StoreId, RECORD_SIZE,
};

use crate::quota::canonical_attributable_physical_bytes;
use crate::root_codec::{PersistentRootEntry, PERSISTENT_ROOT_ENTRY_LEN};

pub const PERSISTENT_AUTHORITY_SNAPSHOT_VERSION: u16 = 2;
const LEGACY_PERSISTENT_AUTHORITY_SNAPSHOT_VERSION: u16 = 1;
pub const PERSISTENT_AUTHORITY_HEADER_LEN: usize = 0x80;
pub const PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN: usize = 0x30;
pub const PERSISTENT_AUTHORITY_PRINCIPAL_LEN: usize = 0x40;
/// Upper bound on the encoded authority snapshot payload. Storage V2 large
/// objects are carried as M4 record streams inside this payload (one 1 MiB
/// object needs ~1.5 MiB of stream), and the authority extent chain may span
/// allocated segments, so this bounds the cumulative encoded object bytes a
/// store instance can admit. Mount memory limits bound the practical value.
pub const MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN: usize = 16_384 * 4096;
/// Upper bound on the number of logical M4 records an authority snapshot can
/// carry. The kernel's Storage V2 record-stream admission check uses this
/// instead of the M4 journal's physical sector count.
pub const MAX_PERSISTENT_AUTHORITY_RECORDS: usize = (MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
    - PERSISTENT_AUTHORITY_HEADER_LEN)
    / vibeos_durable_format::RECORD_SIZE;
pub const MAX_STABLE_PRINCIPALS: usize = 256;
pub const LEGACY_SYSTEM_PRINCIPAL: StablePrincipalId = StablePrincipalId(*b"VIBE-M4-SYSTEM!!");

const MAGIC: &[u8; 8] = b"VIBEAUT2";

/// Stable policy-owned principal key. This key is not object authority and
/// cannot be used to enumerate or read CAS objects.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StablePrincipalId([u8; 16]);

impl StablePrincipalId {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(Self(bytes))
        }
    }

    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentPrincipalPolicy {
    pub principal: StablePrincipalId,
    pub logical_limit_bytes: u64,
    pub physical_limit_bytes: u64,
    pub committed_logical_bytes: u64,
    pub committed_physical_bytes: u64,
    pub admission_revoked: bool,
}

/// Validated, inert input for the one-way M4-to-Storage-V2 authority cutover.
///
/// Construction performs the full M4 semantic recovery pass and applies the
/// caller's exact external root policy.  The recovered object identities and
/// bytes stay private; only [`crate::SegmentStore::import_persistent_authority`]
/// can bind them to fresh opaque V2 handles.
#[derive(Clone)]
pub struct PersistentAuthorityImport {
    pub(crate) root_policy_sha256: [u8; 32],
    pub(crate) record_stream: Vec<u8>,
    pub(crate) recovered: RecoveredStore,
    /// Objects which may receive a durable V2 binding and therefore be
    /// resolved through a recovered authority view.
    admitted_object_ids: BTreeSet<u128>,
    /// Exact inline policy evidence retained only in the logical checkpoint
    /// stream. These identities are deliberately disjoint from
    /// `admitted_object_ids`: no CAS binding, resolver entry, quota charge, or
    /// persistent object handle may be derived from them.
    retained_only_object_ids: BTreeSet<u128>,
    pub(crate) principals: Vec<PersistentPrincipalPolicy>,
    /// Content for external objects committed by this exact append, keyed by
    /// stable object id. Never populated by recovery: a re-install binds
    /// external objects to their already-durable blobs instead.
    pub(crate) external_payloads: BTreeMap<u128, Vec<u8>>,
}

impl fmt::Debug for PersistentAuthorityImport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentAuthorityImport")
            .field("root_policy_sha256", &self.root_policy_sha256)
            .field("record_bytes", &self.record_stream.len())
            .field(
                "materializable_object_count",
                &self.admitted_object_ids.len(),
            )
            .field(
                "retained_only_object_count",
                &self.retained_only_object_ids.len(),
            )
            .field("principal_count", &self.principals.len())
            .field("external_payload_count", &self.external_payloads.len())
            .finish_non_exhaustive()
    }
}

impl PersistentAuthorityImport {
    /// Validate a legacy journal, apply an exact externally supplied root set,
    /// and retain only canonical sealed records for the V2 checkpoint.
    pub fn from_m4(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
    ) -> Result<Self, AuthoritySnapshotError> {
        Self::from_m4_with_sealed_singletons(
            sectors,
            store_id,
            exact_roots,
            &[],
            canonical_external_root_policy,
            principals,
        )
    }

    /// Variant which additionally retains exactly the newest committed object
    /// for each trusted sealed singleton kind. These records are data selected
    /// by boot policy, not namespace roots, and therefore do not confer an
    /// ObjectId lookup capability.
    pub fn from_m4_with_sealed_singletons(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        sealed_singleton_kinds: &[vibeos_durable_format::ObjectKind],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
    ) -> Result<Self, AuthoritySnapshotError> {
        Self::from_m4_with_sealed_singletons_inner(
            sectors,
            store_id,
            exact_roots,
            sealed_singleton_kinds,
            &[],
            canonical_external_root_policy,
            principals,
            None,
        )
    }

    /// Compatibility variant accepting an already-computed preflight hint.
    /// The hint is never trusted as provenance: this constructor independently
    /// recovers the exact `sectors`/`store_id` which will enter the checkpoint.
    pub fn from_m4_with_sealed_singletons_preflighted(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        sealed_singleton_kinds: &[vibeos_durable_format::ObjectKind],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
        _preflight: vibeos_durable_format::RecoveryPreflight,
    ) -> Result<Self, AuthoritySnapshotError> {
        // `RecoveryPreflight` is a freely constructible public value and does
        // not carry an unforgeable association with `sectors`. Recompute from
        // the bytes which will actually enter the checkpoint before taking the
        // dense-stream fast path below. The caller value remains accepted only
        // for API compatibility; it is never provenance.
        let preflight = preflight_recovery(sectors, store_id)
            .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
        Self::from_m4_with_sealed_singletons_inner(
            sectors,
            store_id,
            exact_roots,
            sealed_singleton_kinds,
            &[],
            canonical_external_root_policy,
            principals,
            Some(preflight),
        )
    }

    /// Variant which durably retains validator-selected, exact inline
    /// attachments in addition to granted objects and sealed singletons.
    ///
    /// Attachments are comparison witnesses from the same already-computed
    /// preflight, not stable-ID lookup requests. Each supplied record must be
    /// byte-for-byte equal to the unique recovered record, must be inline,
    /// must not be named by any grant, and the slice must be strictly ordered
    /// by `ObjectId`. This is the narrow bridge used for root-relative
    /// evidence: policy code first proves the association, then Storage V2
    /// retains exactly that proof input without scanning by `ObjectKind`.
    /// Retention is checkpoint-only: attachments never enter the
    /// materializable binding set and cannot produce a persistent object
    /// handle.
    #[allow(clippy::too_many_arguments)]
    pub fn from_m4_with_exact_inline_attachments_preflighted(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        sealed_singleton_kinds: &[vibeos_durable_format::ObjectKind],
        exact_inline_attachments: &[vibeos_durable_format::RecoveredObject],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
        _preflight: vibeos_durable_format::RecoveryPreflight,
    ) -> Result<Self, AuthoritySnapshotError> {
        // Exact attachments must be compared with a recovery derived from the
        // same bytes which will be committed. Trusting an independently
        // supplied preflight here could pair one stream's retained-only set,
        // bindings, and quota accounting with another same-length stream.
        let preflight = preflight_recovery(sectors, store_id)
            .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
        Self::from_m4_with_sealed_singletons_inner(
            sectors,
            store_id,
            exact_roots,
            sealed_singleton_kinds,
            exact_inline_attachments,
            canonical_external_root_policy,
            principals,
            Some(preflight),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_m4_with_sealed_singletons_inner(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        sealed_singleton_kinds: &[vibeos_durable_format::ObjectKind],
        exact_inline_attachments: &[vibeos_durable_format::RecoveredObject],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
        preflight: Option<vibeos_durable_format::RecoveryPreflight>,
    ) -> Result<Self, AuthoritySnapshotError> {
        let record_bytes = sectors
            .len()
            .checked_mul(RECORD_SIZE)
            .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
        if record_bytes
            .checked_add(PERSISTENT_AUTHORITY_HEADER_LEN)
            .is_none_or(|len| len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN)
        {
            return Err(AuthoritySnapshotError::OutOfBounds);
        }
        validate_principals(&principals)?;
        let sector_bound_preflight = preflight.is_some();
        if !exact_inline_attachments.is_empty() {
            let exact_preflight = preflight
                .as_ref()
                .ok_or(AuthoritySnapshotError::InvalidAuthorityGraph)?;
            for attachment in exact_inline_attachments {
                if exact_preflight
                    .committed_grants()
                    .iter()
                    .any(|grant| grant.grant.object_id == attachment.object_id)
                    || exact_preflight
                        .committed_objects()
                        .iter()
                        .filter(|candidate| candidate.object_id == attachment.object_id)
                        .count()
                        != 1
                    || !exact_preflight
                        .committed_objects()
                        .iter()
                        .any(|candidate| candidate == attachment)
                {
                    return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
                }
            }
        }
        let recovered = match preflight {
            Some(preflight) => preflight.finish(exact_roots),
            None => preflight_recovery(sectors, store_id)
                .and_then(|preflight| preflight.finish(exact_roots)),
        }
        .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
        let mut previous_kind = None;
        let mut kinds = sealed_singleton_kinds.to_vec();
        kinds.sort_unstable();
        for kind in &kinds {
            if previous_kind == Some(*kind) {
                return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
            }
            previous_kind = Some(*kind);
        }
        let mut selected_ids = admitted_object_ids(&recovered);
        for kind in kinds {
            if let Some(selected) = recovered
                .objects
                .iter()
                .filter(|object| object.object_kind == kind)
                .max_by_key(|object| object.commit_sequence)
            {
                selected_ids.insert(selected.object_id.get());
            }
        }
        let mut retained_only_ids = BTreeSet::new();
        let mut previous_attachment = None;
        for attachment in exact_inline_attachments {
            let stable_id = attachment.object_id.get();
            if previous_attachment.is_some_and(|previous| previous >= stable_id)
                || attachment.is_external()
                || attachment.byte_len() != attachment.bytes.len() as u64
                || recovered
                    .grants
                    .iter()
                    .any(|grant| grant.grant.object_id == attachment.object_id)
                || recovered
                    .objects
                    .iter()
                    .filter(|candidate| candidate.object_id == attachment.object_id)
                    .count()
                    != 1
                || !recovered
                    .objects
                    .iter()
                    .any(|candidate| candidate == attachment)
                || selected_ids.contains(&stable_id)
                || !retained_only_ids.insert(stable_id)
            {
                return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
            }
            previous_attachment = Some(stable_id);
        }
        let mut record_stream = Vec::new();
        record_stream
            .try_reserve_exact(record_bytes)
            .map_err(|_| AuthoritySnapshotError::MemoryLimit)?;
        let dense_stream = recovered.last_sequence == sectors.len() as u64;
        if dense_stream {
            // Valid sequences are strictly dense (1..=n), so a stream whose
            // sector count equals its final sequence holds no empty or torn
            // sectors: the recovery pass above already decoded every one of
            // these exact records, and a second decode pass would only
            // re-prove that.
            for sector in sectors {
                record_stream.extend_from_slice(sector);
            }
        } else {
            for sector in sectors {
                match LogRecord::decode(sector)
                    .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?
                {
                    DecodeStatus::Valid(_) => record_stream.extend_from_slice(sector),
                    DecodeStatus::Empty | DecodeStatus::Torn => {}
                }
            }
        }
        let principals = if principals.is_empty() {
            vec![system_policy_for_objects(
                LEGACY_SYSTEM_PRINCIPAL,
                u64::MAX,
                u64::MAX,
                false,
                recovered
                    .objects
                    .iter()
                    .filter(|object| selected_ids.contains(&object.object_id.get())),
            )?]
        } else {
            principals
        };
        let mut result = Self {
            external_payloads: BTreeMap::new(),
            root_policy_sha256: root_policy_commitment(canonical_external_root_policy),
            record_stream,
            recovered,
            admitted_object_ids: selected_ids,
            retained_only_object_ids: retained_only_ids,
            principals,
        };
        // A `Some` preflight reaches this private helper only after the public
        // entry point freshly recovered these exact sectors. When the stream
        // bytes above are their verbatim copy, another full chain recovery
        // inside validation would only re-prove that same pass.
        validate_import(&mut result, !(sector_bound_preflight && dense_stream))?;
        Ok(result)
    }

    /// Construct the canonical authority graph for a newly formatted store.
    /// It contains only the mandatory M4 Format record and confers no roots.
    pub fn empty(
        store_id: StoreId,
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
    ) -> Result<Self, AuthoritySnapshotError> {
        let format = RecordChain::new(store_id)
            .append(None, RecordBody::Format)
            .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
        Self::from_m4(
            core::slice::from_ref(&format),
            store_id,
            &[],
            canonical_external_root_policy,
            principals,
        )
    }

    /// Install one fixed stable SYSTEM quota policy, deriving committed usage
    /// from the exact admitted object set. This is the canonical bridge for M4,
    /// whose journal predates persistent principal attribution.
    pub fn with_system_principal(
        mut self,
        principal: StablePrincipalId,
        logical_limit_bytes: u64,
        physical_limit_bytes: u64,
        admission_revoked: bool,
    ) -> Result<Self, AuthoritySnapshotError> {
        if self.principals.len() != 1 || self.principals[0].principal != LEGACY_SYSTEM_PRINCIPAL {
            return Err(AuthoritySnapshotError::InvalidField);
        }
        self.principals[0] = system_policy_for_objects(
            principal,
            logical_limit_bytes,
            physical_limit_bytes,
            admission_revoked,
            self.admitted_objects(),
        )?;
        validate_principals(&self.principals)?;
        Ok(self)
    }

    pub const fn root_policy_sha256(&self) -> [u8; 32] {
        self.root_policy_sha256
    }

    /// Canonical logical authority bytes which will be bound by the imported
    /// V2 checkpoint. Exposing this inert stream lets a boot initializer prove
    /// exact readback without exposing any private CAS object binding.
    pub fn record_stream(&self) -> &[u8] {
        &self.record_stream
    }

    pub fn admitted_object_count(&self) -> usize {
        self.admitted_object_ids.len()
    }

    /// Rebuild this validated import's logical stream for a boot-boundary
    /// compaction. The retained policy-object set is exactly the import's
    /// materializable records (live root objects and explicitly selected
    /// singletons), plus the distinct checkpoint-only exact attachments.
    /// Arbitrary ungranted objects are dropped. Stable IDs never leave this
    /// type and checkpoint-only attachments never become bindings.
    pub fn compact_boot_boundary_records(
        &self,
    ) -> Result<Vec<[u8; RECORD_SIZE]>, AuthoritySnapshotError> {
        let records: Vec<[u8; RECORD_SIZE]> = self
            .record_stream
            .chunks_exact(RECORD_SIZE)
            .map(|record| {
                record
                    .try_into()
                    .map_err(|_| AuthoritySnapshotError::InvalidRecord)
            })
            .collect::<Result<_, _>>()?;
        let preflight = preflight_recovery(&records, self.recovered.store_id)
            .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
        let mut exact: Vec<_> = preflight
            .committed_objects()
            .iter()
            .filter(|object| {
                let stable_id = object.object_id.get();
                self.admitted_object_ids.contains(&stable_id)
                    || self.retained_only_object_ids.contains(&stable_id)
            })
            .cloned()
            .collect();
        exact.sort_unstable_by_key(|object| object.object_id);
        if exact.len()
            != self
                .admitted_object_ids
                .len()
                .checked_add(self.retained_only_object_ids.len())
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?
            || preflight.committed_grants().iter().any(|grant| {
                self.retained_only_object_ids
                    .contains(&grant.grant.object_id.get())
            })
        {
            return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
        }
        preflight
            .compact_with_exact_policy_objects(&exact)
            .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)
    }

    /// Attach the content bytes for one external object committed by this
    /// exact append. The stream must have committed a matching external
    /// identity (declared length; the content root is proved by the blob
    /// writer at publication). Recovery re-installs never attach payloads.
    pub fn attach_external_payload(
        &mut self,
        stable_object_id: u128,
        bytes: Vec<u8>,
    ) -> Result<(), AuthoritySnapshotError> {
        let object = self
            .recovered
            .objects
            .iter()
            .find(|object| object.object_id.get() == stable_object_id)
            .ok_or(AuthoritySnapshotError::InvalidAuthorityGraph)?;
        if object.external_root.is_none() || object.byte_len() != bytes.len() as u64 {
            return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
        }
        self.external_payloads.insert(stable_object_id, bytes);
        Ok(())
    }

    pub fn principals(&self) -> &[PersistentPrincipalPolicy] {
        &self.principals
    }

    pub(crate) fn admitted_objects(
        &self,
    ) -> impl Iterator<Item = &vibeos_durable_format::RecoveredObject> {
        self.recovered
            .objects
            .iter()
            .filter(|object| self.admitted_object_ids.contains(&object.object_id.get()))
    }

    pub(crate) fn is_admitted(&self, stable_object_id: u128) -> bool {
        self.admitted_object_ids.contains(&stable_object_id)
    }

    pub(crate) fn is_retained_only(&self, stable_object_id: u128) -> bool {
        self.retained_only_object_ids.contains(&stable_object_id)
    }

    #[cfg(test)]
    pub(crate) fn test_set_object_admitted(&mut self, stable_object_id: u128, admitted: bool) {
        assert!(
            self.recovered
                .objects
                .iter()
                .any(|object| object.object_id.get() == stable_object_id),
            "test fixture may only select a recovered object"
        );
        if admitted {
            self.admitted_object_ids.insert(stable_object_id);
        } else {
            self.admitted_object_ids.remove(&stable_object_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn test_replace_admitted_object_bytes(
        &mut self,
        stable_object_id: u128,
        bytes: &[u8],
    ) {
        let object = self
            .recovered
            .objects
            .iter_mut()
            .find(|object| object.object_id.get() == stable_object_id)
            .expect("test fixture object must be recovered");
        assert!(self.admitted_object_ids.contains(&stable_object_id));
        assert_eq!(object.bytes.len(), bytes.len());
        object.bytes.copy_from_slice(bytes);
    }
}

/// Private durable binding. Stable M4 ObjectIds remain graph identities only;
/// the V2 object tuple is checked against the CAS catalog before recovery can
/// construct an opaque [`crate::PersistentObjectHandle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PersistentObjectBinding {
    pub(crate) stable_object_id: u128,
    pub(crate) v2_object_id: u128,
    pub(crate) commit_generation: u64,
    pub(crate) object_kind: u32,
}

/// An inert decoded authority snapshot. Object bindings deliberately have no
/// public accessor; only the store recovery bridge may turn them into handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentAuthoritySnapshot {
    checkpoint_generation: u64,
    root_policy_sha256: [u8; 32],
    record_stream: Vec<u8>,
    pub(crate) objects: Vec<PersistentObjectBinding>,
    principals: Vec<PersistentPrincipalPolicy>,
    external_roots: Vec<PersistentRootEntry>,
}

// Own the publication encoding until read-back finishes. Reuse its capacity
// for the installed log when possible, instead of allocating another log copy.
pub(crate) struct PreparedPublicationSnapshot<'a> {
    source: &'a PersistentAuthoritySnapshot,
    encoded: Vec<u8>,
    successor: PersistentAuthoritySnapshot,
    reuse_encoded: bool,
}

impl PreparedPublicationSnapshot<'_> {
    pub(crate) fn source(&self) -> &PersistentAuthoritySnapshot { self.source }
    pub(crate) fn encoded(&self) -> &Vec<u8> { &self.encoded }

    // All capacity was reserved before publication. Neither branch allocates.
    pub(crate) fn finish(self) -> PersistentAuthoritySnapshot {
        let Self { source, encoded, mut successor, reuse_encoded } = self;
        if reuse_encoded {
            successor.record_stream = encoded;
            successor.record_stream.clear();
        } else {
            drop(encoded);
        }
        successor.record_stream.extend_from_slice(source.record_stream());
        successor
    }
}

impl PersistentAuthoritySnapshot {
    pub(crate) fn prepare_publication(
        &self,
        encoded: Vec<u8>,
        maximum_workspace: usize,
    ) -> Result<PreparedPublicationSnapshot<'_>, AuthoritySnapshotError> {
        let mut successor = Self {
            checkpoint_generation: self.checkpoint_generation,
            root_policy_sha256: self.root_policy_sha256,
            record_stream: Vec::new(), objects: Vec::new(),
            principals: Vec::new(), external_roots: Vec::new(),
        };
        let mut used = 0;
        reserve_metadata(&mut successor.objects, self.objects.len(), &mut used, maximum_workspace)?;
        successor.objects.extend_from_slice(&self.objects);
        reserve_metadata(&mut successor.principals, self.principals.len(), &mut used, maximum_workspace)?;
        successor.principals.extend_from_slice(&self.principals);
        reserve_metadata(&mut successor.external_roots, self.external_roots.len(), &mut used, maximum_workspace)?;
        successor.external_roots.extend_from_slice(&self.external_roots);
        let reuse_encoded = encoded.capacity() >= self.record_stream.len();
        if !reuse_encoded {
            reserve_metadata(&mut successor.record_stream, self.record_stream.len(), &mut used, maximum_workspace)?;
        }
        Ok(PreparedPublicationSnapshot { source: self, encoded, successor, reuse_encoded })
    }

    pub(crate) fn new(
        checkpoint_generation: u64,
        root_policy_sha256: [u8; 32],
        record_stream: Vec<u8>,
        objects: Vec<PersistentObjectBinding>,
        principals: Vec<PersistentPrincipalPolicy>,
    ) -> Result<Self, AuthoritySnapshotError> {
        let value = Self {
            checkpoint_generation,
            root_policy_sha256,
            record_stream,
            objects,
            principals,
            external_roots: Vec::new(),
        };
        validate(&value, true)?;
        Ok(value)
    }

    /// Build a snapshot whose record stream is known to be validated because
    /// it was taken verbatim from a [`PersistentAuthorityImport`] or another
    /// validated snapshot. Their constructors preflight the stream. Every
    /// structural field check still runs; only the record-chain walk is skipped.
    pub(crate) fn from_validated_import_parts(
        checkpoint_generation: u64,
        root_policy_sha256: [u8; 32],
        record_stream: Vec<u8>,
        objects: Vec<PersistentObjectBinding>,
        principals: Vec<PersistentPrincipalPolicy>,
        external_roots: Vec<PersistentRootEntry>,
    ) -> Result<Self, AuthoritySnapshotError> {
        let value = Self {
            checkpoint_generation,
            root_policy_sha256,
            record_stream,
            objects,
            principals,
            external_roots,
        };
        validate(&value, false)?;
        Ok(value)
    }

    pub const fn checkpoint_generation(&self) -> u64 {
        self.checkpoint_generation
    }

    pub const fn root_policy_sha256(&self) -> [u8; 32] {
        self.root_policy_sha256
    }

    pub fn record_stream(&self) -> &[u8] {
        &self.record_stream
    }

    pub fn principals(&self) -> &[PersistentPrincipalPolicy] {
        &self.principals
    }

    /// Opaque roots owned by trusted services rather than the logical M4
    /// capability graph. They are deliberately crate-private: media identity
    /// is GC policy, never an object lookup interface.
    pub(crate) fn external_roots(&self) -> &[PersistentRootEntry] {
        &self.external_roots
    }

    pub(crate) fn with_external_roots(
        mut self,
        external_roots: Vec<PersistentRootEntry>,
    ) -> Result<Self, AuthoritySnapshotError> {
        self.external_roots = external_roots;
        validate(&self, true)?;
        Ok(self)
    }

    pub fn record_sectors(&self) -> impl ExactSizeIterator<Item = &[u8; RECORD_SIZE]> {
        self.record_stream
            .chunks_exact(RECORD_SIZE)
            .map(|bytes| bytes.try_into().expect("validated record stream alignment"))
    }

    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.record_stream
            .capacity()
            .checked_add(
                self.objects
                    .capacity()
                    .checked_mul(core::mem::size_of::<PersistentObjectBinding>())?,
            )?
            .checked_add(
                self.principals
                    .capacity()
                    .checked_mul(core::mem::size_of::<PersistentPrincipalPolicy>())?,
            )?
            .checked_add(
                self.external_roots
                    .capacity()
                    .checked_mul(core::mem::size_of::<PersistentRootEntry>())?,
            )
    }

    pub(crate) fn relocated(
        &self,
        checkpoint_generation: u64,
    ) -> Result<Self, AuthoritySnapshotError> {
        // The private record stream was validated on construction and is
        // cloned unchanged. Recheck structural fields against the new
        // generation without replaying the same authority graph twice.
        Self::from_validated_import_parts(
            checkpoint_generation,
            self.root_policy_sha256,
            self.record_stream.clone(),
            self.objects.clone(),
            self.principals.clone(),
            self.external_roots.clone(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoritySnapshotError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    InvalidAuthorityGraph,
    InvalidRecord,
    NonZeroReserved,
    MemoryLimit,
    OutOfBounds,
    PolicyMismatch,
    UnsortedOrDuplicate,
}

impl fmt::Display for AuthoritySnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArithmeticOverflow => "persistent authority arithmetic overflowed",
            Self::InvalidField => "persistent authority snapshot contains an invalid field",
            Self::InvalidLength => "persistent authority snapshot has a non-canonical length",
            Self::InvalidMagic => "persistent authority snapshot magic is invalid",
            Self::InvalidAuthorityGraph => {
                "persistent authority record stream or external roots are invalid"
            }
            Self::InvalidRecord => "persistent authority record stream is not canonical",
            Self::NonZeroReserved => "persistent authority reserved bytes are non-zero",
            Self::MemoryLimit => "persistent authority workspace allocation exceeds its allowance",
            Self::OutOfBounds => "persistent authority snapshot exceeds its fixed bound",
            Self::PolicyMismatch => "persistent authority external root policy does not match",
            Self::UnsortedOrDuplicate => {
                "persistent authority tables are not strictly sorted and unique"
            }
        })
    }
}

impl core::error::Error for AuthoritySnapshotError {}

pub fn root_policy_commitment(canonical_policy: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical_policy).into()
}

/// Exact frozen-format size; unlike encoding, this performs no allocation.
/// Checkpoint generation changes values, never the encoded table widths.
pub(crate) fn persistent_authority_encoded_len(
    value: &PersistentAuthoritySnapshot,
) -> Result<usize, AuthoritySnapshotError> {
    persistent_authority_encoded_len_for_parts(
        value.record_stream.len(), value.objects.len(), value.principals.len(),
        value.external_roots.len())
}

// Size a pending snapshot before its physical object bindings exist. Counts
// must describe the final tables; their values cannot change encoded widths.
pub(crate) fn persistent_authority_encoded_len_for_parts(
    record_bytes: usize,
    objects: usize,
    principals: usize,
    external_roots: usize,
) -> Result<usize, AuthoritySnapshotError> {
    let encoded_len = PERSISTENT_AUTHORITY_HEADER_LEN
        .checked_add(objects.checked_mul(PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN)
            .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?)
        .and_then(|bytes| principals.checked_mul(PERSISTENT_AUTHORITY_PRINCIPAL_LEN)
            .and_then(|more| bytes.checked_add(more)))
        .and_then(|bytes| bytes.checked_add(record_bytes))
        .and_then(|bytes| external_roots.checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
            .and_then(|more| bytes.checked_add(more)))
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if encoded_len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    Ok(encoded_len)
}

pub fn encode_persistent_authority_snapshot(
    value: &PersistentAuthoritySnapshot,
) -> Result<Vec<u8>, AuthoritySnapshotError> {
    encode_snapshot(value, true)
}

/// Hash the canonical snapshot without copying the validated record stream.
/// Metadata carries the full encoded lengths, exactly as the on-media encoder.
pub(crate) fn persistent_authority_snapshot_sha256(
    value: &PersistentAuthoritySnapshot,
) -> Result<[u8; 32], AuthoritySnapshotError> {
    let metadata = encode_snapshot(value, false)?;
    let mut hash = Sha256::new();
    hash.update(&metadata);
    hash.update(value.record_stream());
    Ok(hash.finalize().into())
}

/// Canonical metadata prefix for experimental delta encoding. The header still
/// describes the full snapshot; this prefix alone is not a decodable snapshot.
#[cfg(any(test, feature = "experimental-authority-delta"))]
pub(crate) fn encode_persistent_authority_metadata(
    value: &PersistentAuthoritySnapshot,
) -> Result<Vec<u8>, AuthoritySnapshotError> {
    encode_snapshot(value, false)
}

fn encode_snapshot(
    value: &PersistentAuthoritySnapshot,
    include_records: bool,
) -> Result<Vec<u8>, AuthoritySnapshotError> {
    encode_snapshot_bounded(value, include_records, usize::MAX).map(|(bytes, _)| bytes)
}

// Input snapshot storage belongs to the caller. Structural index scratch is
// dropped before output allocation; peak is the larger of those two phases.
pub(crate) fn encode_snapshot_bounded(
    value: &PersistentAuthoritySnapshot,
    include_records: bool,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, usize), AuthoritySnapshotError> {
    // Constructors validate the record chain; encoding rechecks structure only.
    let scratch_peak = validate_with_records_bounded(
        value, &value.record_stream, false, maximum_bytes,
    )?;
    let object_offset = PERSISTENT_AUTHORITY_HEADER_LEN;
    let principal_offset = object_offset
        .checked_add(
            value
                .objects
                .len()
                .checked_mul(PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let record_offset = principal_offset
        .checked_add(
            value
                .principals
                .len()
                .checked_mul(PERSISTENT_AUTHORITY_PRINCIPAL_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let external_root_offset = record_offset;
    let record_offset = external_root_offset
        .checked_add(
            value
                .external_roots
                .len()
                .checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let encoded_len = persistent_authority_encoded_len(value)?;
    let output_len = if include_records { encoded_len } else { record_offset };
    // Metadata has reserved fields that must stay zero. Record bytes are
    // already canonical and fill the suffix completely: reserve their space
    // now, but avoid zeroing it only to overwrite it during the final copy.
    let mut output = Vec::new();
    let mut output_bytes = 0;
    reserve_metadata(&mut output, output_len, &mut output_bytes, maximum_bytes)?;
    output.resize(record_offset, 0);
    output[..8].copy_from_slice(MAGIC);
    put_u16(&mut output, 0x08, PERSISTENT_AUTHORITY_SNAPSHOT_VERSION);
    put_u16(&mut output, 0x0a, PERSISTENT_AUTHORITY_HEADER_LEN as u16);
    put_u64(&mut output, 0x10, value.checkpoint_generation);
    output[0x18..0x38].copy_from_slice(&value.root_policy_sha256);
    put_u32(&mut output, 0x38, value.objects.len() as u32);
    put_u32(&mut output, 0x3c, value.principals.len() as u32);
    put_u32(
        &mut output,
        0x40,
        (value.record_stream.len() / RECORD_SIZE) as u32,
    );
    put_u32(
        &mut output,
        0x44,
        PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN as u32,
    );
    put_u32(&mut output, 0x48, PERSISTENT_AUTHORITY_PRINCIPAL_LEN as u32);
    put_u32(&mut output, 0x4c, RECORD_SIZE as u32);
    put_u64(&mut output, 0x50, object_offset as u64);
    put_u64(&mut output, 0x58, principal_offset as u64);
    put_u64(&mut output, 0x60, record_offset as u64);
    put_u64(&mut output, 0x68, encoded_len as u64);
    put_u32(&mut output, 0x70, value.external_roots.len() as u32);
    put_u32(&mut output, 0x74, PERSISTENT_ROOT_ENTRY_LEN as u32);
    put_u64(&mut output, 0x78, external_root_offset as u64);
    for (index, binding) in value.objects.iter().enumerate() {
        let offset = object_offset + index * PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN;
        put_u128(&mut output, offset, binding.stable_object_id);
        put_u128(&mut output, offset + 0x10, binding.v2_object_id);
        put_u64(&mut output, offset + 0x20, binding.commit_generation);
        put_u32(&mut output, offset + 0x28, binding.object_kind);
    }
    for (index, policy) in value.principals.iter().enumerate() {
        let offset = principal_offset + index * PERSISTENT_AUTHORITY_PRINCIPAL_LEN;
        output[offset..offset + 0x10].copy_from_slice(&policy.principal.0);
        put_u64(&mut output, offset + 0x10, policy.logical_limit_bytes);
        put_u64(&mut output, offset + 0x18, policy.physical_limit_bytes);
        put_u64(&mut output, offset + 0x20, policy.committed_logical_bytes);
        put_u64(&mut output, offset + 0x28, policy.committed_physical_bytes);
        output[offset + 0x30] = u8::from(policy.admission_revoked);
    }
    for (index, root) in value.external_roots.iter().enumerate() {
        let offset = external_root_offset + index * PERSISTENT_ROOT_ENTRY_LEN;
        put_u128(&mut output, offset, root.object_id);
        put_u64(&mut output, offset + 0x10, root.commit_generation);
        put_u32(&mut output, offset + 0x18, root.object_kind);
    }
    if include_records {
        output.extend_from_slice(&value.record_stream);
    }
    Ok((output, scratch_peak.max(output_bytes)))
}

pub fn decode_persistent_authority_snapshot(
    input: &[u8],
) -> Result<PersistentAuthoritySnapshot, AuthoritySnapshotError> {
    decode_snapshot(input, true, usize::MAX).map(|(snapshot, _)| snapshot)
}

/// Decode an owned snapshot within a requested workspace allowance. Input bytes
/// are owned by the caller and must be charged separately. Includes metadata,
/// semantic/index scratch and the final record-stream copy at their peak overlap.
pub(crate) fn decode_persistent_authority_snapshot_bounded(
    input: &[u8], maximum_bytes: usize,
) -> Result<(PersistentAuthoritySnapshot, usize), AuthoritySnapshotError> {
    decode_snapshot(input, true, maximum_bytes)
}

/// Validate canonical V2 bytes and their full authority graph without retaining
/// another copy of the record stream. Metadata tables remain decoder-owned.
#[cfg(any(test, feature = "experimental-authority-delta"))]
pub(crate) fn validate_canonical_authority_bytes(
    input: &[u8],
) -> Result<(u64, usize), AuthoritySnapshotError> {
    let validated = validate_authority_bytes(input)?;
    if get_u16(input, 0x08) != PERSISTENT_AUTHORITY_SNAPSHOT_VERSION {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    Ok(validated)
}

/// Validate any supported full snapshot, including legacy V1, without copying
/// its record stream. Only validated generation/offset escape this helper.
#[cfg(any(test, feature = "experimental-authority-delta"))]
pub(crate) fn validate_authority_bytes(
    input: &[u8],
) -> Result<(u64, usize), AuthoritySnapshotError> {
    let (decoded, _) = decode_snapshot(input, false, usize::MAX)?;
    Ok((decoded.checkpoint_generation(), get_u64(input, 0x60) as usize))
}

// Bound metadata plus the larger of semantic replay and temporary ID-index workspace.
#[cfg(any(test, feature = "experimental-authority-delta"))]
pub(crate) fn validate_authority_bytes_bounded(
    input: &[u8], budget: usize,
) -> Result<(u64, usize, usize), AuthoritySnapshotError> {
    let (decoded, peak) = decode_snapshot(input, false, budget)?;
    Ok((decoded.checkpoint_generation(), get_u64(input, 0x60) as usize, peak))
}

fn reserve_metadata<T>(table: &mut Vec<T>, count: usize, used: &mut usize, budget: usize)
    -> Result<(), AuthoritySnapshotError>
{
    let requested = count.checked_mul(core::mem::size_of::<T>())
        .and_then(|bytes| used.checked_add(bytes)).ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if requested > budget { return Err(AuthoritySnapshotError::MemoryLimit); }
    table.try_reserve_exact(count).map_err(|_| AuthoritySnapshotError::MemoryLimit)?;
    *used = table.capacity().checked_mul(core::mem::size_of::<T>())
        .and_then(|bytes| used.checked_add(bytes)).ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if *used > budget { return Err(AuthoritySnapshotError::MemoryLimit); }
    Ok(())
}

fn decode_snapshot(
    input: &[u8],
    retain_records: bool,
    metadata_budget: usize,
) -> Result<(PersistentAuthoritySnapshot, usize), AuthoritySnapshotError> {
    if input.len() < PERSISTENT_AUTHORITY_HEADER_LEN
        || input.len() > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN
    {
        return Err(AuthoritySnapshotError::InvalidLength);
    }
    if &input[..8] != MAGIC {
        return Err(AuthoritySnapshotError::InvalidMagic);
    }
    let version = get_u16(input, 0x08);
    if !matches!(
        version,
        LEGACY_PERSISTENT_AUTHORITY_SNAPSHOT_VERSION | PERSISTENT_AUTHORITY_SNAPSHOT_VERSION
    ) || get_u16(input, 0x0a) as usize != PERSISTENT_AUTHORITY_HEADER_LEN
        || get_u32(input, 0x44) as usize != PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN
        || get_u32(input, 0x48) as usize != PERSISTENT_AUTHORITY_PRINCIPAL_LEN
        || get_u32(input, 0x4c) as usize != RECORD_SIZE
        || get_u64(input, 0x68) != input.len() as u64
    {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    if !is_zero(&input[0x0c..0x10])
        || (version == LEGACY_PERSISTENT_AUTHORITY_SNAPSHOT_VERSION && !is_zero(&input[0x70..0x80]))
    {
        return Err(AuthoritySnapshotError::NonZeroReserved);
    }
    let object_count = get_u32(input, 0x38) as usize;
    let principal_count = get_u32(input, 0x3c) as usize;
    let record_count = get_u32(input, 0x40) as usize;
    let external_root_count = if version == PERSISTENT_AUTHORITY_SNAPSHOT_VERSION {
        get_u32(input, 0x70) as usize
    } else {
        0
    };
    if version == PERSISTENT_AUTHORITY_SNAPSHOT_VERSION
        && get_u32(input, 0x74) as usize != PERSISTENT_ROOT_ENTRY_LEN
    {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    if principal_count > MAX_STABLE_PRINCIPALS {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    let object_offset =
        usize::try_from(get_u64(input, 0x50)).map_err(|_| AuthoritySnapshotError::InvalidLength)?;
    let principal_offset =
        usize::try_from(get_u64(input, 0x58)).map_err(|_| AuthoritySnapshotError::InvalidLength)?;
    let record_offset =
        usize::try_from(get_u64(input, 0x60)).map_err(|_| AuthoritySnapshotError::InvalidLength)?;
    let expected_principal = object_offset
        .checked_add(
            object_count
                .checked_mul(PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let expected_external_root = expected_principal
        .checked_add(
            principal_count
                .checked_mul(PERSISTENT_AUTHORITY_PRINCIPAL_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let expected_record = expected_external_root
        .checked_add(
            external_root_count
                .checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let external_root_offset = if version == PERSISTENT_AUTHORITY_SNAPSHOT_VERSION {
        usize::try_from(get_u64(input, 0x78)).map_err(|_| AuthoritySnapshotError::InvalidLength)?
    } else {
        expected_external_root
    };
    let expected_len = expected_record
        .checked_add(
            record_count
                .checked_mul(RECORD_SIZE)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if object_offset != PERSISTENT_AUTHORITY_HEADER_LEN
        || principal_offset != expected_principal
        || external_root_offset != expected_external_root
        || record_offset != expected_record
        || expected_len != input.len()
    {
        return Err(AuthoritySnapshotError::InvalidLength);
    }
    // Reject the complete declared metadata footprint before any table allocation.
    let requested = object_count.checked_mul(core::mem::size_of::<PersistentObjectBinding>())
        .and_then(|bytes| principal_count.checked_mul(core::mem::size_of::<PersistentPrincipalPolicy>()).and_then(|n| bytes.checked_add(n)))
        .and_then(|bytes| external_root_count.checked_mul(core::mem::size_of::<PersistentRootEntry>()).and_then(|n| bytes.checked_add(n)))
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if requested > metadata_budget { return Err(AuthoritySnapshotError::MemoryLimit); }
    let mut metadata_used = 0;
    let mut objects = Vec::new();
    reserve_metadata(&mut objects, object_count, &mut metadata_used, metadata_budget)?;
    for index in 0..object_count {
        let offset = object_offset + index * PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN;
        if get_u32(input, offset + 0x2c) != 0 {
            return Err(AuthoritySnapshotError::NonZeroReserved);
        }
        objects.push(PersistentObjectBinding {
            stable_object_id: get_u128(input, offset),
            v2_object_id: get_u128(input, offset + 0x10),
            commit_generation: get_u64(input, offset + 0x20),
            object_kind: get_u32(input, offset + 0x28),
        });
    }
    let mut principals = Vec::new();
    reserve_metadata(&mut principals, principal_count, &mut metadata_used, metadata_budget)?;
    for index in 0..principal_count {
        let offset = principal_offset + index * PERSISTENT_AUTHORITY_PRINCIPAL_LEN;
        if input[offset + 0x30] > 1 || !is_zero(&input[offset + 0x31..offset + 0x40]) {
            return Err(AuthoritySnapshotError::NonZeroReserved);
        }
        let principal = StablePrincipalId::new(
            input[offset..offset + 0x10]
                .try_into()
                .expect("fixed principal field"),
        )
        .ok_or(AuthoritySnapshotError::InvalidField)?;
        principals.push(PersistentPrincipalPolicy {
            principal,
            logical_limit_bytes: get_u64(input, offset + 0x10),
            physical_limit_bytes: get_u64(input, offset + 0x18),
            committed_logical_bytes: get_u64(input, offset + 0x20),
            committed_physical_bytes: get_u64(input, offset + 0x28),
            admission_revoked: input[offset + 0x30] != 0,
        });
    }
    let mut external_roots = Vec::new();
    reserve_metadata(&mut external_roots, external_root_count, &mut metadata_used, metadata_budget)?;
    for index in 0..external_root_count {
        let offset = external_root_offset + index * PERSISTENT_ROOT_ENTRY_LEN;
        if get_u32(input, offset + 0x1c) != 0 {
            return Err(AuthoritySnapshotError::NonZeroReserved);
        }
        external_roots.push(PersistentRootEntry {
            object_id: get_u128(input, offset),
            commit_generation: get_u64(input, offset + 0x10),
            object_kind: get_u32(input, offset + 0x18),
        });
    }
    let mut snapshot = PersistentAuthoritySnapshot {
        checkpoint_generation: get_u64(input, 0x10),
        root_policy_sha256: input[0x18..0x38].try_into().expect("fixed policy digest"),
        record_stream: Vec::new(),
        objects,
        principals,
        external_roots,
    };
    let scratch_budget = metadata_budget.checked_sub(metadata_used)
        .ok_or(AuthoritySnapshotError::MemoryLimit)?;
    let scratch_peak = validate_with_records_bounded(&snapshot, &input[record_offset..], true, scratch_budget)?;
    let mut metadata_peak = metadata_used.checked_add(scratch_peak)
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if retain_records {
        reserve_metadata(&mut snapshot.record_stream, input.len() - record_offset,
            &mut metadata_used, metadata_budget)?;
        snapshot.record_stream.extend_from_slice(&input[record_offset..]);
        metadata_peak = metadata_peak.max(metadata_used);
    }
    Ok((snapshot, metadata_peak))
}

fn validate(
    value: &PersistentAuthoritySnapshot,
    check_record_chain: bool,
) -> Result<(), AuthoritySnapshotError> {
    validate_with_records(value, &value.record_stream, check_record_chain)
}

fn validate_with_records(
    value: &PersistentAuthoritySnapshot,
    records: &[u8],
    check_record_chain: bool,
) -> Result<(), AuthoritySnapshotError> {
    validate_with_records_bounded(value, records, check_record_chain, usize::MAX).map(|_| ())
}

fn validate_with_records_bounded(
    value: &PersistentAuthoritySnapshot,
    records: &[u8],
    check_record_chain: bool,
    scratch_budget: usize,
) -> Result<usize, AuthoritySnapshotError> {
    if value.checkpoint_generation == 0
        || value.root_policy_sha256 == [0; 32]
        || records.is_empty()
        || !records.len().is_multiple_of(RECORD_SIZE)
        || value.principals.len() > MAX_STABLE_PRINCIPALS
    {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    let semantic_peak = if check_record_chain {
        validate_record_chain_bounded(records, scratch_budget)?
    } else { 0 };
    let v2_object_ids = validate_binding_index(value, scratch_budget)?;
    validate_principals(&value.principals)?;
    let mut previous_external = None;
    for root in &value.external_roots {
        if root.object_id == 0
            || root.commit_generation == 0
            || root.commit_generation > value.checkpoint_generation
            || root.object_kind == 0
            || previous_external.is_some_and(|id| id >= root.object_id)
            || v2_object_ids.as_ref().map_or_else(
                || value.objects.binary_search_by_key(&root.object_id, |binding| binding.v2_object_id).is_ok(),
                |ids| ids.binary_search(&root.object_id).is_ok(),
            )
        {
            return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
        }
        previous_external = Some(root.object_id);
    }
    let encoded_len = persistent_authority_encoded_len(value)?
        .checked_sub(value.record_stream.len())
        .and_then(|n| n.checked_add(records.len()))
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if encoded_len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    let index_peak = v2_object_ids.as_ref().map_or(Ok(0), |ids|
        ids.capacity().checked_mul(core::mem::size_of::<u128>())
            .ok_or(AuthoritySnapshotError::ArithmeticOverflow))?;
    Ok(semantic_peak.max(index_peak))
}

// Most publications preserve V2 ID order as well as stable ID order. In that
// case the binding table itself is an index: no copied ID array or sort is
// necessary. A non-monotonic mapping remains valid and uses a sorted fallback.
fn validate_binding_index(
    value: &PersistentAuthoritySnapshot,
    budget: usize,
) -> Result<Option<Vec<u128>>, AuthoritySnapshotError> {
    let mut previous_stable = None;
    let mut previous_v2 = None;
    let mut ordered_v2 = true;
    for binding in &value.objects {
        if binding.stable_object_id == 0
            || binding.v2_object_id == 0
            || binding.commit_generation == 0
            || binding.commit_generation > value.checkpoint_generation
            || binding.object_kind == 0
            || previous_stable.is_some_and(|id| id >= binding.stable_object_id)
        {
            return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
        }
        previous_stable = Some(binding.stable_object_id);
        ordered_v2 &= previous_v2.is_none_or(|id| id < binding.v2_object_id);
        previous_v2 = Some(binding.v2_object_id);
    }
    if ordered_v2 { return Ok(None); }
    let mut ids = Vec::new();
    let mut used = 0;
    reserve_metadata(&mut ids, value.objects.len(), &mut used, budget)?;
    ids.extend(value.objects.iter().map(|binding| binding.v2_object_id));
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
    }
    Ok(Some(ids))
}

fn validate_record_chain(record_stream: &[u8]) -> Result<(), AuthoritySnapshotError> {
    validate_record_chain_bounded(record_stream, usize::MAX).map(|_| ())
}

fn validate_record_chain_bounded(record_stream: &[u8], budget: usize)
    -> Result<usize, AuthoritySnapshotError> {
    let (sectors, remainder) = record_stream.as_chunks::<RECORD_SIZE>();
    if !remainder.is_empty() { return Err(AuthoritySnapshotError::InvalidRecord); }
    let mut store_id = None;
    // Snapshot streams reject empty/torn records. Inspect without allocating
    // chunk content, preserving sealed-record errors before semantic errors.
    for sector in sectors {
        let Some((store, _)) = LogRecord::inspect_sector(sector)
            .map_err(|_| AuthoritySnapshotError::InvalidRecord)? else {
                return Err(AuthoritySnapshotError::InvalidRecord);
            };
        store_id.get_or_insert(store);
    }
    let store = store_id.ok_or(AuthoritySnapshotError::InvalidRecord)?;
    let map_error = |error| match error {
        vibeos_durable_format::RecoveryError::AllocationFailed => AuthoritySnapshotError::MemoryLimit,
        _ => AuthoritySnapshotError::InvalidAuthorityGraph,
    };
    let mut replay = vibeos_durable_format::PreflightValidator::with_memory_limit(store, budget);
    for batch in sectors.chunks(32) { replay.append(batch).map_err(map_error)?; }
    let (last_sequence, usage) = replay.finish_with_memory_usage().map_err(map_error)?;
    if last_sequence as usize != sectors.len() { return Err(AuthoritySnapshotError::InvalidRecord); }
    Ok(usage.peak_bytes)
}

fn validate_principals(
    principals: &[PersistentPrincipalPolicy],
) -> Result<(), AuthoritySnapshotError> {
    if principals.len() > MAX_STABLE_PRINCIPALS {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    let mut previous_principal = None;
    for policy in principals {
        if policy.logical_limit_bytes == 0
            || policy.physical_limit_bytes == 0
            || policy.committed_logical_bytes > policy.logical_limit_bytes
            || policy.committed_physical_bytes > policy.physical_limit_bytes
            || previous_principal.is_some_and(|id| id >= policy.principal)
        {
            return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
        }
        previous_principal = Some(policy.principal);
    }
    Ok(())
}

fn admitted_object_ids(recovered: &RecoveredStore) -> BTreeSet<u128> {
    recovered
        .grants
        .iter()
        .map(|grant| grant.grant.object_id.get())
        .collect()
}

fn system_policy_for_objects<'a>(
    principal: StablePrincipalId,
    logical_limit_bytes: u64,
    physical_limit_bytes: u64,
    admission_revoked: bool,
    mut objects: impl Iterator<Item = &'a vibeos_durable_format::RecoveredObject>,
) -> Result<PersistentPrincipalPolicy, AuthoritySnapshotError> {
    let totals = objects.try_fold((0_u64, 0_u64), |(logical, physical), object| {
        Some((
            logical.checked_add(object.byte_len())?,
            physical.checked_add(canonical_attributable_physical_bytes(object.byte_len()).ok()?)?,
        ))
    });
    let (committed_logical_bytes, committed_physical_bytes) =
        totals.ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    let policy = PersistentPrincipalPolicy {
        principal,
        logical_limit_bytes,
        physical_limit_bytes,
        committed_logical_bytes,
        committed_physical_bytes,
        admission_revoked,
    };
    validate_principals(core::slice::from_ref(&policy))?;
    Ok(policy)
}

fn validate_import(
    value: &mut PersistentAuthorityImport,
    check_record_chain: bool,
) -> Result<(), AuthoritySnapshotError> {
    if check_record_chain {
        validate_record_chain(&value.record_stream)?;
    }
    validate_principals(&value.principals)?;
    if value.root_policy_sha256 == [0; 32] {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    value
        .recovered
        .objects
        .sort_unstable_by_key(|object| object.object_id);
    if value
        .recovered
        .objects
        .windows(2)
        .any(|pair| pair[0].object_id >= pair[1].object_id)
    {
        return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
    }
    let grant_objects = admitted_object_ids(&value.recovered);
    if !grant_objects.is_subset(&value.admitted_object_ids)
        || !value
            .admitted_object_ids
            .is_disjoint(&value.retained_only_object_ids)
        || !value.admitted_object_ids.iter().all(|id| {
            value
                .recovered
                .objects
                .binary_search_by_key(id, |object| object.object_id.get())
                .is_ok()
        })
        || !value.retained_only_object_ids.iter().all(|id| {
            value
                .recovered
                .objects
                .binary_search_by_key(id, |object| object.object_id.get())
                .is_ok_and(|index| {
                    let object = &value.recovered.objects[index];
                    !object.is_external() && object.byte_len() == object.bytes.len() as u64
                })
        })
    {
        return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
    }
    Ok(())
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn put_u128(output: &mut [u8], offset: usize, value: u128) {
    output[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed field"))
}
fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed field"))
}
fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}
fn get_u128(input: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(input[offset..offset + 16].try_into().expect("fixed field"))
}
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_durable_format::{
        encode_object_transaction, ObjectId, ObjectKind, RecordBody, RecordChain, StoreId,
        TransactionId,
    };

    fn record_stream() -> Vec<u8> {
        RecordChain::new(StoreId::new(7).unwrap())
            .append(None, RecordBody::Format)
            .unwrap()
            .to_vec()
    }

    fn sample() -> PersistentAuthoritySnapshot {
        PersistentAuthoritySnapshot::new(
            9,
            root_policy_commitment(b"exact external roots v1"),
            record_stream(),
            vec![PersistentObjectBinding {
                stable_object_id: 3,
                v2_object_id: 1,
                commit_generation: 7,
                object_kind: 0x41,
            }],
            vec![PersistentPrincipalPolicy {
                principal: StablePrincipalId::new([1; 16]).unwrap(),
                logical_limit_bytes: 100,
                physical_limit_bytes: 200,
                committed_logical_bytes: 3,
                committed_physical_bytes: 70,
                admission_revoked: false,
            }],
        )
        .unwrap()
    }

    #[test]
    fn bounded_encoder_admits_output_and_releases_structural_scratch() {
        let mut value = sample();
        value.objects.push(PersistentObjectBinding {
            stable_object_id: 4, v2_object_id: 3, commit_generation: 7, object_kind: 0x41,
        });
        value.objects[0].v2_object_id = 3;
        value.objects[1].v2_object_id = 1;
        let scratch = value.objects.len() * core::mem::size_of::<u128>();
        for include_records in [false, true] {
            let expected = encode_snapshot(&value, include_records).unwrap();
            let output_bytes = expected.len();
            assert!(output_bytes > scratch);
            assert_eq!(encode_snapshot_bounded(&value, include_records, output_bytes - 1),
                Err(AuthoritySnapshotError::MemoryLimit));
            let (bytes, peak) = encode_snapshot_bounded(&value, include_records, output_bytes).unwrap();
            assert_eq!(bytes, expected);
            assert_eq!(peak, output_bytes, "scratch must be dropped before output allocation");
            assert_eq!(encode_snapshot_bounded(&value, include_records, scratch - 1),
                Err(AuthoritySnapshotError::MemoryLimit));
        }
        value.objects[1].v2_object_id = 3;
        assert_eq!(encode_snapshot_bounded(&value, true, usize::MAX),
            Err(AuthoritySnapshotError::UnsortedOrDuplicate));
    }

    #[test]
    fn bounded_record_replay_matches_whole_stream_across_transaction_boundaries() {
        let store = StoreId::new(7).unwrap();
        let mut chain = RecordChain::new(store);
        let mut records = vec![chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 32 }).unwrap()];
        records.extend(encode_object_transaction(&mut chain, TransactionId::new(3).unwrap(),
            ObjectId::new(4).unwrap(), ObjectKind::new(5).unwrap(), &vec![0x59; 32 * 1024]).unwrap().records);
        assert!(records.len() > 64);
        // Compare all complete-record prefixes, including incomplete object
        // transactions, against the original whole-stream semantic oracle.
        for len in 1..=records.len() {
            let bytes: Vec<u8> = records[..len].iter().flatten().copied().collect();
            let expected = preflight_recovery(&records[..len], store).is_ok();
            assert_eq!(validate_record_chain(&bytes).is_ok(), expected, "prefix {len}");
        }
        // A partial final record must be rejected rather than dropped by a
        // chunking API. Also exercise a borrowed slice starting one byte in.
        let complete: Vec<u8> = records.iter().flatten().copied().collect();
        let mut offset = vec![0xff];
        offset.extend_from_slice(&complete);
        assert!(validate_record_chain(&offset[1..]).is_ok());
        for tail in 1..RECORD_SIZE {
            assert!(validate_record_chain(&complete[..complete.len() - tail]).is_err());
        }
        for boundary in [32,64] {
            let mut bad = records.clone(); bad.swap(boundary-1, boundary);
            assert!(preflight_recovery(&bad, store).is_err());
            assert!(validate_record_chain(&bad.iter().flatten().copied().collect::<Vec<u8>>()).is_err());
            let mut bad = records.clone(); bad[boundary][0] ^= 1;
            assert!(validate_record_chain(&bad.iter().flatten().copied().collect::<Vec<u8>>()).is_err());
        }
    }

    #[test]
    fn relocated_snapshot_preserves_tables_and_checks_generation_constraints() {
        let original = sample().with_external_roots(vec![PersistentRootEntry {
            object_id: 42, commit_generation: 9, object_kind: 7,
        }]).unwrap();
        let moved = original.relocated(10).unwrap();
        let mut expected = encode_persistent_authority_snapshot(&original).unwrap();
        put_u64(&mut expected, 0x10, 10);
        assert_eq!(encode_persistent_authority_snapshot(&moved).unwrap(), expected);
        assert_eq!(decode_persistent_authority_snapshot(&expected).unwrap(), moved);
        assert!(original.relocated(0).is_err());
        // Both object bindings and external roots must remain valid at the
        // new generation; bypassing stream replay must not bypass these.
        assert!(original.relocated(8).is_err());
        assert!(sample().relocated(6).is_err());
        let mut bad_binding = original.clone();
        bad_binding.objects[0].object_kind = 0;
        assert!(bad_binding.relocated(10).is_err());
    }

    #[test]
    fn canonical_round_trip_and_reserved_corruption_fail_closed() {
        let sample = sample();
        let bytes = encode_persistent_authority_snapshot(&sample).unwrap();
        assert_eq!(persistent_authority_encoded_len(&sample).unwrap(), bytes.len());
        let relocated = sample.relocated(sample.checkpoint_generation + 1).unwrap();
        assert_eq!(persistent_authority_encoded_len(&relocated).unwrap(), bytes.len());
        assert_eq!(encode_persistent_authority_snapshot(&relocated).unwrap().len(), bytes.len());
        assert_eq!(&bytes[..8], b"VIBEAUT2");
        assert_eq!(
            decode_persistent_authority_snapshot(&bytes).unwrap(),
            sample
        );
        for offset in [0x0c, 0x80 + 0x2c, 0xb0 + 0x31] {
            let mut corrupt = bytes.clone();
            corrupt[offset] = 1;
            assert_eq!(
                decode_persistent_authority_snapshot(&corrupt),
                Err(AuthoritySnapshotError::NonZeroReserved)
            );
        }
    }

    #[test]
    fn publication_successor_reuses_encoding_and_prepares_short_buffer_fallback() {
        let value = sample().with_external_roots(vec![PersistentRootEntry {
            object_id: 17, commit_generation: 8, object_kind: 0x4653_0001,
        }]).unwrap();
        let table_bytes = value.objects.len() * core::mem::size_of::<PersistentObjectBinding>()
            + value.principals.len() * core::mem::size_of::<PersistentPrincipalPolicy>()
            + value.external_roots.len() * core::mem::size_of::<PersistentRootEntry>();
        let encoded = encode_persistent_authority_snapshot(&value).unwrap();
        let address = encoded.as_ptr();
        let capacity = encoded.capacity();
        assert!(matches!(value.prepare_publication(encoded.clone(), table_bytes - 1),
            Err(AuthoritySnapshotError::MemoryLimit)));
        let prepared = value.prepare_publication(encoded, table_bytes).unwrap();
        let successor = prepared.finish();
        assert_eq!(successor, value);
        assert_eq!(successor.record_stream.as_ptr(), address);
        assert_eq!(successor.record_stream.capacity(), capacity);
        // A short delta encoding cannot hold the complete log. Its extra
        // record capacity must be admitted now, not after durable publication.
        let required = table_bytes + value.record_stream.len();
        assert!(matches!(value.prepare_publication(vec![0; 16], required - 1),
            Err(AuthoritySnapshotError::MemoryLimit)));
        let prepared = value.prepare_publication(vec![0; 16], required).unwrap();
        let reserved = prepared.successor.record_stream.as_ptr();
        assert_eq!(prepared.successor.record_stream.capacity(), value.record_stream.len());
        let successor = prepared.finish();
        assert_eq!(successor, value);
        assert_eq!(successor.record_stream.as_ptr(), reserved);
    }

    #[test]
    fn streamed_snapshot_digest_matches_canonical_bytes_and_rejects_bad_metadata() {
        let base = sample();
        let rooted = base.clone().with_external_roots(vec![PersistentRootEntry {
            object_id: 17, commit_generation: 8, object_kind: 0x4653_0001,
        }]).unwrap();
        for value in [base.clone(), base.relocated(12).unwrap(), rooted] {
            let complete = encode_persistent_authority_snapshot(&value).unwrap();
            let expected: [u8; 32] = Sha256::digest(&complete).into();
            assert_eq!(persistent_authority_snapshot_sha256(&value).unwrap(), expected);
        }
        let mut invalid = base;
        invalid.objects.push(invalid.objects[0]);
        assert_eq!(persistent_authority_snapshot_sha256(&invalid).unwrap_err(),
            encode_persistent_authority_snapshot(&invalid).unwrap_err());
    }

    #[test]
    fn bounded_snapshot_combines_retained_metadata_and_semantic_peak() {
        let mut value = sample();
        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 128 }).unwrap()];
        sectors.extend(encode_object_transaction(&mut chain, TransactionId::new(9).unwrap(),
            ObjectId::new(10).unwrap(), ObjectKind::new(7).unwrap(), &[0x59; 4096]).unwrap().records);
        value.record_stream = sectors.iter().flatten().copied().collect();
        value.objects.push(PersistentObjectBinding {
            stable_object_id: 4, v2_object_id: 3, commit_generation: 7, object_kind: 0x41,
        });
        value.objects[0].v2_object_id = 3;
        value.objects[1].v2_object_id = 1;
        let bytes = encode_persistent_authority_snapshot(&value).unwrap();
        let metadata = value.objects.len() * core::mem::size_of::<PersistentObjectBinding>()
            + value.principals.len() * core::mem::size_of::<PersistentPrincipalPolicy>();
        let semantic = validate_record_chain_bounded(&value.record_stream, usize::MAX).unwrap();
        let scratch = value.objects.len() * core::mem::size_of::<u128>();
        let (_, offset, peak) = validate_authority_bytes_bounded(&bytes, usize::MAX).unwrap();
        assert_eq!(peak, metadata + semantic.max(scratch));
        assert!(semantic > scratch);
        assert_eq!(validate_authority_bytes_bounded(&bytes, metadata), Err(AuthoritySnapshotError::MemoryLimit));
        assert_eq!(validate_authority_bytes_bounded(&bytes, peak).unwrap().2, peak);
        let mut corrupt = bytes.clone();
        corrupt[offset + 3 * RECORD_SIZE + vibeos_durable_format::PAYLOAD_OFFSET + 24] ^= 1;
        // Strict sealed errors still precede semantic admission failure.
        assert_eq!(validate_authority_bytes_bounded(&corrupt, metadata), Err(AuthoritySnapshotError::InvalidRecord));
    }

    #[test]
    fn malformed_fixed_bound_is_distinct_from_workspace_exhaustion() {
        let mut bytes = encode_persistent_authority_snapshot(&sample()).unwrap();
        bytes[0x3c..0x40].copy_from_slice(&((MAX_STABLE_PRINCIPALS + 1) as u32).to_le_bytes());
        for budget in [0, usize::MAX] {
            assert_eq!(decode_persistent_authority_snapshot_bounded(&bytes, budget),
                Err(AuthoritySnapshotError::OutOfBounds));
        }
    }

    #[test]
    fn owned_decode_reserves_record_copy_and_reports_semantic_overlap() {
        let mut value = sample();
        let bytes = encode_persistent_authority_snapshot(&value).unwrap();
        let metadata = value.objects.len() * core::mem::size_of::<PersistentObjectBinding>()
            + value.principals.len() * core::mem::size_of::<PersistentPrincipalPolicy>();
        let retained = metadata + value.record_stream.len();
        assert_eq!(decode_persistent_authority_snapshot_bounded(&bytes, retained - 1),
            Err(AuthoritySnapshotError::MemoryLimit));
        let (decoded, peak) = decode_persistent_authority_snapshot_bounded(&bytes, retained).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(peak, retained);

        let mut chain = RecordChain::new(StoreId::new(7).unwrap());
        let records = [chain.append(None, RecordBody::Format).unwrap(),
            chain.append(None, RecordBody::IdHighWater { exclusive_end: 32 }).unwrap(),
            chain.append(Some(TransactionId::new(9).unwrap()), RecordBody::RevokeTombstone {
                derivation_id: vibeos_durable_format::DerivationId::new(10).unwrap(),
            }).unwrap()];
        value.record_stream = records.iter().flatten().copied().collect();
        let bytes = encode_persistent_authority_snapshot(&value).unwrap();
        let semantic = validate_record_chain_bounded(&value.record_stream, usize::MAX).unwrap();
        assert!(semantic > value.record_stream.len(), "retained record bytes are not a semantic upper bound");
        let (decoded, peak) = decode_persistent_authority_snapshot_bounded(&bytes, usize::MAX).unwrap();
        assert_eq!(peak, metadata + semantic);
        assert_eq!(decoded, value);
        let tight = metadata + value.record_stream.len();
        let (decoded, tight_peak) = decode_persistent_authority_snapshot_bounded(&bytes, tight).unwrap();
        assert_eq!(decoded, value);
        assert!(tight_peak <= tight);
        std::eprintln!("OWNED_AUTHORITY_BUDGET retained={tight} unconstrained_peak={peak} constrained_peak={tight_peak}");
    }

    #[test]
    fn metadata_budget_includes_unordered_id_index_overlap() {
        let mut value = sample();
        value.objects.push(PersistentObjectBinding {
            stable_object_id: 4, v2_object_id: 3, commit_generation: 7, object_kind: 0x41,
        });
        let ordered = encode_persistent_authority_snapshot(&value).unwrap();
        let (_, _, tables) = validate_authority_bytes_bounded(&ordered, usize::MAX).unwrap();
        assert!(validate_binding_index(&value, 0).unwrap().is_none());
        assert_eq!(validate_authority_bytes_bounded(&ordered, tables).unwrap().2, tables);

        value.objects[0].v2_object_id = 3;
        value.objects[1].v2_object_id = 1;
        let unordered = encode_persistent_authority_snapshot(&value).unwrap();
        let (_, _, peak) = validate_authority_bytes_bounded(&unordered, usize::MAX).unwrap();
        let scratch = value.objects.len() * core::mem::size_of::<u128>();
        assert_eq!(peak, tables + scratch);
        assert_eq!(validate_authority_bytes_bounded(&unordered, peak).unwrap().2, peak);
        for budget in [tables, peak - 1] {
            assert_eq!(validate_authority_bytes_bounded(&unordered, budget),
                Err(AuthoritySnapshotError::MemoryLimit));
        }
        // Duplicate detection still executes when admitted. A missing scratch
        // byte must be refused before allocating/populating the sorted index.
        value.objects[1].v2_object_id = 3;
        assert_eq!(validate_binding_index(&value, scratch - 1), Err(AuthoritySnapshotError::MemoryLimit));
        assert_eq!(validate_binding_index(&value, scratch), Err(AuthoritySnapshotError::UnsortedOrDuplicate));
    }

    #[test]
    fn metadata_budget_checks_all_tables_before_decode_and_exact_capacity() {
        let value = sample().with_external_roots(vec![PersistentRootEntry {
            object_id: 99, commit_generation: 1, object_kind: 3,
        }]).unwrap();
        let bytes = encode_persistent_authority_snapshot(&value).unwrap();
        let expected = value.objects.len() * core::mem::size_of::<PersistentObjectBinding>()
            + value.principals.len() * core::mem::size_of::<PersistentPrincipalPolicy>()
            + value.external_roots.len() * core::mem::size_of::<PersistentRootEntry>();
        let (generation, offset, allocated) = validate_authority_bytes_bounded(&bytes, expected).unwrap();
        assert_eq!(generation, value.checkpoint_generation());
        assert_eq!(allocated, expected);
        assert_eq!(&bytes[offset..], value.record_stream());
        assert_eq!(validate_authority_bytes_bounded(&bytes, expected - 1), Err(AuthoritySnapshotError::MemoryLimit));
        // With insufficient table space, fail before inspecting even the
        // first object's reserved field (and before semantic replay).
        let mut corrupt = bytes.clone();
        corrupt[PERSISTENT_AUTHORITY_HEADER_LEN + 0x2c] = 1;
        assert_eq!(validate_authority_bytes_bounded(&corrupt, expected - 1), Err(AuthoritySnapshotError::MemoryLimit));
        assert_eq!(validate_authority_bytes_bounded(&corrupt, expected), Err(AuthoritySnapshotError::NonZeroReserved));
    }

    #[test]
    fn external_roots_round_trip_without_becoming_authority_objects() {
        let sample = sample()
            .with_external_roots(vec![PersistentRootEntry {
                object_id: 17,
                commit_generation: 8,
                object_kind: 0x4653_0001,
            }])
            .unwrap();
        let bytes = encode_persistent_authority_snapshot(&sample).unwrap();
        assert_eq!(persistent_authority_encoded_len(&sample).unwrap(), bytes.len());
        let decoded = decode_persistent_authority_snapshot(&bytes).unwrap();
        assert_eq!(decoded, sample);
        assert_eq!(decoded.objects.len(), 1);
        assert_eq!(decoded.external_roots().len(), 1);

        let root_offset = get_u64(&bytes, 0x78) as usize;
        let mut corrupt = bytes;
        corrupt[root_offset + 0x1c] = 1;
        assert_eq!(
            decode_persistent_authority_snapshot(&corrupt),
            Err(AuthoritySnapshotError::NonZeroReserved)
        );
    }

    #[test]
    fn binding_index_fast_path_preserves_permutations_duplicates_and_root_collisions() {
        for first in 1..=3_u128 {
            for second in 1..=3_u128 {
                for third in 1..=3_u128 {
                    let ids = [first, second, third];
                    let unique = first != second && first != third && second != third;
                    let mut value = sample();
                    value.objects = ids.iter().enumerate().map(|(index, &id)| PersistentObjectBinding {
                        stable_object_id: 3 + index as u128, v2_object_id: id,
                        commit_generation: 7, object_kind: 0x41,
                    }).collect();
                    match validate_binding_index(&value, usize::MAX) {
                        Ok(index) => {
                            assert!(unique);
                            assert_eq!(index.is_none(), ids.windows(2).all(|pair| pair[0] < pair[1]));
                            if let Some(index) = index { assert_eq!(index, vec![1, 2, 3]); }
                        }
                        Err(error) => {
                            assert!(!unique);
                            assert_eq!(error, AuthoritySnapshotError::UnsortedOrDuplicate);
                        }
                    }
                    for root_id in 1..=4 {
                        value.external_roots = vec![PersistentRootEntry {
                            object_id: root_id, commit_generation: 7, object_kind: 0x41,
                        }];
                        let encoded = encode_persistent_authority_snapshot(&value);
                        if unique && !ids.contains(&root_id) {
                            assert_eq!(decode_persistent_authority_snapshot(&encoded.unwrap()).unwrap(), value);
                        } else {
                            assert_eq!(encoded, Err(AuthoritySnapshotError::UnsortedOrDuplicate));
                        }
                    }
                }
            }
        }
        let mut value = sample();
        value.objects.clear();
        assert_eq!(validate_binding_index(&value, usize::MAX).unwrap(), None);
    }

    #[test]
    fn torn_or_noncanonical_record_stream_is_rejected() {
        let mut bytes = encode_persistent_authority_snapshot(&sample()).unwrap();
        let record_offset = get_u64(&bytes, 0x60) as usize;
        bytes[record_offset + vibeos_durable_format::SEAL_OFFSET] ^= 1;
        assert_eq!(
            decode_persistent_authority_snapshot(&bytes),
            Err(AuthoritySnapshotError::InvalidRecord)
        );
    }

    #[test]
    fn tables_are_strictly_sorted_and_principal_usage_is_bounded() {
        let mut value = sample();
        value.objects.push(value.objects[0]);
        assert_eq!(
            encode_persistent_authority_snapshot(&value),
            Err(AuthoritySnapshotError::UnsortedOrDuplicate)
        );
        let mut value = sample();
        value.principals[0].committed_logical_bytes = 101;
        assert_eq!(
            encode_persistent_authority_snapshot(&value),
            Err(AuthoritySnapshotError::UnsortedOrDuplicate)
        );

        // Stable journal IDs define canonical table order. Independently
        // allocated V2 mappings may legitimately be non-monotonic (for
        // example when an older unrooted object receives a delayed grant),
        // but one V2 ObjectId may never back two stable objects.
        let mut value = sample();
        value.objects.push(PersistentObjectBinding {
            stable_object_id: 4,
            v2_object_id: value.objects[0].v2_object_id + 2,
            commit_generation: 8,
            object_kind: 0x41,
        });
        value.objects[0].v2_object_id += 4;
        assert!(encode_persistent_authority_snapshot(&value).is_ok());
        value.objects[1].v2_object_id = value.objects[0].v2_object_id;
        assert_eq!(
            encode_persistent_authority_snapshot(&value),
            Err(AuthoritySnapshotError::UnsortedOrDuplicate)
        );
    }

    #[test]
    fn sealed_singletons_select_only_latest_and_default_to_stable_system_quota() {
        let store = StoreId::new(71).unwrap();
        let kind = ObjectKind::new(0x5353_4801).unwrap();
        let mut chain = RecordChain::new(store);
        let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
        sectors.push(
            chain
                .append(None, RecordBody::IdHighWater { exclusive_end: 32 })
                .unwrap(),
        );
        sectors.extend(
            encode_object_transaction(
                &mut chain,
                TransactionId::new(3).unwrap(),
                ObjectId::new(4).unwrap(),
                kind,
                b"old ssh identity",
            )
            .unwrap()
            .records,
        );
        sectors.extend(
            encode_object_transaction(
                &mut chain,
                TransactionId::new(5).unwrap(),
                ObjectId::new(6).unwrap(),
                kind,
                b"new ssh identity",
            )
            .unwrap()
            .records,
        );

        let import = PersistentAuthorityImport::from_m4_with_sealed_singletons(
            &sectors,
            store,
            &[],
            &[kind],
            b"roots=[];sealed=[0x53534801]",
            Vec::new(),
        )
        .unwrap();
        assert_eq!(import.recovered.objects.len(), 2);
        let admitted: Vec<_> = import.admitted_objects().collect();
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].object_id.get(), 6);
        assert_eq!(admitted[0].bytes, b"new ssh identity");
        assert_eq!(import.principals.len(), 1);
        assert_eq!(import.principals[0].principal, LEGACY_SYSTEM_PRINCIPAL);
        assert_eq!(
            import.principals[0].committed_logical_bytes,
            b"new ssh identity".len() as u64
        );
        assert_eq!(
            import.principals[0].committed_physical_bytes,
            canonical_attributable_physical_bytes(b"new ssh identity".len() as u64).unwrap()
        );
    }

    #[test]
    fn exact_inline_attachments_are_preflight_records_not_kind_lookups() {
        let store = StoreId::new(73).unwrap();
        let kind = ObjectKind::new(0x434d_4531).unwrap();
        let mut chain = RecordChain::new(store);
        let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
        sectors.push(
            chain
                .append(None, RecordBody::IdHighWater { exclusive_end: 16 })
                .unwrap(),
        );
        for (transaction, object, bytes) in [
            (
                TransactionId::new(3).unwrap(),
                ObjectId::new(4).unwrap(),
                b"exact".as_slice(),
            ),
            (
                TransactionId::new(5).unwrap(),
                ObjectId::new(6).unwrap(),
                b"adjacent".as_slice(),
            ),
        ] {
            sectors.extend(
                encode_object_transaction(&mut chain, transaction, object, kind, bytes)
                    .unwrap()
                    .records,
            );
        }
        let preflight = preflight_recovery(&sectors, store).unwrap();
        let exact = preflight.committed_objects()[0].clone();
        let import = PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
            &sectors,
            store,
            &[],
            &[],
            core::slice::from_ref(&exact),
            b"roots=[];exact-attachment=root-relative",
            Vec::new(),
            preflight.clone(),
        )
        .unwrap();
        assert_eq!(import.admitted_object_count(), 0);
        assert!(import.admitted_objects().next().is_none());
        assert_eq!(import.retained_only_object_ids.len(), 1);
        assert!(import
            .retained_only_object_ids
            .contains(&exact.object_id.get()));
        // Debug is intentionally redacted: the public inert import must not
        // become a side channel for raw stable IDs or evidence bytes.
        let debug = alloc::format!("{import:?}");
        assert!(!debug.contains("exact"));
        assert!(!debug.contains("RecoveredObject"));

        // The two sets are a hard type invariant, not merely a convention at
        // the call site: checkpoint-only evidence can never also be selected
        // for a materializable binding.
        let mut conflated = import.clone();
        conflated.admitted_object_ids.insert(exact.object_id.get());
        assert_eq!(
            validate_import(&mut conflated, false).unwrap_err(),
            AuthoritySnapshotError::InvalidAuthorityGraph
        );
        let compacted = import.compact_boot_boundary_records().unwrap();
        let compacted = preflight_recovery(&compacted, store).unwrap();
        assert_eq!(compacted.committed_objects().len(), 1);
        assert_eq!(compacted.committed_objects()[0].object_id, exact.object_id);
        assert_eq!(compacted.committed_objects()[0].bytes, exact.bytes);

        // A same-ID caller value is only comparison evidence. Mutating any
        // recovered field cannot redirect admission to the canonical record.
        let mut substituted = exact.clone();
        substituted.bytes[0] ^= 1;
        assert_eq!(
            PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
                &sectors,
                store,
                &[],
                &[],
                &[substituted],
                b"roots=[];exact-attachment=root-relative",
                Vec::new(),
                preflight.clone(),
            )
            .unwrap_err(),
            AuthoritySnapshotError::InvalidAuthorityGraph
        );

        let later = preflight.committed_objects()[1].clone();
        assert_eq!(
            PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
                &sectors,
                store,
                &[],
                &[],
                &[later, exact.clone()],
                b"roots=[];exact-attachment=root-relative",
                Vec::new(),
                preflight.clone(),
            )
            .unwrap_err(),
            AuthoritySnapshotError::InvalidAuthorityGraph
        );

        let grant = vibeos_durable_format::GrantRecord {
            derivation_id: vibeos_durable_format::DerivationId::new(8).unwrap(),
            parent_id: None,
            object_id: exact.object_id,
            target: vibeos_durable_format::SlotIdentity {
                space: vibeos_durable_format::SpaceId::new(9).unwrap(),
                slot: 0,
                generation: 0,
            },
            rights: vibeos_durable_format::DurableRights::READ,
            resource_kind: vibeos_durable_format::ResourceKind::new(10).unwrap(),
            flags: vibeos_durable_format::GrantFlags::ROOT,
        };
        let (grant_records, next) = vibeos_durable_format::preview_grant_transaction(
            &chain,
            TransactionId::new(7).unwrap(),
            grant,
        )
        .unwrap();
        sectors.extend(grant_records.records);
        chain = next;
        let (revoke, _) = vibeos_durable_format::preview_revoke_transaction(
            &chain,
            TransactionId::new(11).unwrap(),
            vibeos_durable_format::DerivationId::new(8).unwrap(),
        )
        .unwrap();
        sectors.extend(revoke.records);
        let historical = preflight_recovery(&sectors, store).unwrap();
        let exact = historical
            .committed_objects()
            .iter()
            .find(|object| object.object_id == ObjectId::new(4).unwrap())
            .unwrap()
            .clone();
        assert_eq!(
            PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
                &sectors,
                store,
                &[],
                &[],
                &[exact],
                b"roots=[];exact-attachment=root-relative",
                Vec::new(),
                historical,
            )
            .unwrap_err(),
            AuthoritySnapshotError::InvalidAuthorityGraph
        );
    }

    #[test]
    fn public_preflighted_imports_rebind_to_the_exact_same_length_sector_stream() {
        fn stream(
            store: StoreId,
            first_transaction: u128,
            singleton_kind: ObjectKind,
            evidence_kind: ObjectKind,
            byte: u8,
        ) -> Vec<[u8; RECORD_SIZE]> {
            let mut chain = RecordChain::new(store);
            let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
            sectors.push(
                chain
                    .append(None, RecordBody::IdHighWater { exclusive_end: 32 })
                    .unwrap(),
            );
            sectors.extend(
                encode_object_transaction(
                    &mut chain,
                    TransactionId::new(first_transaction).unwrap(),
                    ObjectId::new(first_transaction + 1).unwrap(),
                    singleton_kind,
                    &[byte; 16],
                )
                .unwrap()
                .records,
            );
            sectors.extend(
                encode_object_transaction(
                    &mut chain,
                    TransactionId::new(first_transaction + 2).unwrap(),
                    ObjectId::new(first_transaction + 3).unwrap(),
                    evidence_kind,
                    &[byte; 112],
                )
                .unwrap()
                .records,
            );
            sectors
        }

        let store = StoreId::new(74).unwrap();
        let singleton_kind = ObjectKind::new(0x5353_4801).unwrap();
        let evidence_kind = ObjectKind::new(0x434d_4531).unwrap();
        let actual = stream(store, 3, singleton_kind, evidence_kind, 0xa5);
        let foreign = stream(store, 7, singleton_kind, evidence_kind, 0x5a);
        assert_eq!(actual.len(), foreign.len());

        let actual_preflight = preflight_recovery(&actual, store).unwrap();
        let foreign_preflight = preflight_recovery(&foreign, store).unwrap();
        let actual_singleton = actual_preflight
            .committed_objects()
            .iter()
            .find(|object| object.object_kind == singleton_kind)
            .unwrap();
        let actual_evidence = actual_preflight
            .committed_objects()
            .iter()
            .find(|object| object.object_kind == evidence_kind)
            .unwrap()
            .clone();
        let actual_stream: Vec<u8> = actual.iter().flatten().copied().collect();

        let singleton_import =
            PersistentAuthorityImport::from_m4_with_sealed_singletons_preflighted(
                &actual,
                store,
                &[],
                &[singleton_kind],
                b"roots=[];sealed=[ssh]",
                Vec::new(),
                foreign_preflight.clone(),
            )
            .unwrap();
        assert_eq!(singleton_import.record_stream(), actual_stream);
        assert_eq!(
            singleton_import.recovered.objects,
            actual_preflight.committed_objects()
        );
        let admitted: Vec<_> = singleton_import.admitted_objects().collect();
        assert_eq!(admitted, vec![actual_singleton]);
        assert!(!singleton_import.is_admitted(8));
        assert!(singleton_import.retained_only_object_ids.is_empty());
        assert_eq!(singleton_import.principals.len(), 1);
        assert_eq!(
            singleton_import.principals[0].committed_logical_bytes,
            actual_singleton.byte_len()
        );
        assert_eq!(
            singleton_import.principals[0].committed_physical_bytes,
            canonical_attributable_physical_bytes(actual_singleton.byte_len()).unwrap()
        );

        let attachment_import =
            PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
                &actual,
                store,
                &[],
                &[singleton_kind],
                core::slice::from_ref(&actual_evidence),
                b"roots=[];sealed=[ssh];exact-attachment=root-relative",
                Vec::new(),
                foreign_preflight,
            )
            .unwrap();
        assert_eq!(attachment_import.record_stream(), actual_stream);
        assert_eq!(
            attachment_import.recovered.objects,
            actual_preflight.committed_objects()
        );
        assert!(attachment_import.is_admitted(actual_singleton.object_id.get()));
        assert!(!attachment_import.is_admitted(8));
        assert_eq!(
            attachment_import.retained_only_object_ids,
            alloc::collections::BTreeSet::from([actual_evidence.object_id.get()])
        );
        assert!(!attachment_import.is_retained_only(10));
        assert_eq!(attachment_import.principals.len(), 1);
        assert_eq!(
            attachment_import.principals[0].committed_logical_bytes,
            actual_singleton.byte_len()
        );
        assert_eq!(
            attachment_import.principals[0].committed_physical_bytes,
            canonical_attributable_physical_bytes(actual_singleton.byte_len()).unwrap()
        );
    }

    #[test]
    fn sealed_singleton_policy_rejects_duplicates_but_allows_absence() {
        let store = StoreId::new(72).unwrap();
        let kind = ObjectKind::new(9).unwrap();
        let format = RecordChain::new(store)
            .append(None, RecordBody::Format)
            .unwrap();
        assert_eq!(
            PersistentAuthorityImport::from_m4_with_sealed_singletons(
                &[format],
                store,
                &[],
                &[kind, kind],
                b"duplicate",
                Vec::new(),
            )
            .unwrap_err(),
            AuthoritySnapshotError::UnsortedOrDuplicate
        );
        let absent = PersistentAuthorityImport::from_m4_with_sealed_singletons(
            &[format],
            store,
            &[],
            &[kind],
            b"allowed=[9]",
            Vec::new(),
        )
        .unwrap();
        assert_eq!(absent.admitted_object_count(), 0);
        assert_eq!(absent.principals[0].committed_logical_bytes, 0);
    }
}
