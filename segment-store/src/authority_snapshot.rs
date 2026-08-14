//! Canonical persistent authority, object-binding, and quota-policy snapshot.
//!
//! The durable-format record stream remains the logical CSpace graph codec.
//! Storage V2 stores that stream together with a private stable-object to CAS
//! binding table and stable principal accounting policy as one immutable
//! authority payload.  Decoding this payload is inert: external root policy
//! must still authenticate `root_policy_sha256` before any live capability is
//! reconstructed.

extern crate alloc;

use alloc::collections::BTreeSet;
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
pub const MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN: usize = 256 * 4096;
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
#[derive(Clone, Debug)]
pub struct PersistentAuthorityImport {
    pub(crate) root_policy_sha256: [u8; 32],
    pub(crate) record_stream: Vec<u8>,
    pub(crate) recovered: RecoveredStore,
    admitted_object_ids: BTreeSet<u128>,
    pub(crate) principals: Vec<PersistentPrincipalPolicy>,
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
            canonical_external_root_policy,
            principals,
            None,
        )
    }

    /// Variant reusing an already-computed preflight of the exact same
    /// `sectors`/`store_id`, avoiding one full stream re-validation.
    pub fn from_m4_with_sealed_singletons_preflighted(
        sectors: &[[u8; RECORD_SIZE]],
        store_id: StoreId,
        exact_roots: &[RootPolicy],
        sealed_singleton_kinds: &[vibeos_durable_format::ObjectKind],
        canonical_external_root_policy: &[u8],
        principals: Vec<PersistentPrincipalPolicy>,
        preflight: vibeos_durable_format::RecoveryPreflight,
    ) -> Result<Self, AuthoritySnapshotError> {
        Self::from_m4_with_sealed_singletons_inner(
            sectors,
            store_id,
            exact_roots,
            sealed_singleton_kinds,
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
        let mut record_stream = Vec::new();
        record_stream
            .try_reserve_exact(record_bytes)
            .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
        for sector in sectors {
            match LogRecord::decode(sector)
                .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?
            {
                DecodeStatus::Valid(_) => record_stream.extend_from_slice(sector),
                DecodeStatus::Empty | DecodeStatus::Torn => {}
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
            root_policy_sha256: root_policy_commitment(canonical_external_root_policy),
            record_stream,
            recovered,
            admitted_object_ids: selected_ids,
            principals,
        };
        validate_import(&mut result)?;
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

impl PersistentAuthoritySnapshot {
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
    /// it was taken verbatim from a [`PersistentAuthorityImport`], whose only
    /// constructors preflight the stream. Every structural field check still
    /// runs; only the per-record chain walk is skipped.
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
        Self::new(
            checkpoint_generation,
            self.root_policy_sha256,
            self.record_stream.clone(),
            self.objects.clone(),
            self.principals.clone(),
        )?
        .with_external_roots(self.external_roots.clone())
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

pub fn encode_persistent_authority_snapshot(
    value: &PersistentAuthoritySnapshot,
) -> Result<Vec<u8>, AuthoritySnapshotError> {
    // Every constructor validated the snapshot, including its record chain;
    // re-run only the cheap structural checks before encoding.
    validate(value, false)?;
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
    let encoded_len = record_offset
        .checked_add(value.record_stream.len())
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if encoded_len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    let mut output = vec![0; encoded_len];
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
    output[record_offset..].copy_from_slice(&value.record_stream);
    Ok(output)
}

pub fn decode_persistent_authority_snapshot(
    input: &[u8],
) -> Result<PersistentAuthoritySnapshot, AuthoritySnapshotError> {
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
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(object_count)
        .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
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
    principals
        .try_reserve_exact(principal_count)
        .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
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
    external_roots
        .try_reserve_exact(external_root_count)
        .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
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
    let record_stream = input[record_offset..].to_vec();
    let snapshot = PersistentAuthoritySnapshot {
        checkpoint_generation: get_u64(input, 0x10),
        root_policy_sha256: input[0x18..0x38].try_into().expect("fixed policy digest"),
        record_stream,
        objects,
        principals,
        external_roots,
    };
    validate(&snapshot, true)?;
    Ok(snapshot)
}

fn validate(
    value: &PersistentAuthoritySnapshot,
    check_record_chain: bool,
) -> Result<(), AuthoritySnapshotError> {
    if value.checkpoint_generation == 0
        || value.root_policy_sha256 == [0; 32]
        || value.record_stream.is_empty()
        || !value.record_stream.len().is_multiple_of(RECORD_SIZE)
        || value.principals.len() > MAX_STABLE_PRINCIPALS
    {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    if check_record_chain {
        validate_record_chain(&value.record_stream)?;
    }
    let mut previous_stable = None;
    let mut v2_object_ids = Vec::new();
    v2_object_ids
        .try_reserve_exact(value.objects.len())
        .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
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
        v2_object_ids.push(binding.v2_object_id);
    }
    v2_object_ids.sort_unstable();
    if v2_object_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
    }
    validate_principals(&value.principals)?;
    let mut previous_external = None;
    for root in &value.external_roots {
        if root.object_id == 0
            || root.commit_generation == 0
            || root.commit_generation > value.checkpoint_generation
            || root.object_kind == 0
            || previous_external.is_some_and(|id| id >= root.object_id)
            || v2_object_ids.binary_search(&root.object_id).is_ok()
        {
            return Err(AuthoritySnapshotError::UnsortedOrDuplicate);
        }
        previous_external = Some(root.object_id);
    }
    let encoded_len = PERSISTENT_AUTHORITY_HEADER_LEN
        .checked_add(
            value
                .objects
                .len()
                .checked_mul(PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN)
                .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?,
        )
        .and_then(|bytes| {
            value
                .principals
                .len()
                .checked_mul(PERSISTENT_AUTHORITY_PRINCIPAL_LEN)
                .and_then(|more| bytes.checked_add(more))
        })
        .and_then(|bytes| bytes.checked_add(value.record_stream.len()))
        .and_then(|bytes| {
            value
                .external_roots
                .len()
                .checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(AuthoritySnapshotError::ArithmeticOverflow)?;
    if encoded_len > MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN {
        return Err(AuthoritySnapshotError::OutOfBounds);
    }
    Ok(())
}

fn validate_record_chain(record_stream: &[u8]) -> Result<(), AuthoritySnapshotError> {
    let record_count = record_stream.len() / RECORD_SIZE;
    let mut sectors = Vec::new();
    sectors
        .try_reserve_exact(record_count)
        .map_err(|_| AuthoritySnapshotError::OutOfBounds)?;
    let mut store_id = None;
    for bytes in record_stream.chunks_exact(RECORD_SIZE) {
        let sector: [u8; RECORD_SIZE] = bytes.try_into().expect("exact record chunk");
        let decoded = match LogRecord::decode(&sector) {
            Ok(DecodeStatus::Valid(decoded)) => decoded,
            _ => return Err(AuthoritySnapshotError::InvalidRecord),
        };
        store_id.get_or_insert(decoded.record.store_id);
        sectors.push(sector);
    }
    let store_id = store_id.ok_or(AuthoritySnapshotError::InvalidRecord)?;
    let preflight = preflight_recovery(&sectors, store_id)
        .map_err(|_| AuthoritySnapshotError::InvalidAuthorityGraph)?;
    if preflight.last_sequence() as usize != sectors.len() {
        return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
    }
    Ok(())
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
            logical.checked_add(object.bytes.len() as u64)?,
            physical.checked_add(
                canonical_attributable_physical_bytes(object.bytes.len() as u64).ok()?,
            )?,
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

fn validate_import(value: &mut PersistentAuthorityImport) -> Result<(), AuthoritySnapshotError> {
    validate_record_chain(&value.record_stream)?;
    validate_principals(&value.principals)?;
    if value.root_policy_sha256 == [0; 32] {
        return Err(AuthoritySnapshotError::InvalidField);
    }
    let grant_objects = admitted_object_ids(&value.recovered);
    if !grant_objects.is_subset(&value.admitted_object_ids)
        || !value.admitted_object_ids.iter().all(|id| {
            value
                .recovered
                .objects
                .iter()
                .any(|object| object.object_id.get() == *id)
        })
    {
        return Err(AuthoritySnapshotError::InvalidAuthorityGraph);
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
    fn canonical_round_trip_and_reserved_corruption_fail_closed() {
        let sample = sample();
        let bytes = encode_persistent_authority_snapshot(&sample).unwrap();
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
    fn external_roots_round_trip_without_becoming_authority_objects() {
        let sample = sample()
            .with_external_roots(vec![PersistentRootEntry {
                object_id: 17,
                commit_generation: 8,
                object_kind: 0x4653_0001,
            }])
            .unwrap();
        let bytes = encode_persistent_authority_snapshot(&sample).unwrap();
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
