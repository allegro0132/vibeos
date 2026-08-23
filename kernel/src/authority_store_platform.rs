//! Kernel CSpace publication and fault-recovery adapter for authority-store.
//!
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
use vibeos_durable_format as durable;
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, RecoveredGrant, RecoveredSlot,
    RecoveredStore, RootConstraint, RootPolicy, RootPolicyPartition, RootRightsConstraint,
    SlotIdentity, StoreId, TransactionId,
};
use vibeos_object_store as object_codec;
use vibeos_program_store as program_model;

use crate::saved_program::{SavedProgramService, TrustedProgram};
use crate::store::{AuthorityJournal, AuthoritySnapshot, StoreError, StoredObject};
use crate::world::Space;
use crate::{block_device, exec, heap, sync::SpinLock};

pub(crate) use vibeos_authority_store::persistent_space_id;
use vibeos_authority_store::{
    persistent_object_kind, stored_object_resource_kind, CHILD_RIGHTS, CHILD_SLOT,
    GRANDCHILD_RIGHTS, GRANDCHILD_SLOT, MARKER, PERSISTENT_SPACE_ID_RAW, ROOT_RIGHTS, ROOT_SLOT,
};
pub use vibeos_authority_store::{
    DurableCSpaceError, DurableCSpaceInfo, DurableCSpaceState, PersistentTestPhase,
    PersistentTestReport,
};

const STORAGE_V2_EXTERNAL_POLICY_V1: &[u8] = b"vibeos.storage-v2.external-policy.v1\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0sealed-singleton-optional=0x53534801";
const STORAGE_V2_EXTERNAL_POLICY_V2: &[u8] = b"vibeos.storage-v2.external-policy.v2\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0component-space=0x564942454f532d434f4d504f4e454e54,slot=0,generation=0,rights=r,kind=0x434d5031\0component-evidence=exact-root-relative,kind=0x434d4531,len=112,inline=1,ungranted=1\0sealed-singleton-optional=0x53534801";
const SSH_CONFIG_OBJECT_KIND_RAW: u32 = 0x5353_4801;
const COMPONENT_ARTIFACT_SPACE_ID_RAW: u128 = 0x5649_4245_4f53_2d43_4f4d_504f_4e45_4e54;
const COMPONENT_ARTIFACT_OBJECT_KIND_RAW: u32 = 0x434d_5031;
const COMPONENT_OPERATOR_EVIDENCE_OBJECT_KIND_RAW: u32 = 0x434d_4531;
const M4_STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageV2ExternalPolicy {
    LegacyV1,
    ComponentV2,
}

impl StorageV2ExternalPolicy {
    const fn canonical(self) -> &'static [u8] {
        match self {
            Self::LegacyV1 => STORAGE_V2_EXTERNAL_POLICY_V1,
            Self::ComponentV2 => STORAGE_V2_EXTERNAL_POLICY_V2,
        }
    }

    fn commitment(self) -> [u8; 32] {
        vibeos_segment_store::root_policy_commitment(self.canonical())
    }

    fn from_commitment(commitment: [u8; 32]) -> Option<Self> {
        if commitment == Self::LegacyV1.commitment() {
            Some(Self::LegacyV1)
        } else if commitment == Self::ComponentV2.commitment() {
            Some(Self::ComponentV2)
        } else {
            None
        }
    }
}

const fn active_storage_v2_external_policy() -> StorageV2ExternalPolicy {
    #[cfg(feature = "component-durable-publication")]
    {
        StorageV2ExternalPolicy::ComponentV2
    }
    #[cfg(not(feature = "component-durable-publication"))]
    {
        StorageV2ExternalPolicy::LegacyV1
    }
}

pub(crate) fn storage_v2_external_policy_sha256() -> [u8; 32] {
    active_storage_v2_external_policy().commitment()
}

pub(crate) fn storage_v2_component_external_policy_sha256() -> [u8; 32] {
    StorageV2ExternalPolicy::ComponentV2.commitment()
}

pub(crate) fn storage_v2_legacy_external_policy_sha256() -> [u8; 32] {
    StorageV2ExternalPolicy::LegacyV1.commitment()
}

pub(crate) fn storage_v2_recovery_policy_is_recognized(commitment: [u8; 32]) -> bool {
    if commitment == storage_v2_external_policy_sha256() {
        return true;
    }
    #[cfg(feature = "component-durable-publication")]
    {
        commitment == storage_v2_legacy_external_policy_sha256()
    }
    #[cfg(not(feature = "component-durable-publication"))]
    {
        false
    }
}

/// Construct the sole native-empty authority snapshot. It is deliberately the
/// same one-record M4 logical format accepted by migration, with no roots,
/// objects, or optional sealed singletons, and is bound to the compiled
/// external policy before it can reach V2 media.
pub(crate) fn storage_v2_empty_import(
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    vibeos_segment_store::PersistentAuthorityImport::empty(
        store_id,
        active_storage_v2_external_policy().canonical(),
        Vec::new(),
    )
    .map_err(|_| DurableCSpaceError::RootPolicy)
}

/// Recognize only the post-import residue produced by native empty
/// provisioning. This is intentionally stricter than generic V2 validity:
/// UUID, logical stream, policy digest, zero object bindings, and the complete
/// principal policy must all equal the canonical constructor.
pub(crate) fn is_storage_v2_native_empty_view(
    view: &vibeos_segment_store::PersistentAuthorityView,
    expected: &vibeos_segment_store::PersistentAuthorityImport,
) -> bool {
    view.store_uuid() == *b"VIBEOS-STOR-V2!!"
        && view.checkpoint_generation() == 2
        && view.root_policy_sha256() == expected.root_policy_sha256()
        && view.record_stream() == expected.record_stream()
        && view.objects().is_empty()
        && view.principal_policies() == expected.principals()
        && view.principals().len() == expected.principals().len()
}

fn validate_storage_v2_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    policy: StorageV2ExternalPolicy,
) -> Result<durable::RecoveryPreflight, DurableCSpaceError> {
    // The V2 logical stream is not constrained by the M4 journal's physical
    // 512-sector log; its envelope is the persistent authority snapshot
    // payload, which admits multi-MiB large objects.
    if records.is_empty() || records.len() > vibeos_segment_store::MAX_PERSISTENT_AUTHORITY_RECORDS
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    let preflight = durable::preflight_recovery(records, store_id)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    // This is the complete production validator: exact external roots, fixed
    // CSpace history, typed resource witnesses, and saved-program semantics.
    let snapshot = AuthoritySnapshot::from_legacy_preflight(records.len(), preflight.clone())?;
    let _validated = authorize_snapshot_with_policy(snapshot, policy)?;
    Ok(preflight)
}

/// Revalidate a V2 authority payload under the compiled production policy.
/// The on-media policy digest is only a commitment; it cannot replace this
/// semantic pass before boot publishes Storage V2 as the selected backend.
pub(crate) fn validate_storage_v2_record_stream(
    record_stream: &[u8],
) -> Result<(), DurableCSpaceError> {
    storage_v2_recovery_import(record_stream).map(|_| ())
}

pub(crate) fn validate_storage_v2_record_stream_for_policy(
    record_stream: &[u8],
    policy_sha256: [u8; 32],
) -> Result<(), DurableCSpaceError> {
    storage_v2_recovery_import_for_policy(record_stream, policy_sha256).map(|_| ())
}

/// Reconstruct the exact inert authority import selected by the kernel's
/// compiled external policy. Cold Storage V2 recovery uses this value to prove
/// that every private stable-object binding names the logical record bytes,
/// rather than trusting the on-media policy digest or object metadata alone.
pub(crate) fn storage_v2_recovery_import(
    record_stream: &[u8],
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    storage_v2_recovery_import_for_policy(record_stream, storage_v2_external_policy_sha256())
}

/// Reconstruct an inert import under exactly the policy committed by the
/// recovered V2 checkpoint. v1 and v2 are separate semantic profiles; an
/// unknown digest is never interpreted as the active build's policy.
pub(crate) fn storage_v2_recovery_import_for_policy(
    record_stream: &[u8],
    policy_sha256: [u8; 32],
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let policy = StorageV2ExternalPolicy::from_commitment(policy_sha256)
        .ok_or(DurableCSpaceError::RootPolicy)?;
    if record_stream.is_empty()
        || !record_stream
            .len()
            .is_multiple_of(vibeos_durable_format::RECORD_SIZE)
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let record_count = record_stream.len() / vibeos_durable_format::RECORD_SIZE;
    if record_count > vibeos_segment_store::MAX_PERSISTENT_AUTHORITY_RECORDS {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    for record in record_stream.chunks_exact(vibeos_durable_format::RECORD_SIZE) {
        records.push(
            record
                .try_into()
                .map_err(|_| DurableCSpaceError::RootPolicy)?,
        );
    }
    storage_v2_import_exact_policy(&records, policy)
}

#[cfg(any(test, feature = "legacy-shell"))]
mod storage_v2_policy_tests {
    use super::*;

    fn record_stream(records: &[[u8; durable::RECORD_SIZE]]) -> Vec<u8> {
        records.iter().flatten().copied().collect()
    }

    #[cfg_attr(test, test)]
    pub(crate) fn v2_stream_policy_rejects_semantic_extra_root_with_canonical_records() {
        let store_id = StoreId::new(M4_STORE_ID_RAW).unwrap();
        let mut chain = durable::RecordChain::new(store_id);
        let mut records = vec![chain.append(None, durable::RecordBody::Format).unwrap()];
        records.push(
            chain
                .append(None, durable::RecordBody::IdHighWater { exclusive_end: 5 })
                .unwrap(),
        );
        let object_id = durable::ObjectId::new(2).unwrap();
        records.extend(
            durable::encode_object_transaction(
                &mut chain,
                durable::TransactionId::new(1).unwrap(),
                object_id,
                durable::ObjectKind::new(0x7f00_0001).unwrap(),
                b"semantically outside the production root policy",
            )
            .unwrap()
            .records,
        );
        let grant = durable::GrantRecord {
            derivation_id: durable::DerivationId::new(4).unwrap(),
            parent_id: None,
            object_id,
            target: durable::SlotIdentity {
                space: durable::SpaceId::new(0x7f00_0002).unwrap(),
                slot: 0,
                generation: 0,
            },
            rights: durable::DurableRights::READ,
            resource_kind: durable::ResourceKind::new(0x7f00_0003).unwrap(),
            flags: durable::GrantFlags::ROOT,
        };
        records.extend(
            durable::preview_grant_transaction(
                &chain,
                durable::TransactionId::new(3).unwrap(),
                grant,
            )
            .unwrap()
            .0
            .records,
        );

        assert_eq!(
            validate_storage_v2_record_stream(&record_stream(&records)),
            Err(DurableCSpaceError::RootPolicy)
        );
    }

    #[cfg_attr(test, test)]
    pub(crate) fn v2_stream_policy_accepts_canonical_empty_authority() {
        let store_id = StoreId::new(M4_STORE_ID_RAW).unwrap();
        let mut chain = durable::RecordChain::new(store_id);
        let records = [chain.append(None, durable::RecordBody::Format).unwrap()];
        assert_eq!(
            validate_storage_v2_record_stream(&record_stream(&records)),
            Ok(())
        );
        let native = storage_v2_empty_import().unwrap();
        assert_eq!(native.record_stream(), record_stream(&records));
        assert_eq!(
            native.root_policy_sha256(),
            storage_v2_external_policy_sha256()
        );
        assert_eq!(native.admitted_object_count(), 0);
    }

    #[cfg_attr(test, test)]
    pub(crate) fn storage_v2_policy_commitments_dispatch_without_reinterpretation() {
        let store_id = StoreId::new(M4_STORE_ID_RAW).unwrap();
        let mut chain = durable::RecordChain::new(store_id);
        let records = [chain.append(None, durable::RecordBody::Format).unwrap()];
        let stream = record_stream(&records);
        let legacy = storage_v2_recovery_import_for_policy(
            &stream,
            storage_v2_legacy_external_policy_sha256(),
        )
        .unwrap();
        assert_eq!(
            legacy.root_policy_sha256(),
            storage_v2_legacy_external_policy_sha256()
        );
        assert_ne!(
            storage_v2_legacy_external_policy_sha256(),
            storage_v2_component_external_policy_sha256()
        );
        assert!(matches!(
            storage_v2_recovery_import_for_policy(&stream, [0xa5; 32]),
            Err(DurableCSpaceError::RootPolicy)
        ));

        #[cfg(feature = "component-durable-publication")]
        {
            let component = storage_v2_recovery_import_for_policy(
                &stream,
                storage_v2_component_external_policy_sha256(),
            )
            .unwrap();
            assert_eq!(
                component.root_policy_sha256(),
                vibeos_component_loader::C74_STORAGE_V2_EXTERNAL_POLICY_SHA256
            );
            assert_eq!(
                storage_v2_component_external_policy_sha256(),
                vibeos_component_loader::C74_STORAGE_V2_EXTERNAL_POLICY_SHA256
            );
            assert!(storage_v2_recovery_policy_is_recognized(
                storage_v2_legacy_external_policy_sha256()
            ));
            assert!(storage_v2_recovery_policy_is_recognized(
                storage_v2_component_external_policy_sha256()
            ));
        }
        #[cfg(not(feature = "component-durable-publication"))]
        {
            assert!(matches!(
                storage_v2_recovery_import_for_policy(
                    &stream,
                    storage_v2_component_external_policy_sha256(),
                ),
                Err(DurableCSpaceError::RootPolicy)
            ));
            assert!(!storage_v2_recovery_policy_is_recognized(
                storage_v2_component_external_policy_sha256()
            ));
        }
    }
}

#[cfg(feature = "legacy-shell")]
pub(crate) fn run_storage_v2_policy_selftests() {
    storage_v2_policy_tests::v2_stream_policy_accepts_canonical_empty_authority();
    storage_v2_policy_tests::v2_stream_policy_rejects_semantic_extra_root_with_canonical_records();
    storage_v2_policy_tests::storage_v2_policy_commitments_dispatch_without_reinterpretation();
}

/// Build the inert import only after running the same exact graph and saved
/// program policy used by live M4 boot. The SSH configuration kind is an
/// optional sealed singleton in the compiled policy: when present, exactly its
/// newest committed value is retained without turning ObjectKind into lookup
/// authority.
pub(crate) fn storage_v2_migration_import(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    // Frozen M4 is always checked under its historical v1 allowlist. Only
    // after that proof may the disjoint V2 checkpoint commit to the active
    // policy. This is an explicit cutover, never an in-place reinterpretation
    // of v1 media.
    let preflight = validate_storage_v2_records(records, StorageV2ExternalPolicy::LegacyV1)?;
    let roots = select_storage_v2_roots(&preflight, StorageV2ExternalPolicy::LegacyV1)?;
    storage_v2_import_from_parts(
        records,
        store_id,
        preflight,
        roots,
        active_storage_v2_external_policy(),
    )
}

fn storage_v2_import_exact_policy(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    policy: StorageV2ExternalPolicy,
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    let preflight = validate_storage_v2_records(records, policy)?;
    let roots = select_storage_v2_roots(&preflight, policy)?;
    storage_v2_import_from_parts(records, store_id, preflight, roots, policy)
}

pub(crate) fn storage_v2_compaction_import_for_policy(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    policy_sha256: [u8; 32],
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let policy = StorageV2ExternalPolicy::from_commitment(policy_sha256)
        .ok_or(DurableCSpaceError::RootPolicy)?;
    storage_v2_import_exact_policy(records, policy)
}

fn storage_v2_import_from_parts(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    store_id: StoreId,
    preflight: durable::RecoveryPreflight,
    roots: Vec<RootPolicy>,
    policy: StorageV2ExternalPolicy,
) -> Result<vibeos_segment_store::PersistentAuthorityImport, DurableCSpaceError> {
    let ssh_kind = durable::ObjectKind::new(SSH_CONFIG_OBJECT_KIND_RAW)
        .expect("fixed SSH configuration kind is non-zero");
    let sealed_singletons = preflight
        .committed_objects()
        .iter()
        .any(|object| object.object_kind == ssh_kind)
        .then_some(ssh_kind);
    let exact_attachments = exact_component_evidence_attachment(&preflight, &roots, policy)?;
    // The policy pass above selects the exact root-relative attachment. The
    // public import boundary independently re-preflights these same sectors so
    // a caller-supplied recovery can never stand in for their provenance.
    // Component evidence is retained only through that selected full record,
    // never by `latest(kind)` or singleton scanning.
    vibeos_segment_store::PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
        records,
        store_id,
        &roots,
        sealed_singletons.as_slice(),
        &exact_attachments,
        policy.canonical(),
        Vec::new(),
        preflight,
    )
    .map_err(|_| DurableCSpaceError::RootPolicy)
}

fn exact_component_evidence_attachment(
    preflight: &durable::RecoveryPreflight,
    roots: &[RootPolicy],
    policy: StorageV2ExternalPolicy,
) -> Result<Vec<durable::RecoveredObject>, DurableCSpaceError> {
    if policy == StorageV2ExternalPolicy::LegacyV1 {
        return Ok(Vec::new());
    }
    #[cfg(not(feature = "component-durable-publication"))]
    {
        let _ = (preflight, roots);
        return Err(DurableCSpaceError::RootPolicy);
    }
    #[cfg(feature = "component-durable-publication")]
    {
        use vibeos_component_format::{ComponentArtifactSignerPolicyKind, ComponentArtifactV1};

        let recovered = preflight
            .clone()
            .finish(roots)
            .map_err(|_| DurableCSpaceError::RootPolicy)?;
        let present = vibeos_component_loader::validate_recovered_bundle_shape(&recovered)
            .map_err(|_| DurableCSpaceError::RootPolicy)?;
        if !present {
            let artifact_kind = durable::ObjectKind::new(COMPONENT_ARTIFACT_OBJECT_KIND_RAW)
                .expect("fixed Component artifact kind is non-zero");
            let evidence_kind =
                durable::ObjectKind::new(COMPONENT_OPERATOR_EVIDENCE_OBJECT_KIND_RAW)
                    .expect("fixed Component evidence kind is non-zero");
            if recovered.objects.iter().any(|object| {
                object.object_kind == artifact_kind || object.object_kind == evidence_kind
            }) {
                // v2 does not treat an orphan of either reserved Component
                // kind as a future lookup target. Initial installation is one
                // complete bundle or no Component records at all.
                return Err(DurableCSpaceError::RootPolicy);
            }
            return Ok(Vec::new());
        }
        let component_space = vibeos_durable_format::SpaceId::new(
            vibeos_component_loader::COMPONENT_ARTIFACT_SPACE_ID_RAW,
        )
        .expect("fixed Component space is non-zero");
        let root = recovered
            .grants
            .iter()
            .find(|grant| grant.grant.target.space == component_space)
            .ok_or(DurableCSpaceError::RootPolicy)?;
        let artifact = recovered
            .objects
            .iter()
            .find(|object| object.object_id == root.grant.object_id)
            .ok_or(DurableCSpaceError::RootPolicy)?;
        let artifact = ComponentArtifactV1::decode(&artifact.bytes)
            .map_err(|_| DurableCSpaceError::RootPolicy)?;
        match artifact.signer_policy().kind() {
            ComponentArtifactSignerPolicyKind::DevelopmentImagePin => Ok(Vec::new()),
            ComponentArtifactSignerPolicyKind::OperatorRequired => {
                let evidence_id = root
                    .transaction_id
                    .get()
                    .checked_sub(3)
                    .and_then(durable::ObjectId::new)
                    .ok_or(DurableCSpaceError::RootPolicy)?;
                let evidence = recovered
                    .objects
                    .iter()
                    .find(|object| object.object_id == evidence_id)
                    .cloned()
                    .ok_or(DurableCSpaceError::RootPolicy)?;
                if preflight
                    .committed_grants()
                    .iter()
                    .any(|grant| grant.grant.object_id == evidence_id)
                {
                    // Evidence is inert data forever. Even a tombstoned
                    // historical grant would prove that this stable object
                    // once crossed the capability boundary.
                    return Err(DurableCSpaceError::RootPolicy);
                }
                Ok(vec![evidence])
            }
        }
    }
}

/// Retained validated replay of the exact published logical stream, so the
/// next strict-extension append validates only its own records instead of
/// re-decoding the whole journal. The chain checkpoint and record count bind
/// the cache to one stream identity; any mismatch falls back to full replay.
pub(crate) struct StorageV2PreflightCache {
    pub(crate) checkpoint: vibeos_durable_format::ChainCheckpoint,
    pub(crate) records: usize,
    pub(crate) replay: durable::PreflightReplay,
}

/// Build the persistent-authority import for `full_records`, reusing a cached
/// validated replay of the untouched prefix when its chain checkpoint matches
/// the observed stream tail. The complete production authorization pass still
/// runs over the resulting state on every append; only the per-record decode
/// and semantic replay of the unchanged prefix is skipped.
pub(crate) fn storage_v2_migration_import_incremental(
    full_records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    appended: usize,
    observed: vibeos_durable_format::ChainCheckpoint,
    cache: Option<StorageV2PreflightCache>,
) -> Result<
    (
        vibeos_segment_store::PersistentAuthorityImport,
        StorageV2PreflightCache,
    ),
    DurableCSpaceError,
> {
    storage_v2_migration_import_incremental_for_policy(
        full_records,
        appended,
        observed,
        cache,
        storage_v2_external_policy_sha256(),
    )
}

pub(crate) fn storage_v2_migration_import_incremental_for_policy(
    full_records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    appended: usize,
    observed: vibeos_durable_format::ChainCheckpoint,
    cache: Option<StorageV2PreflightCache>,
    policy_sha256: [u8; 32],
) -> Result<
    (
        vibeos_segment_store::PersistentAuthorityImport,
        StorageV2PreflightCache,
    ),
    DurableCSpaceError,
> {
    let policy = StorageV2ExternalPolicy::from_commitment(policy_sha256)
        .ok_or(DurableCSpaceError::RootPolicy)?;
    if full_records.is_empty()
        || appended == 0
        || appended > full_records.len()
        || full_records.len() > vibeos_segment_store::MAX_PERSISTENT_AUTHORITY_RECORDS
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    let prefix_len = full_records.len() - appended;
    let mut replay = match cache {
        Some(cache)
            if cache.records == prefix_len
                && cache.checkpoint == observed
                && cache.replay.record_count() as usize == prefix_len =>
        {
            cache.replay
        }
        _ => {
            let mut replay = durable::PreflightReplay::new(store_id);
            replay
                .append(&full_records[..prefix_len])
                .map_err(|_| DurableCSpaceError::RootPolicy)?;
            replay
        }
    };
    replay
        .append(&full_records[prefix_len..])
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    let preflight = replay
        .clone()
        .finish()
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    // This is the complete production validator: exact external roots, fixed
    // CSpace history, typed resource witnesses, and saved-program semantics.
    let snapshot = AuthoritySnapshot::from_legacy_preflight(full_records.len(), preflight.clone())?;
    let _validated = authorize_snapshot_with_policy(snapshot, policy)?;
    let roots = select_storage_v2_roots(&preflight, policy)?;
    let import = storage_v2_import_from_parts(full_records, store_id, preflight, roots, policy)?;
    let checkpoint = replay
        .chain_checkpoint()
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    let cache = StorageV2PreflightCache {
        checkpoint,
        records: full_records.len(),
        replay,
    };
    Ok((import, cache))
}

/// Attempt to compact a validated V2 logical stream. Returns `None` when the
/// rewrite would not repay an extra checkpoint (savings below one quarter of
/// the records). `drop_ungranted_objects` may be true only at a boot
/// boundary: ungranted objects are unreachable after reboot because no
/// durable grant names them, but capabilities minted this boot still resolve
/// them, so runtime compaction must keep them.
pub(crate) fn storage_v2_compact_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    drop_ungranted_objects: bool,
) -> Result<Option<Vec<[u8; vibeos_durable_format::RECORD_SIZE]>>, DurableCSpaceError> {
    storage_v2_compact_records_for_policy(
        records,
        drop_ungranted_objects,
        storage_v2_external_policy_sha256(),
    )
}

pub(crate) fn storage_v2_compact_records_for_policy(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    drop_ungranted_objects: bool,
    policy_sha256: [u8; 32],
) -> Result<Option<Vec<[u8; vibeos_durable_format::RECORD_SIZE]>>, DurableCSpaceError> {
    let policy = StorageV2ExternalPolicy::from_commitment(policy_sha256)
        .ok_or(DurableCSpaceError::RootPolicy)?;
    let compacted = if drop_ungranted_objects {
        // Constructing the import first performs the complete external-policy
        // pass and freezes its exact admitted set. Segment-store then retains
        // only those full comparison records; no kernel kind/ID scan can turn
        // an unrelated orphan into a compaction attachment.
        storage_v2_import_exact_policy(records, policy)?
            .compact_boot_boundary_records()
            .map_err(|_| DurableCSpaceError::RootPolicy)?
    } else {
        let preflight = validate_storage_v2_records(records, policy)?;
        preflight
            .compact(false)
            .map_err(|_| DurableCSpaceError::RootPolicy)?
    };
    // The rewrite must be worth a replace checkpoint plus the risk budget of
    // touching authority at all: require at least a 25% record reduction.
    if compacted
        .len()
        .saturating_add(compacted.len() / 4)
        .saturating_add(1)
        >= records.len()
    {
        return Ok(None);
    }
    Ok(Some(compacted))
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

/// The saved-program artifact whose source-to-executable recompilation proof
/// already succeeded this boot. The proof is a deterministic function of the
/// stream-authenticated artifact bytes, so re-running the compiler on every
/// authority append re-proves a settled fact; any identity change (a new
/// program, or a compacted stream's fresh sequences) revalidates in full.
static VALIDATED_PROGRAM_ARTIFACT: SpinLock<Option<program_model::ValidatedArtifact>> =
    SpinLock::new(None);
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
            active: SpinLock::new_recoverable(None),
            dependent_started: AtomicBool::new(false),
            graph: crate::sync::SpinLock::new_recoverable(LiveGraph::default()),
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
        if !block_device::is_online() {
            return Err(StoreError::Backend(crate::store::BackendError::Offline).into());
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
                .stage_recovered(program_identities.first().copied())
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
        self.inner
            .saved_program
            .activate_recovered()
            .map_err(|_| DurableCSpaceError::Install)?;
        // SavedProgram Ready is the final fallible activation publication.
        // From here to the coordinator's exact claim release there is no await
        // or fallible operation for a remote client to overtake.
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
        let resource = committed.stored_object(&object)?;
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
                crate::store::BackendError::Offline
                    | crate::store::BackendError::DriverFault
                    | crate::store::BackendError::DriverRestarted
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

    let task_key =
        crate::sync::TaskRecoveryKey::new(task.0).expect("executor TaskId zero is reserved");

    // Safety: the executor detached the exact task before this hook. Repair
    // each possibly abandoned lock before taking it. The saved-program hook is
    // ordered before this one in `cleanup_faulted_task`, because quarantine of
    // a durable boot claim also fail-closes the saved-program target.
    let _ = unsafe { inner.active.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { inner.target.0.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { inner.graph.recover_after_task_fault(domain, task_key) };

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

fn component_artifact_space_id() -> durable::SpaceId {
    durable::SpaceId::new(COMPONENT_ARTIFACT_SPACE_ID_RAW)
        .expect("fixed Component artifact space is non-zero")
}

fn component_space_has_live_root(
    preflight: &durable::RecoveryPreflight,
) -> Result<bool, DurableCSpaceError> {
    let space = component_artifact_space_id();
    let has_live = preflight
        .slots()
        .iter()
        .any(|slot| slot.space == space && slot.live_derivation.is_some());
    if preflight
        .slots()
        .iter()
        .any(|slot| slot.space == space && slot.slot != 0)
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    Ok(has_live)
}

fn select_storage_v2_roots(
    preflight: &durable::RecoveryPreflight,
    policy: StorageV2ExternalPolicy,
) -> Result<Vec<RootPolicy>, DurableCSpaceError> {
    let has_live_authority = preflight
        .slots()
        .iter()
        .any(|slot| slot.space == persistent_space_id() && slot.live_derivation.is_some());
    let has_live_program = preflight.slots().iter().any(|slot| {
        slot.space == program_model::program_space_id() && slot.live_derivation.is_some()
    });
    let has_live_component = component_space_has_live_root(preflight)?;
    if policy == StorageV2ExternalPolicy::LegacyV1 && has_live_component {
        return Err(DurableCSpaceError::RootPolicy);
    }
    #[cfg(not(feature = "component-durable-publication"))]
    if policy == StorageV2ExternalPolicy::ComponentV2 {
        return Err(DurableCSpaceError::RootPolicy);
    }
    let persistent_constraints = [RootConstraint {
        space: persistent_space_id(),
        first_slot: ROOT_SLOT,
        last_slot_inclusive: ROOT_SLOT,
        rights: RootRightsConstraint::exact(ROOT_RIGHTS),
        resource_kind: stored_object_resource_kind(),
        object_kind: persistent_object_kind(),
    }];
    let program_constraints = [program_model::program_root_constraint()];
    #[cfg(feature = "component-durable-publication")]
    let component_constraints = [vibeos_component_loader::root_constraint()];
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
    #[cfg(feature = "component-durable-publication")]
    if policy == StorageV2ExternalPolicy::ComponentV2 && has_live_component {
        partitions.push(RootPolicyPartition {
            space: component_artifact_space_id(),
            constraints: &component_constraints,
        });
    }
    let roots = durable::select_root_policy_union(preflight, &partitions)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    if has_live_program
        && !roots.iter().any(|root| {
            root.grant.target.space == program_model::program_space_id()
                && program_model::program_root_policy_is_exact(root)
        })
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    if has_live_authority
        && !roots.iter().any(|root| {
            root.grant.target.space == persistent_space_id()
                && root.grant.target.slot == ROOT_SLOT
                && root.grant.target.generation == 0
                && root.grant.parent_id.is_none()
                && root.grant.flags == GrantFlags::ROOT
                && root.grant.rights == ROOT_RIGHTS
                && root.grant.resource_kind == stored_object_resource_kind()
        })
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    #[cfg(feature = "component-durable-publication")]
    if policy == StorageV2ExternalPolicy::ComponentV2
        && has_live_component
        && !roots.iter().any(|root| {
            root.grant.target.space == component_artifact_space_id()
                && vibeos_component_loader::root_policy_is_exact(root)
        })
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    Ok(roots)
}

fn authorize_snapshot(snapshot: AuthoritySnapshot) -> Result<TrustedSnapshot, DurableCSpaceError> {
    authorize_snapshot_with_policy(snapshot, StorageV2ExternalPolicy::LegacyV1)
}

fn authorize_snapshot_with_policy(
    snapshot: AuthoritySnapshot,
    policy: StorageV2ExternalPolicy,
) -> Result<TrustedSnapshot, DurableCSpaceError> {
    let object_resolver = snapshot.object_resolver();
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
    let roots = select_storage_v2_roots(&preflight, policy)?;
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
            object_resolver.stored_object(object).map_err(Into::into)
        })
        .transpose()?;
    let recovered = preflight
        .finish(&roots)
        .map_err(|_| DurableCSpaceError::RootPolicy)?;
    if policy == StorageV2ExternalPolicy::ComponentV2 {
        #[cfg(feature = "component-durable-publication")]
        vibeos_component_loader::validate_recovered_bundle_shape(&recovered)
            .map_err(|_| DurableCSpaceError::RootPolicy)?;
        #[cfg(not(feature = "component-durable-publication"))]
        return Err(DurableCSpaceError::RootPolicy);
    }
    let mut policy_spaces = vec![persistent_space_id(), program_model::program_space_id()];
    if policy == StorageV2ExternalPolicy::ComponentV2 {
        policy_spaces.push(component_artifact_space_id());
    }
    let tombstone_partitions = durable::partition_tombstones_by_space(
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
    let allowed_space = |space| {
        space == persistent_space_id()
            || space == program_model::program_space_id()
            || (policy == StorageV2ExternalPolicy::ComponentV2
                && space == component_artifact_space_id())
    };
    if recovered
        .grants
        .iter()
        .any(|grant| !allowed_space(grant.grant.target.space))
        || recovered
            .slots
            .iter()
            .any(|slot| !allowed_space(slot.space))
    {
        return Err(DurableCSpaceError::RootPolicy);
    }
    // The shape validator reads only object identities, never content, so
    // the space-partitioned view borrows the objects instead of duplicating
    // every committed object's bytes on each append.
    let persistent = RecoveredStore {
        store_id: recovered.store_id,
        id_high_water: recovered.id_high_water,
        grants: recovered
            .grants
            .iter()
            .filter(|grant| grant.grant.target.space == persistent_space_id())
            .cloned()
            .collect(),
        objects: Vec::new(),
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
    let shape = validate_fixed_graph_shape(
        &persistent_committed_grants,
        &persistent,
        &recovered.objects,
    )?;
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
    let memo = *VALIDATED_PROGRAM_ARTIFACT.lock();
    let (program, validated) = program_model::authorize_recovered_with_memo(
        &program_recovered,
        |object| {
            object_resolver
                .stored_object(object)
                .map_err(program_model::SavedProgramError::from)
        },
        memo,
    )
    .map_err(|_| DurableCSpaceError::RootPolicy)?;
    if validated.is_some() {
        *VALIDATED_PROGRAM_ARTIFACT.lock() = validated;
    }
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
    objects: &[durable::RecoveredObject],
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
    if !objects.iter().any(|object| {
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
