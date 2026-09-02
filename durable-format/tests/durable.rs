//! M4.0 durable-authority format and crash-recovery proof tests.

use vibeos_durable_format::{
    crc32c, encode_object_transaction, preflight_recovery, preview_grant_transaction,
    preview_id_high_water, preview_revoke_transaction, recover, DecodeError, DecodeStatus,
    DerivationId, DurableRights, GrantFlags, GrantRecord, LogRecord, ObjectId, ObjectKind,
    RecordBody, RecordChain, RecoveredStore, RecoveryError, RecoveryPolicy, ResourceKind,
    RootConstraint, RootPolicy, RootRightsConstraint, SlotIdentity, SpaceId, StoreId,
    TransactionId, CRC_OFFSET, PAYLOAD_OFFSET, RECORD_SIZE,
};

const HIGH_WATER: u128 = 1_000;

fn store() -> StoreId {
    StoreId::new(9000).unwrap()
}
fn deriv(value: u128) -> DerivationId {
    DerivationId::new(value).unwrap()
}
fn object(value: u128) -> ObjectId {
    ObjectId::new(value).unwrap()
}
fn space(value: u128) -> SpaceId {
    SpaceId::new(value).unwrap()
}
fn tx(value: u128) -> TransactionId {
    TransactionId::new(value).unwrap()
}
fn kind(value: u32) -> ResourceKind {
    ResourceKind::new(value).unwrap()
}

fn root_grant(id: u128, space_id: u128, slot: u32, generation: u64) -> GrantRecord {
    GrantRecord {
        derivation_id: deriv(id),
        parent_id: None,
        object_id: object(100),
        target: SlotIdentity {
            space: space(space_id),
            slot,
            generation,
        },
        rights: DurableRights::ALL,
        resource_kind: kind(7),
        flags: GrantFlags::ROOT,
    }
}

fn child_grant(id: u128, parent: u128, space_id: u128, slot: u32) -> GrantRecord {
    GrantRecord {
        derivation_id: deriv(id),
        parent_id: Some(deriv(parent)),
        object_id: object(100),
        target: SlotIdentity {
            space: space(space_id),
            slot,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind: kind(7),
        flags: GrantFlags::DERIVED,
    }
}

struct TestLog {
    chain: RecordChain,
    sectors: Vec<[u8; RECORD_SIZE]>,
}

impl TestLog {
    fn formatted() -> Self {
        let mut this = Self {
            chain: RecordChain::new(store()),
            sectors: Vec::new(),
        };
        this.push(None, RecordBody::Format);
        this.push(
            None,
            RecordBody::IdHighWater {
                exclusive_end: HIGH_WATER,
            },
        );
        this
    }

    fn push(&mut self, transaction: Option<TransactionId>, body: RecordBody) -> (u64, u32) {
        let bytes = self.chain.append(transaction, body).unwrap();
        let DecodeStatus::Valid(decoded) = LogRecord::decode(&bytes).unwrap() else {
            panic!("freshly encoded record must decode")
        };
        let result = (decoded.record.sequence, decoded.crc32c);
        self.sectors.push(bytes);
        result
    }

    fn grant(&mut self, transaction: TransactionId, grant: GrantRecord) {
        let (prepare_sequence, prepare_crc32c) =
            self.push(Some(transaction), RecordBody::GrantPrepare(grant.clone()));
        self.push(
            Some(transaction),
            RecordBody::GrantCommit {
                prepare_sequence,
                prepare_crc32c,
                derivation_id: grant.derivation_id,
            },
        );
    }

    fn tombstone(&mut self, transaction: TransactionId, id: DerivationId) {
        self.push(
            Some(transaction),
            RecordBody::RevokeTombstone { derivation_id: id },
        );
    }

    fn object(
        &mut self,
        transaction: TransactionId,
        object_id: ObjectId,
        object_kind: ObjectKind,
        bytes: &[u8],
    ) {
        let transaction =
            encode_object_transaction(&mut self.chain, transaction, object_id, object_kind, bytes)
                .unwrap();
        self.sectors.extend(transaction.records);
    }
}

fn recover_with(
    sectors: &[[u8; RECORD_SIZE]],
    roots: &[GrantRecord],
) -> Result<RecoveredStore, RecoveryError> {
    let policies: Vec<_> = roots
        .iter()
        .cloned()
        .map(|grant| RootPolicy { grant })
        .collect();
    recover(
        sectors,
        RecoveryPolicy {
            store_id: store(),
            roots: &policies,
        },
    )
}

fn prefix(bytes: &[u8; RECORD_SIZE], cut: usize) -> [u8; RECORD_SIZE] {
    let mut torn = [0u8; RECORD_SIZE];
    torn[..cut].copy_from_slice(&bytes[..cut]);
    torn
}

fn refresh_crc(bytes: &mut [u8; RECORD_SIZE]) {
    let crc = crc32c(&bytes[..CRC_OFFSET]);
    bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    bytes[CRC_OFFSET + 4..CRC_OFFSET + 8].copy_from_slice(&(!crc).to_le_bytes());
}

#[test]
fn crc32c_matches_the_standard_check_vector() {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
}

#[test]
fn every_record_kind_has_a_canonical_round_trip() {
    let root = root_grant(10, 20, 3, 4);
    let mut log = TestLog::formatted();
    let (prepare_sequence, prepare_crc32c) =
        log.push(Some(tx(30)), RecordBody::GrantPrepare(root.clone()));
    log.push(
        Some(tx(30)),
        RecordBody::GrantCommit {
            prepare_sequence,
            prepare_crc32c,
            derivation_id: root.derivation_id,
        },
    );
    log.tombstone(tx(31), root.derivation_id);

    for bytes in &log.sectors {
        let DecodeStatus::Valid(decoded) = LogRecord::decode(bytes).unwrap() else {
            panic!("canonical record did not decode")
        };
        assert_eq!(decoded.record.encode().unwrap(), *bytes);
        assert_eq!(
            decoded.crc32c,
            u32::from_le_bytes(bytes[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap())
        );
    }
    assert_eq!(&log.sectors[0][..8], b"VIBECAP\0");
    assert_eq!(&log.sectors[0][0x1f0..], b"VIBECAP-COMMIT!!");
}

#[test]
fn every_prefix_cut_of_every_record_is_empty_or_torn_until_the_full_sector() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    log.grant(tx(30), root.clone());
    log.tombstone(tx(31), root.derivation_id);

    for record in &log.sectors {
        for cut in 0..=RECORD_SIZE {
            let image = prefix(record, cut);
            match (cut, LogRecord::decode(&image).unwrap()) {
                (0, DecodeStatus::Empty) => {}
                (RECORD_SIZE, DecodeStatus::Valid(_)) => {}
                (_, DecodeStatus::Torn) => {}
                other => panic!("cut {cut} produced {other:?}"),
            }
        }
    }
}

#[test]
fn grant_prepare_and_commit_cuts_never_publish_extra_authority() {
    let root = root_grant(10, 20, 0, 0);
    let mut base = TestLog::formatted();
    let prepare = base
        .chain
        .append(Some(tx(30)), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded_prepare) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };

    for cut in 0..=RECORD_SIZE {
        let mut image = base.sectors.clone();
        image.push(prefix(&prepare, cut));
        let recovered = recover_with(&image, core::slice::from_ref(&root)).unwrap();
        assert!(
            recovered.grants.is_empty(),
            "prepare cut {cut} published a grant"
        );
    }

    base.sectors.push(prepare);
    let commit = base
        .chain
        .append(
            Some(tx(30)),
            RecordBody::GrantCommit {
                prepare_sequence: decoded_prepare.record.sequence,
                prepare_crc32c: decoded_prepare.crc32c,
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();
    for cut in 0..=RECORD_SIZE {
        let mut image = base.sectors.clone();
        image.push(prefix(&commit, cut));
        let recovered = recover_with(&image, core::slice::from_ref(&root)).unwrap();
        assert_eq!(
            recovered.grants.len(),
            usize::from(cut == RECORD_SIZE),
            "commit cut {cut} did not recover an old-or-exact-new state"
        );
    }
}

#[test]
fn tombstone_cuts_only_preserve_or_shrink_authority() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    log.grant(tx(30), root.clone());
    let tombstone = log
        .chain
        .append(
            Some(tx(31)),
            RecordBody::RevokeTombstone {
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();

    for cut in 0..=RECORD_SIZE {
        let mut image = log.sectors.clone();
        image.push(prefix(&tombstone, cut));
        let recovered = recover_with(&image, core::slice::from_ref(&root)).unwrap();
        assert_eq!(
            recovered.grants.len(),
            usize::from(cut != RECORD_SIZE),
            "tombstone cut {cut} amplified authority"
        );
    }
}

#[test]
fn an_ancestor_tombstone_wins_across_spaces_and_record_order() {
    let root = root_grant(10, 20, 0, 0);
    let child = child_grant(11, 10, 21, 0);
    let mut log = TestLog::formatted();
    log.grant(tx(30), root.clone());
    log.tombstone(tx(31), root.derivation_id);
    log.grant(tx(32), child);

    let recovered = recover_with(&log.sectors, core::slice::from_ref(&root)).unwrap();
    assert!(recovered.grants.is_empty());
    assert_eq!(recovered.tombstones, vec![root.derivation_id]);
    assert_eq!(recovered.slots.len(), 2);
    assert!(recovered
        .slots
        .iter()
        .all(|slot| { slot.max_generation == 0 && slot.live_derivation.is_none() }));
}

#[test]
fn a_tombstone_for_a_not_yet_present_id_prevents_identity_reuse() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    log.tombstone(tx(29), root.derivation_id);
    log.grant(tx(30), root.clone());
    assert_eq!(
        recover_with(&log.sectors, core::slice::from_ref(&root)),
        Err(RecoveryError::DuplicateDerivation { sequence: 4 })
    );
}

#[test]
fn high_water_must_precede_ids_and_never_move_backward() {
    let root = root_grant(999, 20, 0, 0);
    let mut okay = TestLog::formatted();
    okay.grant(tx(998), root.clone());
    assert_eq!(
        recover_with(&okay.sectors, core::slice::from_ref(&root))
            .unwrap()
            .id_high_water,
        HIGH_WATER
    );

    let unreserved = root_grant(1_000, 20, 0, 0);
    let mut bad = TestLog::formatted();
    bad.grant(tx(30), unreserved.clone());
    assert_eq!(
        recover_with(&bad.sectors, core::slice::from_ref(&unreserved)),
        Err(RecoveryError::IdNotReserved { sequence: 3 })
    );

    let mut decreasing = TestLog::formatted();
    decreasing.push(None, RecordBody::IdHighWater { exclusive_end: 999 });
    assert_eq!(
        recover_with(&decreasing.sectors, &[]),
        Err(RecoveryError::NonMonotonicHighWater)
    );
}

#[test]
fn every_high_water_cut_recovers_the_old_or_exact_new_reservation() {
    let mut chain = RecordChain::new(store());
    let format = chain.append(None, RecordBody::Format).unwrap();
    let old = chain
        .append(None, RecordBody::IdHighWater { exclusive_end: 100 })
        .unwrap();
    let new = chain
        .append(None, RecordBody::IdHighWater { exclusive_end: 200 })
        .unwrap();
    for cut in 0..=RECORD_SIZE {
        let image = [format, old, prefix(&new, cut)];
        let recovered = recover_with(&image, &[]).unwrap();
        assert_eq!(
            recovered.id_high_water,
            if cut == RECORD_SIZE { 200 } else { 100 }
        );
    }

    // Only the fully written-and-flushed high-water permits issuing these IDs.
    let root = GrantRecord {
        derivation_id: deriv(150),
        parent_id: None,
        object_id: object(151),
        target: SlotIdentity {
            space: space(152),
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::ALL,
        resource_kind: kind(7),
        flags: GrantFlags::ROOT,
    };
    let prepare = chain
        .append(Some(tx(153)), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };
    let commit = chain
        .append(
            Some(tx(153)),
            RecordBody::GrantCommit {
                prepare_sequence: decoded.record.sequence,
                prepare_crc32c: decoded.crc32c,
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();
    assert_eq!(
        recover_with(
            &[format, old, new, prepare, commit],
            core::slice::from_ref(&root)
        )
        .unwrap()
        .grants
        .len(),
        1
    );
}

#[test]
fn authority_previews_never_advance_the_live_chain() {
    let chain = RecordChain::new(store());
    let original = chain.checkpoint();
    let (high_water, after_high_water) = preview_id_high_water(&chain, HIGH_WATER).unwrap();
    assert_eq!(chain.checkpoint(), original);
    assert_eq!(high_water.records.len(), 1);
    assert_eq!(after_high_water.next_sequence(), 2);

    let root = root_grant(10, 20, 0, 0);
    let before_grant = after_high_water.checkpoint();
    let (grant, after_grant) =
        preview_grant_transaction(&after_high_water, tx(30), root.clone()).unwrap();
    assert_eq!(after_high_water.checkpoint(), before_grant);
    assert_eq!(grant.records.len(), 2);
    assert_eq!(after_grant.next_sequence(), 4);

    let before_revoke = after_grant.checkpoint();
    let (revoke, after_revoke) =
        preview_revoke_transaction(&after_grant, tx(31), root.derivation_id).unwrap();
    assert_eq!(after_grant.checkpoint(), before_revoke);
    assert_eq!(revoke.records.len(), 1);
    assert_eq!(after_revoke.next_sequence(), 5);
}

#[test]
fn graph_recovery_rejects_missing_granting_amplifying_and_mismatched_parents() {
    let base_root = root_grant(10, 20, 0, 0);

    let mut missing = TestLog::formatted();
    missing.grant(tx(31), child_grant(11, 99, 21, 0));
    assert!(matches!(
        recover_with(&missing.sectors, core::slice::from_ref(&base_root)),
        Err(RecoveryError::MissingParent { .. })
    ));

    let mut no_grant_root = base_root.clone();
    no_grant_root.rights = DurableRights::READ;
    let mut no_grant = TestLog::formatted();
    no_grant.grant(tx(30), no_grant_root.clone());
    no_grant.grant(tx(31), child_grant(11, 10, 21, 0));
    assert!(matches!(
        recover_with(&no_grant.sectors, core::slice::from_ref(&no_grant_root)),
        Err(RecoveryError::ParentCannotGrant { .. })
    ));

    let mut weak_root = base_root.clone();
    weak_root.rights = DurableRights::READ.union(DurableRights::GRANT);
    let mut amplified_child = child_grant(11, 10, 21, 0);
    amplified_child.rights = DurableRights::WRITE;
    let mut amplified = TestLog::formatted();
    amplified.grant(tx(30), weak_root.clone());
    amplified.grant(tx(31), amplified_child);
    assert!(matches!(
        recover_with(&amplified.sectors, core::slice::from_ref(&weak_root)),
        Err(RecoveryError::RightsAmplification { .. })
    ));

    let mut wrong_object = child_grant(11, 10, 21, 0);
    wrong_object.object_id = object(101);
    let mut mismatch = TestLog::formatted();
    mismatch.grant(tx(30), base_root.clone());
    mismatch.grant(tx(31), wrong_object);
    assert!(matches!(
        recover_with(&mismatch.sectors, core::slice::from_ref(&base_root)),
        Err(RecoveryError::ObjectMismatch { .. })
    ));
}

#[test]
fn only_exact_trusted_roots_and_one_kind_per_object_are_recovered() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    log.grant(tx(30), root.clone());
    assert!(matches!(
        recover_with(&log.sectors, &[]),
        Err(RecoveryError::RootNotTrusted { .. })
    ));

    let mut other_kind = root_grant(11, 21, 0, 0);
    other_kind.resource_kind = kind(8);
    log.grant(tx(31), other_kind.clone());
    assert!(matches!(
        recover_with(&log.sectors, &[root, other_kind]),
        Err(RecoveryError::ObjectMismatch { .. })
    ));
}

#[test]
fn dynamic_root_selection_binds_external_policy_and_object_commit_order() {
    let root = root_grant(10, 20, 0, 0);
    let object_kind = ObjectKind::new(3).unwrap();
    let constraint = RootConstraint {
        space: root.target.space,
        first_slot: 0,
        last_slot_inclusive: 0,
        rights: RootRightsConstraint::exact(DurableRights::ALL),
        resource_kind: root.resource_kind,
        object_kind,
    };

    let mut ordered = TestLog::formatted();
    ordered.object(tx(40), root.object_id, object_kind, b"typed-root");
    ordered.grant(tx(30), root.clone());
    let preflight = preflight_recovery(&ordered.sectors, store()).unwrap();
    assert_eq!(preflight.committed_objects()[0].bytes, b"typed-root");
    let roots = preflight.select_roots(&[constraint]).unwrap();
    assert_eq!(
        roots,
        vec![RootPolicy {
            grant: root.clone()
        }]
    );
    let recovered = preflight.finish(&roots).unwrap();
    assert_eq!(recovered.grants.len(), 1);
    assert_eq!(recovered.objects.len(), 1);

    let mut too_late = TestLog::formatted();
    too_late.grant(tx(30), root.clone());
    too_late.object(tx(40), root.object_id, object_kind, b"late-object");
    let preflight = preflight_recovery(&too_late.sectors, store()).unwrap();
    assert_eq!(
        preflight.select_roots(&[constraint]),
        Err(RecoveryError::MissingRootConstraint)
    );
}

#[test]
fn multiple_live_roots_matching_one_constraint_fail_closed() {
    let first = root_grant(10, 20, 0, 0);
    let second = root_grant(11, 20, 1, 0);
    let object_kind = ObjectKind::new(4).unwrap();
    let mut log = TestLog::formatted();
    log.object(tx(40), first.object_id, object_kind, b"ambiguous");
    log.grant(tx(30), first.clone());
    log.grant(tx(31), second);
    let preflight = preflight_recovery(&log.sectors, store()).unwrap();
    let constraint = RootConstraint {
        space: first.target.space,
        first_slot: 0,
        last_slot_inclusive: 1,
        rights: RootRightsConstraint::exact(DurableRights::ALL),
        resource_kind: first.resource_kind,
        object_kind,
    };
    assert_eq!(
        preflight.select_roots(&[constraint]),
        Err(RecoveryError::AmbiguousRootConstraint)
    );
}

fn slot_log(second_generation: u64, tombstone_first: bool) -> (TestLog, GrantRecord, GrantRecord) {
    let first = root_grant(10, 20, 4, 1);
    let second = root_grant(11, 20, 4, second_generation);
    let mut log = TestLog::formatted();
    log.grant(tx(30), first.clone());
    if tombstone_first {
        log.tombstone(tx(31), first.derivation_id);
    }
    log.grant(tx(32), second.clone());
    (log, first, second)
}

#[test]
fn slot_reuse_requires_a_prior_tombstone_and_strict_generation_growth() {
    let (live, first, second) = slot_log(2, false);
    assert!(matches!(
        recover_with(&live.sectors, &[first.clone(), second.clone()]),
        Err(RecoveryError::SlotStillLive { .. })
    ));

    let (same, first, second) = slot_log(1, true);
    assert!(matches!(
        recover_with(&same.sectors, &[first, second]),
        Err(RecoveryError::SlotGeneration { .. })
    ));

    let (valid, first, second) = slot_log(2, true);
    let recovered = recover_with(&valid.sectors, &[first, second.clone()]).unwrap();
    assert_eq!(recovered.grants.len(), 1);
    assert_eq!(recovered.grants[0].grant, second);
}

#[test]
fn tombstoned_latest_slot_retains_its_historical_generation() {
    let root = root_grant(10, 20, 4, 37);
    let mut log = TestLog::formatted();
    log.grant(tx(30), root.clone());
    log.tombstone(tx(31), root.derivation_id);

    let recovered = recover_with(&log.sectors, core::slice::from_ref(&root)).unwrap();
    assert!(recovered.grants.is_empty());
    assert_eq!(recovered.slots.len(), 1);
    assert_eq!(recovered.slots[0].space, root.target.space);
    assert_eq!(recovered.slots[0].slot, root.target.slot);
    assert_eq!(recovered.slots[0].max_generation, 37);
    assert_eq!(recovered.slots[0].live_derivation, None);
}

#[test]
fn transaction_and_commit_binding_cannot_be_reused_or_spliced() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    let (prepare_sequence, prepare_crc32c) =
        log.push(Some(tx(30)), RecordBody::GrantPrepare(root.clone()));
    log.push(
        Some(tx(30)),
        RecordBody::GrantCommit {
            prepare_sequence,
            prepare_crc32c: prepare_crc32c ^ 1,
            derivation_id: root.derivation_id,
        },
    );
    assert_eq!(
        recover_with(&log.sectors, core::slice::from_ref(&root)),
        Err(RecoveryError::CommitMismatch { sequence: 4 })
    );

    let mut duplicate = TestLog::formatted();
    duplicate.push(Some(tx(30)), RecordBody::GrantPrepare(root.clone()));
    duplicate.tombstone(tx(30), root.derivation_id);
    assert_eq!(
        recover_with(&duplicate.sectors, core::slice::from_ref(&root)),
        Err(RecoveryError::DuplicateTransaction { sequence: 4 })
    );
}

#[test]
fn orphan_commits_consume_stable_derivation_identity() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    log.push(
        Some(tx(30)),
        RecordBody::GrantCommit {
            prepare_sequence: 99,
            prepare_crc32c: 1,
            derivation_id: root.derivation_id,
        },
    );
    log.grant(tx(31), root.clone());
    assert_eq!(
        recover_with(&log.sectors, core::slice::from_ref(&root)),
        Err(RecoveryError::DuplicateDerivation { sequence: 4 })
    );
}

#[test]
fn typed_ids_share_one_numeric_namespace() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    let (prepare_sequence, prepare_crc32c) =
        log.push(Some(tx(100)), RecordBody::GrantPrepare(root.clone()));
    log.push(
        Some(tx(100)),
        RecordBody::GrantCommit {
            prepare_sequence,
            prepare_crc32c,
            derivation_id: root.derivation_id,
        },
    );
    assert_eq!(
        recover_with(&log.sectors, core::slice::from_ref(&root)),
        Err(RecoveryError::IdClassCollision { sequence: 3 })
    );
}

#[test]
fn sealed_noncanonical_records_fail_closed() {
    let mut chain = RecordChain::new(store());
    let format = chain.append(None, RecordBody::Format).unwrap();
    let mutations: &[(usize, u8, DecodeError)] = &[
        (0x08, 2, DecodeError::UnsupportedVersion),
        (0x0a, 0xff, DecodeError::UnknownKind),
        (0x0c, 79, DecodeError::BadHeaderLength),
        (0x0e, 1, DecodeError::BadPayloadLength),
        (0x24, 1, DecodeError::NonZeroHeaderFlags),
        (0x48, 1, DecodeError::NonZeroReserved),
        (PAYLOAD_OFFSET, 1, DecodeError::NonCanonicalPadding),
        (0x20, 1, DecodeError::BadCrc),
        (CRC_OFFSET + 4, 1, DecodeError::BadCrcComplement),
        (CRC_OFFSET + 8, 2, DecodeError::BadSequenceCopy),
        (CRC_OFFSET + 16, 1, DecodeError::BadTransactionCopy),
    ];
    for (offset, value, expected) in mutations {
        let mut bad = format;
        bad[*offset] ^= *value;
        assert_eq!(LogRecord::decode(&bad), Err(*expected));
        assert_eq!(
            recover_with(&[bad], &[]),
            Err(RecoveryError::SealedRecord {
                sector: 0,
                source: *expected
            })
        );
    }
}

#[test]
fn sealed_semantic_field_errors_are_all_rejected_canonically() {
    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    let prepare = log
        .chain
        .append(Some(tx(30)), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };
    let commit = log
        .chain
        .append(
            Some(tx(30)),
            RecordBody::GrantCommit {
                prepare_sequence: decoded.record.sequence,
                prepare_crc32c: decoded.crc32c,
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();

    let mut cases = Vec::new();
    let mut bad = prepare;
    bad[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 16].fill(0);
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::ZeroStableId));

    let mut bad = prepare;
    bad[PAYLOAD_OFFSET + 68] = 0x80;
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::UnknownRights));

    let mut bad = prepare;
    bad[PAYLOAD_OFFSET + 80..PAYLOAD_OFFSET + 84].fill(0);
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::ZeroResourceKind));

    let mut bad = prepare;
    bad[PAYLOAD_OFFSET + 84] = 2;
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::UnknownGrantFlags));

    let mut bad = prepare;
    bad[0x38..0x48].fill(0);
    bad[0x1e0..0x1f0].fill(0);
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::MissingTransaction));

    let mut bad = log.sectors[0];
    bad[0x38] = 1;
    bad[0x1e0] = 1;
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::UnexpectedTransaction));

    let mut bad = commit;
    bad[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 8].fill(0);
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::ZeroPrepareSequence));

    let mut bad = commit;
    bad[PAYLOAD_OFFSET + 12] = 1;
    refresh_crc(&mut bad);
    cases.push((bad, DecodeError::NonZeroReserved));

    for (bad, expected) in cases {
        assert_eq!(LogRecord::decode(&bad), Err(expected));
    }
}

#[test]
fn durable_v1_rights_exclude_the_volatile_invoke_bit() {
    const DURABLE_V1_ALL: u32 = 0x3f;
    const VOLATILE_INVOKE_BIT: u32 = 0x40;

    assert_eq!(DurableRights::ALL.bits(), DURABLE_V1_ALL);
    assert_eq!(
        DurableRights::from_bits(DURABLE_V1_ALL),
        Some(DurableRights::ALL)
    );
    assert_eq!(DurableRights::from_bits(VOLATILE_INVOKE_BIT), None);
    assert_eq!(
        DurableRights::from_bits(DURABLE_V1_ALL | VOLATILE_INVOKE_BIT),
        None
    );
}

#[test]
fn sealed_grant_with_volatile_invoke_bit_is_rejected_after_crc_and_chain_rebinding() {
    const VOLATILE_INVOKE_BIT: u32 = 0x40;
    const PREVIOUS_CRC_OFFSET: usize = 0x20;
    const GRANT_RIGHTS_OFFSET: usize = PAYLOAD_OFFSET + 68;
    const COMMIT_PREPARE_CRC_OFFSET: usize = PAYLOAD_OFFSET + 8;

    let root = root_grant(10, 20, 0, 0);
    let mut log = TestLog::formatted();
    let mut prepare = log
        .chain
        .append(Some(tx(30)), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };
    let mut commit = log
        .chain
        .append(
            Some(tx(30)),
            RecordBody::GrantCommit {
                prepare_sequence: decoded.record.sequence,
                prepare_crc32c: decoded.crc32c,
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();

    let serialized_rights = DurableRights::ALL.bits() | VOLATILE_INVOKE_BIT;
    prepare[GRANT_RIGHTS_OFFSET..GRANT_RIGHTS_OFFSET + 4]
        .copy_from_slice(&serialized_rights.to_le_bytes());
    refresh_crc(&mut prepare);
    let prepare_crc = u32::from_le_bytes(prepare[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap());

    commit[PREVIOUS_CRC_OFFSET..PREVIOUS_CRC_OFFSET + 4]
        .copy_from_slice(&prepare_crc.to_le_bytes());
    commit[COMMIT_PREPARE_CRC_OFFSET..COMMIT_PREPARE_CRC_OFFSET + 4]
        .copy_from_slice(&prepare_crc.to_le_bytes());
    refresh_crc(&mut commit);

    assert_eq!(LogRecord::decode(&prepare), Err(DecodeError::UnknownRights));
    assert!(matches!(
        LogRecord::decode(&commit),
        Ok(DecodeStatus::Valid(_))
    ));
    assert_eq!(
        u32::from_le_bytes(
            commit[PREVIOUS_CRC_OFFSET..PREVIOUS_CRC_OFFSET + 4]
                .try_into()
                .unwrap()
        ),
        prepare_crc
    );
    assert_eq!(
        u32::from_le_bytes(
            commit[COMMIT_PREPARE_CRC_OFFSET..COMMIT_PREPARE_CRC_OFFSET + 4]
                .try_into()
                .unwrap()
        ),
        prepare_crc
    );

    log.sectors.extend([prepare, commit]);
    assert_eq!(
        recover_with(&log.sectors, &[root]),
        Err(RecoveryError::SealedRecord {
            sector: 2,
            source: DecodeError::UnknownRights,
        })
    );
}

#[test]
fn write_flush_publish_and_revoke_ack_boundaries_are_ordered() {
    let root = root_grant(10, 20, 0, 0);
    let mut base = TestLog::formatted();
    let prepare = base
        .chain
        .append(Some(tx(30)), RecordBody::GrantPrepare(root.clone()))
        .unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(&prepare).unwrap() else {
        unreachable!()
    };
    base.sectors.push(prepare);
    let commit = base
        .chain
        .append(
            Some(tx(30)),
            RecordBody::GrantCommit {
                prepare_sequence: decoded.record.sequence,
                prepare_crc32c: decoded.crc32c,
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();

    for cut in 0..=RECORD_SIZE {
        for flush_requested in [false, true] {
            // The media contract permits flush success only after a complete write.
            let flush_succeeded = flush_requested && cut == RECORD_SIZE;
            let mut image = base.sectors.clone();
            image.push(prefix(&commit, cut));
            let recovered = recover_with(&image, core::slice::from_ref(&root)).unwrap();
            let live_published = flush_succeeded;
            assert!(recovered.grants.len() <= 1);
            if live_published {
                assert_eq!(recovered.grants.len(), 1);
            }
        }
    }

    base.sectors.push(commit);
    let tombstone = base
        .chain
        .append(
            Some(tx(31)),
            RecordBody::RevokeTombstone {
                derivation_id: root.derivation_id,
            },
        )
        .unwrap();
    for cut in 0..=RECORD_SIZE {
        for flush_requested in [false, true] {
            let revoke_acknowledged = flush_requested && cut == RECORD_SIZE;
            let mut image = base.sectors.clone();
            image.push(prefix(&tombstone, cut));
            let recovered = recover_with(&image, core::slice::from_ref(&root)).unwrap();
            if revoke_acknowledged {
                assert!(recovered.grants.is_empty());
            }
        }
    }
}

#[test]
fn valid_records_can_chain_around_a_permanently_torn_physical_slot() {
    let mut chain = RecordChain::new(store());
    let format = chain.append(None, RecordBody::Format).unwrap();
    let DecodeStatus::Valid(decoded_format) = LogRecord::decode(&format).unwrap() else {
        unreachable!()
    };
    let high = LogRecord {
        store_id: store(),
        transaction_id: None,
        sequence: 2,
        previous_sequence: 1,
        previous_crc32c: decoded_format.crc32c,
        body: RecordBody::IdHighWater {
            exclusive_end: HIGH_WATER,
        },
    }
    .encode()
    .unwrap();
    let image = [format, prefix(&high, 173), high];
    let recovered = recover_with(&image, &[]).unwrap();
    assert_eq!(recovered.last_sequence, 2);
    assert_eq!(recovered.id_high_water, HIGH_WATER);
}

#[test]
fn a_valid_but_broken_chain_and_wrong_store_are_rejected() {
    let mut chain = RecordChain::new(store());
    let format = chain.append(None, RecordBody::Format).unwrap();
    let broken = LogRecord {
        store_id: store(),
        transaction_id: None,
        sequence: 3,
        previous_sequence: 1,
        previous_crc32c: u32::from_le_bytes(format[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap()),
        body: RecordBody::IdHighWater {
            exclusive_end: HIGH_WATER,
        },
    }
    .encode()
    .unwrap();
    assert_eq!(
        recover_with(&[format, broken], &[]),
        Err(RecoveryError::BrokenSequence { sector: 1 })
    );

    let other_store = StoreId::new(9001).unwrap();
    let wrong = LogRecord {
        store_id: other_store,
        transaction_id: None,
        sequence: 1,
        previous_sequence: 0,
        previous_crc32c: 0,
        body: RecordBody::Format,
    }
    .encode()
    .unwrap();
    assert_eq!(
        recover_with(&[wrong], &[]),
        Err(RecoveryError::WrongStore { sector: 0 })
    );
}

fn root_grant_for_object(
    id: u128,
    object_id: u128,
    space_id: u128,
    slot: u32,
    generation: u64,
) -> GrantRecord {
    GrantRecord {
        derivation_id: deriv(id),
        parent_id: None,
        object_id: object(object_id),
        target: SlotIdentity {
            space: space(space_id),
            slot,
            generation,
        },
        rights: DurableRights::ALL,
        resource_kind: kind(7),
        flags: GrantFlags::ROOT,
    }
}

fn okind(value: u32) -> ObjectKind {
    ObjectKind::new(value).unwrap()
}

/// A replace-style history: object versions whose grants were tombstoned are
/// the reclaimable garbage; live closures, slot generation history, and
/// ungranted (runtime-transient) objects must survive compaction verbatim.
fn replace_style_log() -> TestLog {
    let mut log = TestLog::formatted();
    // The long-lived root object and its live grant chain.
    log.object(tx(501), object(100), okind(40), b"root-object");
    log.grant(tx(502), root_grant_for_object(10, 100, 1, 1, 1));
    log.tombstone(tx(503), deriv(10));
    log.grant(tx(504), root_grant_for_object(11, 100, 1, 1, 2));
    log.grant(tx(505), child_grant(12, 11, 2, 7));
    // A dead derived branch under the live root.
    log.grant(tx(506), child_grant(13, 11, 2, 8));
    log.tombstone(tx(507), deriv(13));
    // Replace pattern: version 1 fully dead, version 2 live.
    log.object(tx(520), object(200), okind(41), b"replaced-v1");
    log.grant(tx(521), root_grant_for_object(14, 200, 1, 5, 1));
    log.tombstone(tx(522), deriv(14));
    log.object(tx(523), object(201), okind(41), b"replaced-v2");
    log.grant(tx(524), root_grant_for_object(15, 201, 1, 5, 2));
    // A slot whose final holder is dead: its generation must stay burned.
    log.object(tx(530), object(210), okind(42), b"dead-slot-object");
    log.grant(tx(531), root_grant_for_object(16, 210, 1, 9, 1));
    log.tombstone(tx(532), deriv(16));
    // A never-granted (runtime-transient) object.
    log.object(tx(533), object(300), okind(43), b"ungranted");
    log
}

#[test]
fn compaction_drops_dead_closures_and_keeps_equivalent_state() {
    let log = replace_style_log();
    let original = preflight_recovery(&log.sectors, store()).unwrap();
    let compacted = original.compact(false).unwrap();
    assert!(
        compacted.len() < log.sectors.len(),
        "compaction must shrink this history ({} -> {})",
        log.sectors.len(),
        compacted.len(),
    );
    let recovered = preflight_recovery(&compacted, store()).unwrap();
    assert_eq!(recovered.id_high_water(), HIGH_WATER);
    let object_ids: Vec<u128> = recovered
        .committed_objects()
        .iter()
        .map(|object| object.object_id.get())
        .collect();
    // Replaced version 1 is gone; everything reachable or transient stays.
    assert_eq!(object_ids, vec![100, 201, 210, 300]);
    // The dead slot 9 keeps its burned generation: a fresh grant reusing
    // generation 1 on that slot must still be rejected.
    let mut reuse = RecordChain::from_checkpoint(
        store(),
        preflight_recovery(&compacted, store())
            .unwrap()
            .chain_checkpoint()
            .unwrap(),
    )
    .unwrap();
    let mut sectors = compacted.clone();
    let grant = root_grant_for_object(17, 210, 1, 9, 1);
    let (prepare, commit);
    {
        let bytes = reuse
            .append(Some(tx(560)), RecordBody::GrantPrepare(grant.clone()))
            .unwrap();
        let DecodeStatus::Valid(decoded) = LogRecord::decode(&bytes).unwrap() else {
            panic!("prepare must decode");
        };
        prepare = (decoded.record.sequence, decoded.crc32c);
        sectors.push(bytes);
        commit = reuse
            .append(
                Some(tx(560)),
                RecordBody::GrantCommit {
                    prepare_sequence: prepare.0,
                    prepare_crc32c: prepare.1,
                    derivation_id: grant.derivation_id,
                },
            )
            .unwrap();
        sectors.push(commit);
    }
    assert!(matches!(
        preflight_recovery(&sectors, store()),
        Err(RecoveryError::SlotGeneration { .. })
    ));
}

#[test]
fn boot_compaction_may_drop_only_ungranted_objects() {
    let log = replace_style_log();
    let original = preflight_recovery(&log.sectors, store()).unwrap();
    let compacted = original.compact(true).unwrap();
    let recovered = preflight_recovery(&compacted, store()).unwrap();
    let object_ids: Vec<u128> = recovered
        .committed_objects()
        .iter()
        .map(|object| object.object_id.get())
        .collect();
    assert_eq!(object_ids, vec![100, 201, 210]);
}

#[test]
fn boot_compaction_retains_only_exact_ungranted_witnesses() {
    let log = replace_style_log();
    let original = preflight_recovery(&log.sectors, store()).unwrap();
    let attachment = original
        .committed_objects()
        .iter()
        .find(|candidate| candidate.object_id == object(300))
        .unwrap()
        .clone();
    let compacted = original
        .compact_with_exact_ungranted(core::slice::from_ref(&attachment))
        .unwrap();
    let recovered = preflight_recovery(&compacted, store()).unwrap();
    let object_ids: Vec<u128> = recovered
        .committed_objects()
        .iter()
        .map(|object| object.object_id.get())
        .collect();
    assert_eq!(object_ids, vec![100, 201, 210, 300]);

    let mut substituted = attachment.clone();
    substituted.bytes[0] ^= 1;
    assert_eq!(
        original.compact_with_exact_ungranted(&[substituted]),
        Err(RecoveryError::CompactionMismatch)
    );
    let historically_granted = original
        .committed_objects()
        .iter()
        .find(|candidate| candidate.object_id == object(200))
        .unwrap()
        .clone();
    assert_eq!(
        original.compact_with_exact_ungranted(&[historically_granted]),
        Err(RecoveryError::CompactionMismatch)
    );
    assert_eq!(
        original.compact_with_exact_ungranted(&[attachment.clone(), attachment]),
        Err(RecoveryError::CompactionMismatch)
    );
}

#[test]
fn compaction_is_idempotent_and_preserves_root_selection() {
    let log = replace_style_log();
    let original = preflight_recovery(&log.sectors, store()).unwrap();
    let once = original.compact(false).unwrap();
    let twice = preflight_recovery(&once, store())
        .unwrap()
        .compact(false)
        .unwrap();
    assert_eq!(once, twice, "a second compaction must change nothing");

    // Root policy selection sees the same unique live roots before and after.
    let constraint = RootConstraint {
        space: space(1),
        first_slot: 1,
        last_slot_inclusive: 1,
        rights: RootRightsConstraint::exact(DurableRights::ALL),
        resource_kind: kind(7),
        object_kind: okind(40),
    };
    let original_roots = original.select_roots(&[constraint]).unwrap();
    let compacted_roots = preflight_recovery(&once, store())
        .unwrap()
        .select_roots(&[constraint])
        .unwrap();
    assert_eq!(original_roots, compacted_roots);
    assert_eq!(
        original_roots[0].grant.derivation_id,
        deriv(11),
        "the live replacement root is the selected one",
    );
}

#[test]
fn external_object_records_recover_compact_and_fail_closed() {
    let mut log = TestLog::formatted();
    let merkle_root = [0x5a; 32];
    log.push(
        Some(tx(700)),
        RecordBody::ObjectExternal {
            object_id: object(400),
            object_kind: okind(50),
            byte_len: 16 * 1024 * 1024,
            merkle_root,
        },
    );
    let preflight = preflight_recovery(&log.sectors, store()).unwrap();
    let recovered = &preflight.committed_objects()[0];
    assert_eq!(recovered.object_id, object(400));
    assert_eq!(recovered.byte_len(), 16 * 1024 * 1024);
    assert_eq!(recovered.external_root, Some(merkle_root));
    assert!(recovered.bytes.is_empty());
    assert!(recovered.is_external());

    // The canonical record round-trips exactly.
    let bytes = log.sectors.last().unwrap();
    let DecodeStatus::Valid(decoded) = LogRecord::decode(bytes).unwrap() else {
        panic!("external record must decode");
    };
    assert_eq!(decoded.record.encode().unwrap(), *bytes);

    // A second commit reusing the stable object id is rejected.
    let mut duplicate = log.sectors.clone();
    duplicate.push(
        RecordChain::from_checkpoint(store(), preflight.chain_checkpoint().unwrap())
            .unwrap()
            .append(
                Some(tx(701)),
                RecordBody::ObjectExternal {
                    object_id: object(400),
                    object_kind: okind(50),
                    byte_len: 4096,
                    merkle_root,
                },
            )
            .unwrap(),
    );
    assert!(matches!(
        preflight_recovery(&duplicate, store()),
        Err(RecoveryError::DuplicateObject { .. })
    ));

    // Runtime compaction keeps the ungranted external object; boot
    // compaction sheds it like any other runtime-transient object.
    let kept = preflight.compact(false).unwrap();
    let kept = preflight_recovery(&kept, store()).unwrap();
    assert_eq!(kept.committed_objects().len(), 1);
    assert_eq!(kept.committed_objects()[0].external_root, Some(merkle_root));
    assert_eq!(kept.committed_objects()[0].byte_len(), 16 * 1024 * 1024);
    let shed = preflight.compact(true).unwrap();
    assert!(preflight_recovery(&shed, store())
        .unwrap()
        .committed_objects()
        .is_empty());

    // Declared identities outside the envelope fail to encode.
    let mut chain = RecordChain::new(store());
    let _ = chain.append(None, RecordBody::Format).unwrap();
    assert!(chain
        .append(
            Some(tx(1)),
            RecordBody::ObjectExternal {
                object_id: object(2),
                object_kind: okind(50),
                byte_len: 64 * 1024 * 1024 + 1,
                merkle_root,
            },
        )
        .is_err());
    assert!(chain
        .append(
            Some(tx(1)),
            RecordBody::ObjectExternal {
                object_id: object(2),
                object_kind: okind(50),
                byte_len: 4096,
                merkle_root: [0; 32],
            },
        )
        .is_err());
}

#[test]
fn incremental_replay_equals_whole_stream_recovery_at_every_cut() {
    use vibeos_durable_format::PreflightReplay;
    let log = replace_style_log();
    let whole = preflight_recovery(&log.sectors, store()).unwrap();
    for cut in 0..=log.sectors.len() {
        let mut replay = PreflightReplay::new(store());
        replay.append(&log.sectors[..cut]).unwrap();
        replay.append(&log.sectors[cut..]).unwrap();
        assert_eq!(replay.record_count(), log.sectors.len() as u64, "cut {cut}");
        let split = replay.finish().unwrap();
        assert_eq!(split.id_high_water(), whole.id_high_water(), "cut {cut}");
        assert_eq!(split.last_sequence(), whole.last_sequence(), "cut {cut}");
        assert_eq!(split.last_crc32c(), whole.last_crc32c(), "cut {cut}");
        assert_eq!(
            split.chain_checkpoint().unwrap(),
            whole.chain_checkpoint().unwrap(),
            "cut {cut}"
        );
        let ids = |p: &vibeos_durable_format::RecoveryPreflight| -> Vec<(u128, u64)> {
            p.committed_objects()
                .iter()
                .map(|object| (object.object_id.get(), object.commit_sequence))
                .collect()
        };
        assert_eq!(ids(&split), ids(&whole), "cut {cut}");
        assert_eq!(
            split.committed_grants().len(),
            whole.committed_grants().len(),
            "cut {cut}"
        );
        assert_eq!(split.slots().len(), whole.slots().len(), "cut {cut}");
    }
    // A failed append poisons the builder fail-closed.
    let mut poisoned = PreflightReplay::new(store());
    poisoned.append(&log.sectors).unwrap();
    let mut broken = log.sectors[3];
    broken[0] ^= 0xff;
    assert!(poisoned.append(&[broken]).is_err());
    assert!(matches!(
        poisoned.append(&log.sectors[..1]),
        Err(vibeos_durable_format::RecoveryError::ReplayPoisoned)
    ));
    assert!(matches!(
        poisoned.finish(),
        Err(vibeos_durable_format::RecoveryError::ReplayPoisoned)
    ));
}
