use vibeos_core::program::{
    partition_tombstones_by_space, program_root_constraint, program_root_policy_is_exact,
    select_root_policy_union, sha256, ProgramArtifact, ProgramArtifactError, RootPolicyPartition,
    TombstonePartition, TombstonePartitionError, MAX_PROGRAM_EXECUTABLE_BYTES, PROGRAM_ALIAS,
    PROGRAM_ARTIFACT_HEADER_LEN, PROGRAM_ROOT_GENERATION, PROGRAM_ROOT_RIGHTS, PROGRAM_ROOT_SLOT,
};
use vibeos_durable_format::encode_object_transaction;
use vibeos_durable_format::{
    preflight_recovery, preview_grant_transaction, DerivationId, DurableRights, GrantFlags,
    GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain, RecoveredGrant, RecoveryError,
    ResourceKind, RootConstraint, RootPolicy, RootRightsConstraint, SlotIdentity, SpaceId, StoreId,
    TransactionId,
};

fn artifact() -> ProgramArtifact {
    ProgramArtifact::new("fn main() { println!(\"hello\"); }\n", b"VIBEEXE\0fixture").unwrap()
}

#[test]
fn sha256_matches_standard_vectors() {
    assert_eq!(
        sha256(b""),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn artifact_is_deterministic_canonical_and_round_trips() {
    let first = artifact().encode();
    let second = artifact().encode();
    assert_eq!(first, second);
    let decoded = ProgramArtifact::decode(&first).unwrap();
    assert_eq!(decoded, artifact());
    assert_eq!(decoded.encode(), first);
}

#[test]
fn every_strict_prefix_and_trailing_suffix_is_rejected() {
    let encoded = artifact().encode();
    for end in 0..encoded.len() {
        assert!(
            ProgramArtifact::decode(&encoded[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    for extra in 1..=16 {
        let mut extended = encoded.clone();
        extended.resize(extended.len() + extra, 0);
        assert!(ProgramArtifact::decode(&extended).is_err());
    }
}

#[test]
fn header_authority_reserved_and_hash_mutations_fail_closed() {
    let encoded = artifact().encode();
    for offset in [
        0usize, 8, 10, 12, 16, 20, 24, 28, 32, 64, 96, 100, 104, 108, 112, 116, 120, 122, 124, 128,
        132, 134, 136, 141, 151, 159,
    ] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(
            ProgramArtifact::decode(&corrupted).is_err(),
            "accepted mutation at {offset}"
        );
    }
    let body = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
    for offset in [body, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(ProgramArtifact::decode(&corrupted).is_err());
    }
}

#[test]
fn fixed_program_root_constraint_matches_the_artifact_slot() {
    let constraint = program_root_constraint();
    assert_eq!(constraint.space, vibeos_core::program::program_space_id());
    assert_eq!(constraint.first_slot, PROGRAM_ROOT_SLOT);
    assert_eq!(constraint.last_slot_inclusive, PROGRAM_ROOT_SLOT);
    assert_eq!(
        constraint.rights,
        RootRightsConstraint::exact(PROGRAM_ROOT_RIGHTS)
    );
    assert_eq!(PROGRAM_ALIAS, "hello");

    let exact = RootPolicy {
        grant: GrantRecord {
            derivation_id: DerivationId::new(1).unwrap(),
            parent_id: None,
            object_id: ObjectId::new(2).unwrap(),
            target: SlotIdentity {
                space: constraint.space,
                slot: PROGRAM_ROOT_SLOT,
                generation: PROGRAM_ROOT_GENERATION,
            },
            rights: PROGRAM_ROOT_RIGHTS,
            resource_kind: constraint.resource_kind,
            flags: GrantFlags::ROOT,
        },
    };
    assert!(program_root_policy_is_exact(&exact));
    let mut reused = exact;
    reused.grant.target.generation = 1;
    assert!(!program_root_policy_is_exact(&reused));
}

#[test]
fn global_root_policy_union_is_partitioned_by_space_and_complete() {
    let (preflight, first, second) = two_root_preflight();
    let partitions = [
        RootPolicyPartition {
            space: first.space,
            constraints: core::slice::from_ref(&first),
        },
        RootPolicyPartition {
            space: second.space,
            constraints: core::slice::from_ref(&second),
        },
    ];
    let roots = select_root_policy_union(&preflight, &partitions).unwrap();
    assert_eq!(roots.len(), 2);
    assert_eq!(preflight.clone().finish(&roots).unwrap().grants.len(), 2);

    // A subsystem-local policy is not sufficient for a shared journal: finish
    // still sees the other live root and fails closed.
    let local = preflight
        .select_roots(core::slice::from_ref(&first))
        .unwrap();
    assert!(matches!(
        preflight.clone().finish(&local),
        Err(RecoveryError::RootNotTrusted { .. })
    ));

    let duplicate_space = [partitions[0], partitions[0]];
    assert_eq!(
        select_root_policy_union(&preflight, &duplicate_space),
        Err(RecoveryError::InvalidRootConstraint)
    );
    let wrong_owner = [RootPolicyPartition {
        space: second.space,
        constraints: core::slice::from_ref(&first),
    }];
    assert_eq!(
        select_root_policy_union(&preflight, &wrong_owner),
        Err(RecoveryError::InvalidRootConstraint)
    );
    let overlapping = RootConstraint {
        last_slot_inclusive: first.last_slot_inclusive + 1,
        ..first
    };
    let overlap_constraints = [first, overlapping];
    let overlap_partition = [RootPolicyPartition {
        space: first.space,
        constraints: &overlap_constraints,
    }];
    assert_eq!(
        select_root_policy_union(&preflight, &overlap_partition),
        Err(RecoveryError::InvalidRootConstraint)
    );
}

#[test]
fn mixed_authority_tombstones_are_partitioned_by_original_grant_space() {
    let persistent_space = SpaceId::new(0x5053).unwrap();
    let program_space = vibeos_core::program::program_space_id();
    let persistent_root = test_recovered_grant(20, None, persistent_space, 0, GrantFlags::ROOT);
    let persistent_child = test_recovered_grant(
        21,
        Some(persistent_root.grant.derivation_id),
        persistent_space,
        1,
        GrantFlags::DERIVED,
    );
    let program_root = test_recovered_grant(22, None, program_space, 0, GrantFlags::ROOT);
    let committed = [persistent_root, persistent_child, program_root];

    let partitions = partition_tombstones_by_space(
        &committed,
        &[committed[0].grant.derivation_id],
        &[persistent_space, program_space],
    )
    .unwrap();
    assert_eq!(
        partitions,
        vec![
            TombstonePartition {
                space: persistent_space,
                tombstones: vec![committed[0].grant.derivation_id],
            },
            TombstonePartition {
                space: program_space,
                tombstones: Vec::new(),
            },
        ]
    );
}

#[test]
fn tombstone_partition_rejects_unknown_foreign_and_cross_space_authority() {
    let persistent_space = SpaceId::new(0x5053).unwrap();
    let program_space = vibeos_core::program::program_space_id();
    let root = test_recovered_grant(30, None, persistent_space, 0, GrantFlags::ROOT);
    assert_eq!(
        partition_tombstones_by_space(
            core::slice::from_ref(&root),
            &[DerivationId::new(99).unwrap()],
            &[persistent_space, program_space],
        ),
        Err(TombstonePartitionError::UnknownDerivation)
    );

    let foreign =
        test_recovered_grant(31, None, SpaceId::new(0xdead).unwrap(), 0, GrantFlags::ROOT);
    assert_eq!(
        partition_tombstones_by_space(&[foreign], &[], &[persistent_space, program_space]),
        Err(TombstonePartitionError::ForeignSpace)
    );

    let cross_space_child = test_recovered_grant(
        32,
        Some(root.grant.derivation_id),
        program_space,
        1,
        GrantFlags::DERIVED,
    );
    assert_eq!(
        partition_tombstones_by_space(
            &[root, cross_space_child],
            &[],
            &[persistent_space, program_space],
        ),
        Err(TombstonePartitionError::CrossSpaceDerivation)
    );
}

fn test_recovered_grant(
    derivation: u128,
    parent_id: Option<DerivationId>,
    space: SpaceId,
    slot: u32,
    flags: GrantFlags,
) -> RecoveredGrant {
    RecoveredGrant {
        grant: GrantRecord {
            derivation_id: DerivationId::new(derivation).unwrap(),
            parent_id,
            object_id: ObjectId::new(0x7000).unwrap(),
            target: SlotIdentity {
                space,
                slot,
                generation: 0,
            },
            rights: DurableRights::READ,
            resource_kind: ResourceKind::new(0x7001).unwrap(),
            flags,
        },
        transaction_id: TransactionId::new(derivation + 100).unwrap(),
        prepare_sequence: derivation as u64,
        commit_sequence: derivation as u64 + 1,
    }
}

fn two_root_preflight() -> (
    vibeos_durable_format::RecoveryPreflight,
    RootConstraint,
    RootConstraint,
) {
    let store = StoreId::new(0xfeed).unwrap();
    let object_a = ObjectId::new(1).unwrap();
    let object_b = ObjectId::new(2).unwrap();
    let object_tx_a = TransactionId::new(3).unwrap();
    let object_tx_b = TransactionId::new(4).unwrap();
    let grant_tx_a = TransactionId::new(5).unwrap();
    let grant_tx_b = TransactionId::new(6).unwrap();
    let derivation_a = DerivationId::new(7).unwrap();
    let derivation_b = DerivationId::new(8).unwrap();
    let space_a = SpaceId::new(9).unwrap();
    let space_b = SpaceId::new(10).unwrap();
    let kind_a = ObjectKind::new(0x1001).unwrap();
    let kind_b = ObjectKind::new(0x1002).unwrap();
    let resource_kind = ResourceKind::new(0x2001).unwrap();

    let mut chain = RecordChain::new(store);
    let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
    sectors.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end: 11 })
            .unwrap(),
    );
    sectors.extend(
        encode_object_transaction(&mut chain, object_tx_a, object_a, kind_a, b"a")
            .unwrap()
            .records,
    );
    sectors.extend(
        encode_object_transaction(&mut chain, object_tx_b, object_b, kind_b, b"b")
            .unwrap()
            .records,
    );
    let grant_a = GrantRecord {
        derivation_id: derivation_a,
        parent_id: None,
        object_id: object_a,
        target: SlotIdentity {
            space: space_a,
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind,
        flags: GrantFlags::ROOT,
    };
    let grant_b = GrantRecord {
        derivation_id: derivation_b,
        parent_id: None,
        object_id: object_b,
        target: SlotIdentity {
            space: space_b,
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind,
        flags: GrantFlags::ROOT,
    };
    let (encoded, next) = preview_grant_transaction(&chain, grant_tx_a, grant_a).unwrap();
    sectors.extend(encoded.records);
    chain = next;
    let (encoded, _next) = preview_grant_transaction(&chain, grant_tx_b, grant_b).unwrap();
    sectors.extend(encoded.records);

    let first = RootConstraint {
        space: space_a,
        first_slot: 0,
        last_slot_inclusive: 0,
        rights: RootRightsConstraint::exact(DurableRights::READ),
        resource_kind,
        object_kind: kind_a,
    };
    let second = RootConstraint {
        space: space_b,
        first_slot: 0,
        last_slot_inclusive: 0,
        rights: RootRightsConstraint::exact(DurableRights::READ),
        resource_kind,
        object_kind: kind_b,
    };
    (preflight_recovery(&sectors, store).unwrap(), first, second)
}

#[test]
fn invalid_utf8_empty_fields_and_limits_are_rejected() {
    assert_eq!(
        ProgramArtifact::new("", b"x"),
        Err(ProgramArtifactError::EmptySource)
    );
    assert_eq!(
        ProgramArtifact::new("x", b""),
        Err(ProgramArtifactError::EmptyExecutable)
    );
    assert!(ProgramArtifact::new("x", &vec![0; MAX_PROGRAM_EXECUTABLE_BYTES + 1]).is_err());

    let mut encoded = artifact().encode();
    let body = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
    encoded[body] = 0xff;
    let source_hash = sha256(
        &encoded[body..body + u32::from_le_bytes(encoded[20..24].try_into().unwrap()) as usize],
    );
    encoded[32..64].copy_from_slice(&source_hash);
    assert_eq!(
        ProgramArtifact::decode(&encoded),
        Err(ProgramArtifactError::Utf8)
    );
}

fn hex(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}
