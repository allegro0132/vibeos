//! Durable root-policy composition and tombstone partition tests.

use vibeos_durable_format::{
    encode_object_transaction, partition_tombstones_by_space, preflight_recovery,
    preview_grant_transaction, select_root_policy_union, DerivationId, DurableRights, GrantFlags,
    GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain, RecoveredGrant, RecoveryError,
    ResourceKind, RootConstraint, RootPolicyPartition, RootRightsConstraint, SlotIdentity, SpaceId,
    StoreId, TombstonePartition, TombstonePartitionError, TransactionId,
};

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
    let program_space = SpaceId::new(0x5052_4f47).unwrap();
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
    let program_space = SpaceId::new(0x5052_4f47).unwrap();
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
