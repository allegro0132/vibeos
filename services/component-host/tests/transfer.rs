use std::any::Any;
use std::sync::Arc;

use vibeos_component_host::{
    install_persistent_proxy_owned, prepare_owned_supervised, revoke_owned_supervised,
    transfer_owned, with_supervised_borrow, AuthorityClass, AuthorityError, ComponentAuthority,
    ComponentAuthoritySpace, ComponentHostResource, HostResourceKind, OwnedTransferError,
    SharedCSpace, SupervisedBorrowError, SupervisedRevokeError,
};
use vibeos_component_runtime::resource::{ResourceError, ResourceTable, ResourceTypeId};
use vibeos_core::cap::{CSpace, Cap, PersistentDerivationWitness, Resource, Rights};
use vibeos_core::heap::{AllocationDomain, ArenaId, OwnerId};
use vibeos_core::instance::{InstanceRegistry, PairTransferError};
use vibeos_core::sync::SpinLock;
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, ResourceKind, SpaceId,
};

const SOURCE_TYPE: ResourceTypeId = ResourceTypeId(11);
const TARGET_TYPE: ResourceTypeId = ResourceTypeId(21);

struct Probe(u32);
struct OtherProbe;

impl Resource for Probe {
    fn kind(&self) -> &'static str {
        "owned-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for Probe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

impl Resource for OtherProbe {
    fn kind(&self) -> &'static str {
        "other-owned-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for OtherProbe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Clock;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

fn space(name: &str) -> (SharedCSpace, ComponentAuthoritySpace) {
    let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
    let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    (cspace, binding)
}

fn source(
    rights: Rights,
) -> (
    SharedCSpace,
    ComponentAuthoritySpace,
    Cap,
    ResourceTable<ComponentAuthority>,
    vibeos_component_runtime::resource::ResourceToken,
) {
    let (cspace, binding) = space("owned-source");
    let cap = cspace.lock().mint(Arc::new(Probe(42)), rights);
    let authority = binding.bind_ephemeral::<Probe>(cap, rights).unwrap();
    let mut table = ResourceTable::new(1, 2).unwrap();
    let token = table.insert_owned(SOURCE_TYPE, authority).unwrap();
    (cspace, binding, cap, table, token)
}

fn persistent_probe() -> (SharedCSpace, Cap, PersistentDerivationWitness<Probe>) {
    let mut cspace = CSpace::new_persistent("durable-transfer-probe", SpaceId::new(0x701).unwrap());
    let reservation = cspace
        .reserve_persistent_slot(cspace.incarnation())
        .unwrap();
    let grant = GrantRecord {
        derivation_id: DerivationId::new(0x702).unwrap(),
        parent_id: None,
        object_id: ObjectId::new(0x703).unwrap(),
        target: reservation.target(),
        rights: DurableRights::READ
            .union(DurableRights::GRANT)
            .union(DurableRights::REVOKE),
        resource_kind: ResourceKind::new(0x704).unwrap(),
        flags: GrantFlags::ROOT,
    };
    let (cap, witness) = cspace
        .install_reserved_root(&reservation, &grant, Arc::new(Probe(314)))
        .unwrap();
    (Arc::new(SpinLock::new(cspace)), cap, witness)
}

fn reserved_supervised_source(
    seed: u64,
    value: u32,
) -> (
    InstanceRegistry,
    [vibeos_core::instance::InstanceToken; 2],
    Cap,
    Cap,
    ResourceTable<ComponentAuthority>,
    vibeos_component_runtime::resource::ResourceToken,
) {
    let registry = InstanceRegistry::new();
    let domains = [
        AllocationDomain::new(OwnerId::new(seed), ArenaId::new(seed + 1)),
        AllocationDomain::new(OwnerId::new(seed + 2), ArenaId::new(seed + 3)),
    ];
    let tokens = registry
        .reserve_named_batch(&[
            (domains[0], "staged-host-source"),
            (domains[1], "staged-host-target"),
        ])
        .unwrap();
    let tokens = [tokens[0], tokens[1]];
    let mut source_table = ResourceTable::new(seed, 2).unwrap();
    let source_reservation = source_table.reserve().unwrap();
    let (ancestor, source_cap, prepared) =
        unsafe {
            registry
                .configure_reserved_space(tokens[0], |source| {
                    let ancestor = source.mint(
                        Arc::new(Probe(value)),
                        Rights::READ.union(Rights::GRANT).union(Rights::REVOKE),
                    );
                    let source_cap = source
                        .derive(ancestor, Rights::READ.union(Rights::GRANT))
                        .unwrap();
                    let prepared = ComponentAuthority::prepare_supervised_ephemeral_source_in::<
                        Probe,
                    >(source, source_cap, Rights::READ)
                    .unwrap();
                    (ancestor, source_cap, prepared)
                })
                .unwrap()
        };
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedSupervisedEphemeralSource(<redacted>)"
    );
    let source_token = source_reservation.commit(SOURCE_TYPE, prepared.into_authority());
    (
        registry,
        tokens,
        ancestor,
        source_cap,
        source_table,
        source_token,
    )
}

#[test]
fn cross_space_owned_transfer_requires_supervisor_and_changes_nothing() {
    let (source_cspace, source_binding, source_cap, mut source_table, source_token) =
        source(Rights::READ);
    let (target_space, target_binding) = space("owned-target");
    let mut target_table = ResourceTable::new(2, 2).unwrap();

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::CrossSpaceSupervisorRequired),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert_eq!(source_cspace.lock().list().len(), 1);
    assert!(target_space.lock().list().is_empty());
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
    assert_eq!(
        source_table
            .with_borrow(source_token, SOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    authority.with_revocable::<Probe, _, _>(&source_cspace, Rights::READ, |probe| {
                        probe.0
                    })
                })
            })
            .unwrap(),
        Ok(42),
    );
}

#[test]
fn cross_space_refusal_preserves_ancestor_revocation_and_source_ownership() {
    let (source_cspace, source_binding) = space("derived-source");
    let ancestor = source_cspace.lock().mint(
        Arc::new(Probe(91)),
        Rights::READ.union(Rights::GRANT).union(Rights::REVOKE),
    );
    let child = source_cspace.lock().derive(ancestor, Rights::READ).unwrap();
    let authority = source_binding
        .bind_ephemeral::<Probe>(child, Rights::READ)
        .unwrap();
    let mut source_table = ResourceTable::new(8, 2).unwrap();
    let source_token = source_table.insert_owned(SOURCE_TYPE, authority).unwrap();
    let (target_cspace, target_binding) = space("derived-target");
    let mut target_table = ResourceTable::new(9, 2).unwrap();

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::CrossSpaceSupervisorRequired),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert!(target_cspace.lock().list().is_empty());
    assert_eq!(
        source_table
            .with_borrow(source_token, SOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    authority.with_revocable::<Probe, _, _>(&source_cspace, Rights::READ, |probe| {
                        probe.0
                    })
                })
            })
            .unwrap(),
        Ok(91),
    );

    assert_eq!(source_cspace.lock().revoke(ancestor).unwrap(), 2);
    assert_eq!(
        source_table
            .with_borrow(source_token, SOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    authority.with_revocable::<Probe, _, _>(&source_cspace, Rights::READ, |_| ())
                })
            })
            .unwrap(),
        Err(AuthorityError::InvalidOrRevoked),
    );
}

#[test]
fn same_space_owned_transfer_is_linear_and_not_copied_between_tables() {
    let (cspace, source_binding, _, mut source_table, source_token) = source(Rights::READ);
    let target_binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    let mut target_table = ResourceTable::new(3, 2).unwrap();

    let target_token = transfer_owned::<Probe>(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &source_binding,
        &mut target_table,
        TARGET_TYPE,
        &target_binding,
        Rights::READ,
    )
    .unwrap();
    assert!(source_table.is_empty());
    assert_eq!(target_table.len(), 1);
    assert_eq!(target_table.contains(target_token, TARGET_TYPE), Ok(true));
    let listed = cspace.lock().list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].2, Rights::READ);
}

#[test]
fn same_space_wrong_type_and_overrights_leave_source_ownership_intact() {
    let (source_cspace, source_binding, source_cap, mut source_table, source_token) =
        source(Rights::READ);
    let target_binding = ComponentAuthoritySpace::new(source_cspace.clone(), 1).unwrap();
    let mut target_table = ResourceTable::new(4, 2).unwrap();
    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            ResourceTypeId(SOURCE_TYPE.0 + 1),
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::SourceTable(ResourceError::WrongType)),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::WRITE,
        ),
        Err(OwnedTransferError::Authority(
            AuthorityError::RightsExceedCeiling,
        )),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
}

#[test]
fn same_space_stale_target_route_leaves_fresh_source_ownership_intact() {
    let (cspace, stale_target_binding) = space("stale-target");
    assert_eq!(cspace.lock().reset(), 0);
    let source_binding = ComponentAuthoritySpace::new(cspace.clone(), 2).unwrap();
    let source_cap = cspace.lock().mint(Arc::new(Probe(73)), Rights::READ);
    let authority = source_binding
        .bind_ephemeral::<Probe>(source_cap, Rights::READ)
        .unwrap();
    let mut source_table = ResourceTable::new(10, 2).unwrap();
    let source_token = source_table.insert_owned(SOURCE_TYPE, authority).unwrap();
    let mut target_table = ResourceTable::new(11, 2).unwrap();

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &stale_target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::Authority(
            AuthorityError::IncarnationMismatch,
        )),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert!(cspace.lock().lookup(source_cap, Rights::READ).is_ok());
}

#[test]
fn cross_space_refusal_precedes_table_validation_and_capacity() {
    let (source_cspace, source_binding, source_cap, mut source_table, source_token) =
        source(Rights::READ);
    let (target_space, target_binding) = space("full-target");
    let existing_cap = target_space.lock().mint(Arc::new(Probe(7)), Rights::READ);
    let existing = target_binding
        .bind_ephemeral::<Probe>(existing_cap, Rights::READ)
        .unwrap();
    let mut target_table = ResourceTable::new(5, 1).unwrap();
    target_table.insert_owned(TARGET_TYPE, existing).unwrap();
    let target_caps_before = target_space.lock().list().len();

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            ResourceTypeId(SOURCE_TYPE.0 + 1),
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::CrossSpaceSupervisorRequired),
    );
    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::CrossSpaceSupervisorRequired),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert_eq!(target_table.len(), 1);
    assert_eq!(target_space.lock().list().len(), target_caps_before);
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
}

#[test]
fn same_space_target_capacity_failure_occurs_before_source_is_taken() {
    let (cspace, source_binding, source_cap, mut source_table, source_token) = source(Rights::READ);
    let target_binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    let existing_cap = cspace.lock().mint(Arc::new(Probe(7)), Rights::READ);
    let existing = target_binding
        .bind_ephemeral::<Probe>(existing_cap, Rights::READ)
        .unwrap();
    let mut target_table = ResourceTable::new(12, 1).unwrap();
    target_table.insert_owned(TARGET_TYPE, existing).unwrap();
    let caps_before = cspace.lock().list().len();

    assert_eq!(
        transfer_owned::<Probe>(
            &mut source_table,
            source_token,
            SOURCE_TYPE,
            &source_binding,
            &mut target_table,
            TARGET_TYPE,
            &target_binding,
            Rights::READ,
        ),
        Err(OwnedTransferError::TargetTable(ResourceError::TableFull)),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert_eq!(target_table.len(), 1);
    assert_eq!(cspace.lock().list().len(), caps_before);
    assert!(cspace.lock().lookup(source_cap, Rights::READ).is_ok());
}

#[test]
fn staged_pair_transfer_commits_tables_only_after_fused_core_transfer() {
    let (registry, instance_tokens, ancestor, source_cap, mut source_table, source_token) =
        reserved_supervised_source(30_001, 808);
    let mut target_table = ResourceTable::new(30_010, 2).unwrap();
    let guard = prepare_owned_supervised(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &mut target_table,
        TARGET_TYPE,
    )
    .unwrap();

    let target_token = unsafe {
        registry.transfer_reserved_space_pair(
            instance_tokens[0],
            instance_tokens[1],
            |source, target| guard.prepare_in::<Probe>(source, target, Rights::READ),
            |prepared, receipt| prepared.commit(receipt),
        )
    }
    .unwrap()
    .unwrap();

    assert!(source_table.is_empty());
    assert_eq!(target_table.contains(target_token, TARGET_TYPE), Ok(true));
    let (source_retired, source_caps, target_caps) = unsafe {
        registry
            .with_reserved_space_pair(instance_tokens[0], instance_tokens[1], |source, target| {
                (
                    source.rights_of(source_cap).is_err(),
                    source.live_count(),
                    target.live_count(),
                )
            })
            .unwrap()
    };
    assert!(source_retired);
    assert_eq!(source_caps, 1, "only the ancestor remains");
    assert_eq!(target_caps, 1);
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(instance_tokens[1], |target| {
                target_table.with_borrow(target_token, TARGET_TYPE, |borrowed| {
                    borrowed.with(|authority| {
                        authority
                            .with_resource_in::<Probe, _, _>(target, Rights::READ, |probe| probe.0)
                    })
                })
            })
        }
        .unwrap()
        .unwrap(),
        Ok(808),
    );
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(instance_tokens[0], |source| source.revoke(ancestor))
        }
        .unwrap(),
        Ok(1),
    );
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(instance_tokens[1], |target| {
                target_table.with_borrow(target_token, TARGET_TYPE, |borrowed| {
                    borrowed.with(|authority| {
                        assert_eq!(authority.class(), AuthorityClass::Ephemeral);
                        authority.with_resource_in::<Probe, _, _>(target, Rights::READ, |_| ())
                    })
                })
            })
        }
        .unwrap()
        .unwrap(),
        Err(AuthorityError::InvalidOrRevoked),
    );
    drop(target_table.drop_owned(target_token, TARGET_TYPE).unwrap());
    assert!(target_table.is_empty());
    assert_eq!(
        registry
            .abort_reserved_batch(&instance_tokens)
            .unwrap()
            .aborted_instances(),
        2,
    );
}

#[test]
fn staged_pair_prepare_error_rolls_back_both_tables_and_never_moves_capability() {
    let (registry, instance_tokens, _ancestor, source_cap, mut source_table, source_token) =
        reserved_supervised_source(31_001, 909);
    let mut target_table = ResourceTable::new(31_010, 2).unwrap();
    let guard = prepare_owned_supervised(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &mut target_table,
        TARGET_TYPE,
    )
    .unwrap();

    let result = unsafe {
        registry.transfer_reserved_space_pair(
            instance_tokens[0],
            instance_tokens[1],
            |source, target| guard.prepare_in::<Probe>(source, target, Rights::WRITE),
            |prepared, receipt| prepared.commit(receipt),
        )
    };
    assert_eq!(
        result,
        Ok(Err(PairTransferError::Configure(
            AuthorityError::RightsExceedCeiling,
        ))),
    );
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    let unchanged = unsafe {
        registry
            .with_reserved_space_pair(instance_tokens[0], instance_tokens[1], |source, target| {
                (
                    source.rights_of(source_cap) == Ok(Rights::READ.union(Rights::GRANT)),
                    source.live_count(),
                    target.live_count(),
                )
            })
            .unwrap()
    };
    assert_eq!(unchanged, (true, 2, 0));
    drop(source_table.drop_owned(source_token, SOURCE_TYPE).unwrap());
    assert_eq!(
        registry
            .abort_reserved_batch(&instance_tokens)
            .unwrap()
            .aborted_instances(),
        2,
    );
}

#[test]
fn staged_pair_preparation_without_grant_rolls_back_both_tables_and_cspaces() {
    let (source_cspace, _source_binding, source_cap, mut source_table, source_token) =
        source(Rights::READ);
    let (target_cspace, _) = space("staged-missing-grant-target");
    let mut target_table = ResourceTable::new(32_010, 2).unwrap();
    let source_before = source_cspace.lock().list();
    let target_before = target_cspace.lock().list();
    let guard = prepare_owned_supervised(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &mut target_table,
        TARGET_TYPE,
    )
    .unwrap();
    let result = {
        let source = source_cspace.lock();
        let target = target_cspace.lock();
        guard.prepare_in::<Probe>(&source, &target, Rights::READ)
    };
    assert_eq!(result.unwrap_err(), AuthorityError::SupervisorGrantRequired);
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert_eq!(source_cspace.lock().list(), source_before);
    assert_eq!(target_cspace.lock().list(), target_before);
    assert_eq!(
        ComponentAuthority::prepare_supervised_ephemeral_source_in::<Probe>(
            &source_cspace.lock(),
            source_cap,
            Rights::READ,
        )
        .unwrap_err(),
        AuthorityError::SupervisorGrantRequired,
    );
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
}

#[test]
fn supervised_borrow_creates_no_target_entry_or_capability() {
    let (source_cspace, _, source_cap, source_table, source_token) = source(Rights::READ);
    let (target_cspace, _) = space("supervised-borrow-target");
    let target_table = ResourceTable::<ComponentAuthority>::new(23, 2).unwrap();
    let source_caps_before = source_cspace.lock().list();
    let target_caps_before = target_cspace.lock().list();

    let observed = {
        let source = source_cspace.lock();
        let target = target_cspace.lock();
        with_supervised_borrow::<Probe, _>(
            &source_table,
            source_token,
            SOURCE_TYPE,
            &source,
            &target_table,
            TARGET_TYPE,
            &target,
            Rights::READ,
            |scope| {
                assert_eq!(source_table.len(), 1);
                assert!(target_table.is_empty());
                assert_eq!(source.list(), source_caps_before);
                assert_eq!(target.list(), target_caps_before);
                let alias = scope.alias();
                scope.with_alias(&alias, |probe| probe.0)
            },
        )
        .unwrap()
    };
    assert_eq!(observed, Ok(42));
    assert_eq!(source_table.len(), 1);
    assert!(target_table.is_empty());
    assert_eq!(source_cspace.lock().list(), source_caps_before);
    assert_eq!(target_cspace.lock().list(), target_caps_before);
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
}

#[test]
fn supervised_borrow_route_errors_are_exact_and_leave_both_sides_unchanged() {
    let (source_cspace, _, source_cap, source_table, source_token) = source(Rights::READ);
    let target_table = ResourceTable::<ComponentAuthority>::new(26, 2).unwrap();
    let source_before = source_cspace.lock().list();
    let source = source_cspace.lock();

    assert_eq!(
        with_supervised_borrow::<Probe, _>(
            &source_table,
            source_token,
            SOURCE_TYPE,
            &source,
            &target_table,
            TARGET_TYPE,
            &source,
            Rights::READ,
            |_| (),
        ),
        Err(SupervisedBorrowError::Authority(
            AuthorityError::SupervisorDistinctSpacesRequired,
        )),
    );
    drop(source);

    let (target_cspace, _) = space("borrow-rights-error-target");
    let source = source_cspace.lock();
    let target = target_cspace.lock();
    assert_eq!(
        with_supervised_borrow::<Probe, _>(
            &source_table,
            source_token,
            SOURCE_TYPE,
            &source,
            &target_table,
            TARGET_TYPE,
            &target,
            Rights::GRANT,
            |_| (),
        ),
        Err(SupervisedBorrowError::Authority(
            AuthorityError::RightsExceedCeiling,
        )),
    );
    drop(target);
    drop(source);
    assert_eq!(source_table.len(), 1);
    assert!(target_table.is_empty());
    assert_eq!(source_cspace.lock().list(), source_before);
    assert!(target_cspace.lock().list().is_empty());
    assert!(source_cspace
        .lock()
        .lookup(source_cap, Rights::READ)
        .is_ok());
}

#[test]
fn durable_proxy_staging_revalidates_parent_and_local_revoke_survives_parent_revoke() {
    let (durable, durable_cap, witness) = persistent_probe();
    let durable_binding = ComponentAuthoritySpace::new(durable.clone(), 1).unwrap();
    let (source_cspace, source_binding) = space("proxy-transfer-source");
    let mut source_table = ResourceTable::new(24, 2).unwrap();
    let source_token = install_persistent_proxy_owned::<Probe>(
        &mut source_table,
        SOURCE_TYPE,
        &source_binding,
        &durable_binding,
        durable_cap,
        Rights::READ,
    )
    .unwrap();
    let (target_cspace, _) = space("proxy-transfer-target");
    let mut target_table = ResourceTable::new(25, 2).unwrap();

    let guard = prepare_owned_supervised(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &mut target_table,
        TARGET_TYPE,
    )
    .unwrap();
    let stage = {
        let source = source_cspace.lock();
        let target = target_cspace.lock();
        guard
            .prepare_in::<Probe>(&source, &target, Rights::READ)
            .unwrap()
    };
    assert_eq!(format!("{stage:?}"), "SupervisedTransferStage(<redacted>)");
    drop(stage);
    assert_eq!(source_table.contains(source_token, SOURCE_TYPE), Ok(true));
    assert!(target_table.is_empty());
    assert_eq!(source_cspace.lock().list().len(), 1);
    assert!(target_cspace.lock().list().is_empty());
    assert_eq!(
        source_table
            .with_borrow(source_token, SOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    assert_eq!(authority.class(), AuthorityClass::PersistentProxy);
                    authority
                        .with_resource::<Probe, _, _>(&source_cspace, Rights::READ, |probe| probe.0)
                })
            })
            .unwrap(),
        Ok(314),
    );

    let identity = witness.identity();
    assert_eq!(
        durable
            .lock()
            .complete_persistent_revoke(&witness, identity),
        Ok(1),
    );
    assert_eq!(
        source_table
            .with_borrow(source_token, SOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    authority
                        .with_resource::<Probe, _, _>(&source_cspace, Rights::READ, |probe| probe.0)
                })
            })
            .unwrap(),
        Err(AuthorityError::InvalidOrRevoked),
    );
    let mut source = source_cspace.lock();
    assert_eq!(
        revoke_owned_supervised::<Probe>(&mut source_table, source_token, SOURCE_TYPE, &mut source,),
        Ok(1),
    );
    assert!(source_table.is_empty());
    assert!(source.list().is_empty());
    assert!(target_table.is_empty());
    assert!(target_cspace.lock().list().is_empty());
}

#[test]
fn durable_proxy_relocates_only_through_fused_pair_and_remains_revocable() {
    let (durable, durable_cap, witness) = persistent_probe();
    let registry = InstanceRegistry::new();
    let domains = [
        AllocationDomain::new(OwnerId::new(40_001), ArenaId::new(40_002)),
        AllocationDomain::new(OwnerId::new(40_003), ArenaId::new(40_004)),
    ];
    let tokens = registry
        .reserve_named_batch(&[
            (domains[0], "durable-proxy-source"),
            (domains[1], "durable-proxy-target"),
        ])
        .unwrap();
    let tokens = [tokens[0], tokens[1]];
    let mut source_table = ResourceTable::new(40_010, 2).unwrap();
    let source_reservation = source_table.reserve().unwrap();
    let prepared = unsafe {
        registry
            .configure_reserved_space(tokens[0], |source| {
                let durable = durable.lock();
                ComponentAuthority::prepare_supervised_persistent_proxy_source_in::<Probe>(
                    source,
                    &durable,
                    durable_cap,
                    Rights::READ,
                )
            })
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedSupervisedPersistentProxySource(<redacted>)"
    );
    let source_token = source_reservation.commit(SOURCE_TYPE, prepared.into_authority());
    let mut target_table = ResourceTable::new(40_020, 2).unwrap();
    let guard = prepare_owned_supervised(
        &mut source_table,
        source_token,
        SOURCE_TYPE,
        &mut target_table,
        TARGET_TYPE,
    )
    .unwrap();
    let target_token = unsafe {
        registry.transfer_reserved_space_pair(
            tokens[0],
            tokens[1],
            |source, target| guard.prepare_in::<Probe>(source, target, Rights::READ),
            |prepared, receipt| prepared.commit(receipt),
        )
    }
    .unwrap()
    .unwrap();

    assert!(source_table.is_empty());
    assert_eq!(target_table.contains(target_token, TARGET_TYPE), Ok(true));
    let observed = unsafe {
        registry
            .with_reserved_space_pair(tokens[0], tokens[1], |source, target| {
                (
                    source.live_count(),
                    target.live_count(),
                    target.singleton_live_shape(),
                )
            })
            .unwrap()
    };
    assert_eq!(
        observed,
        (0, 1, Some(("component-persistent-proxy", Rights::READ)),)
    );
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(tokens[1], |target| {
                target_table.with_borrow(target_token, TARGET_TYPE, |borrowed| {
                    borrowed.with(|authority| {
                        authority
                            .with_resource_in::<Probe, _, _>(target, Rights::READ, |probe| probe.0)
                    })
                })
            })
        }
        .unwrap()
        .unwrap(),
        Ok(314),
    );

    let identity = witness.identity();
    assert_eq!(
        durable
            .lock()
            .complete_persistent_revoke(&witness, identity),
        Ok(1),
    );
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(tokens[1], |target| {
                target_table.with_borrow(target_token, TARGET_TYPE, |borrowed| {
                    borrowed.with(|authority| {
                        authority.with_resource_in::<Probe, _, _>(target, Rights::READ, |_| ())
                    })
                })
            })
        }
        .unwrap()
        .unwrap(),
        Err(AuthorityError::InvalidOrRevoked),
    );
    assert_eq!(
        unsafe {
            registry.configure_reserved_space(tokens[1], |target| {
                revoke_owned_supervised::<Probe>(
                    &mut target_table,
                    target_token,
                    TARGET_TYPE,
                    target,
                )
            })
        }
        .unwrap(),
        Ok(1),
    );
    assert!(target_table.is_empty());
    assert_eq!(
        registry
            .abort_reserved_batch(&tokens)
            .unwrap()
            .aborted_instances(),
        2,
    );
}

#[test]
fn supervised_revoke_wrong_resource_class_restores_entry_and_capability() {
    let (cspace, _, cap, mut table, token) = source(Rights::READ);
    let before = cspace.lock().list();
    let result = {
        let mut guard = cspace.lock();
        revoke_owned_supervised::<OtherProbe>(&mut table, token, SOURCE_TYPE, &mut guard)
    };
    assert_eq!(
        result,
        Err(SupervisedRevokeError::Authority(
            AuthorityError::WrongResourceKind,
        )),
    );
    assert_eq!(table.contains(token, SOURCE_TYPE), Ok(true));
    assert_eq!(cspace.lock().list(), before);
    assert!(cspace.lock().lookup(cap, Rights::READ).is_ok());

    let mut guard = cspace.lock();
    assert_eq!(
        revoke_owned_supervised::<Probe>(&mut table, token, SOURCE_TYPE, &mut guard),
        Ok(1),
    );
    assert!(table.is_empty());
    assert!(guard.list().is_empty());
}
