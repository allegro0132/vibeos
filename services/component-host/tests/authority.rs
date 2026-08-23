use std::any::Any;
use std::sync::Arc;

use vibeos_component_host::{
    install_persistent_proxy_owned, AuthorityClass, AuthorityError, BlobBackend, BlobBackendFault,
    BlobResource, ComponentAuthority, ComponentAuthoritySpace, ComponentHostResource,
    ComponentHostServices, HostResourceKind, PersistentProxyInstallError, SharedCSpace,
};
use vibeos_component_runtime::resource::{ResourceError, ResourceTable, ResourceTypeId};
use vibeos_core::cap::{CSpace, Cap, PersistentDerivationWitness, Resource, Rights};
use vibeos_core::sync::SpinLock;
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, ResourceKind, SpaceId,
};

const BLOB_TYPE: ResourceTypeId = ResourceTypeId(1);

struct Probe(u32);
struct OtherProbe;
struct ExternalRightsProbe(u32);

impl Resource for Probe {
    fn kind(&self) -> &'static str {
        "probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for Probe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Random;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

impl Resource for OtherProbe {
    fn kind(&self) -> &'static str {
        "other-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for OtherProbe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

impl Resource for ExternalRightsProbe {
    fn kind(&self) -> &'static str {
        "external-rights-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for ExternalRightsProbe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    // This integration-test implementation has the same freedom as any safe
    // external crate and maliciously claims host management bits as operations.
    const OPERATION_RIGHTS: Rights = Rights::ALL_VOLATILE;
}

fn ordinary(name: &str) -> (SharedCSpace, ComponentAuthoritySpace) {
    let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
    let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
    (cspace, binding)
}

fn mint_probe(cspace: &SharedCSpace, value: u32, rights: Rights) -> Cap {
    cspace.lock().mint(Arc::new(Probe(value)), rights)
}

#[test]
fn guessed_stale_wrong_type_and_over_rights_are_rejected_at_binding() {
    let (issuer, _) = ordinary("issuer");
    let guessed = mint_probe(&issuer, 1, Rights::READ);
    let (_empty, empty_binding) = ordinary("empty-target");
    assert_eq!(
        empty_binding
            .bind_ephemeral::<Probe>(guessed, Rights::READ)
            .unwrap_err(),
        AuthorityError::InvalidOrRevoked,
    );

    let (space, binding) = ordinary("binding-negative-cases");
    let stale = mint_probe(&space, 2, Rights::READ);
    assert_eq!(space.lock().revoke_slot(stale.slot()), 1);
    assert_eq!(
        binding
            .bind_ephemeral::<Probe>(stale, Rights::READ)
            .unwrap_err(),
        AuthorityError::InvalidOrRevoked,
    );

    let wrong_type = mint_probe(&space, 3, Rights::READ);
    assert_eq!(
        binding
            .bind_ephemeral::<OtherProbe>(wrong_type, Rights::READ)
            .unwrap_err(),
        AuthorityError::WrongResourceType,
    );

    let over_righted = mint_probe(&space, 4, Rights::READ.union(Rights::WRITE));
    assert_eq!(
        binding
            .bind_ephemeral::<Probe>(over_righted, Rights::READ)
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );
}

#[test]
fn ordinary_ephemeral_receipts_reject_every_trait_declared_management_right() {
    const MANAGEMENT_CASES: [Rights; 4] = [
        Rights::GRANT,
        Rights::REVOKE,
        Rights::INVOKE,
        Rights::GRANT.union(Rights::REVOKE).union(Rights::INVOKE),
    ];

    let (space, _) = ordinary("management-rights-negative");
    for (index, management) in MANAGEMENT_CASES.into_iter().enumerate() {
        let held = Rights::READ.union(management);
        let cap = space
            .lock()
            .mint(Arc::new(ExternalRightsProbe(index as u32)), held);
        let guard = space.lock();
        let identity = guard.identity();
        let incarnation = guard.incarnation();
        let table_range = guard.capability_table_range();

        let rejected =
            ComponentAuthority::prepare_ephemeral_in::<ExternalRightsProbe>(&guard, cap, held);
        assert_eq!(
            rejected.unwrap_err(),
            AuthorityError::RightsExceedCeiling,
            "held management rights {management:?} must not produce a receipt",
        );
        assert_eq!(guard.identity(), identity);
        assert_eq!(guard.incarnation(), incarnation);
        assert_eq!(guard.capability_table_range(), table_range);
        assert_eq!(guard.rights_of(cap), Ok(held));
    }
}

#[test]
fn ordinary_ephemeral_receipts_reject_management_bits_in_the_ceiling() {
    const MANAGEMENT_CASES: [Rights; 4] = [
        Rights::GRANT,
        Rights::REVOKE,
        Rights::INVOKE,
        Rights::GRANT.union(Rights::REVOKE).union(Rights::INVOKE),
    ];

    let (space, _) = ordinary("management-ceiling-negative");
    for (index, management) in MANAGEMENT_CASES.into_iter().enumerate() {
        let cap = space
            .lock()
            .mint(Arc::new(ExternalRightsProbe(index as u32)), Rights::READ);
        let guard = space.lock();
        let identity = guard.identity();
        let incarnation = guard.incarnation();
        let table_range = guard.capability_table_range();
        let ceiling = Rights::READ.union(management);

        let rejected =
            ComponentAuthority::prepare_ephemeral_in::<ExternalRightsProbe>(&guard, cap, ceiling);
        assert_eq!(
            rejected.unwrap_err(),
            AuthorityError::RightsExceedCeiling,
            "ceiling management rights {management:?} must not produce a receipt",
        );
        assert_eq!(guard.identity(), identity);
        assert_eq!(guard.incarnation(), incarnation);
        assert_eq!(guard.capability_table_range(), table_range);
        assert_eq!(guard.rights_of(cap), Ok(Rights::READ));
    }
}

#[test]
fn ordinary_ephemeral_receipt_accepts_only_normal_operation_rights_and_is_redacted() {
    let normal = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::SEND)
        .union(Rights::RECV);
    let (space, _) = ordinary("normal-operation-rights");
    let cap = space.lock().mint(Arc::new(ExternalRightsProbe(73)), normal);
    let guard = space.lock();
    let prepared =
        ComponentAuthority::prepare_ephemeral_in::<ExternalRightsProbe>(&guard, cap, normal)
            .unwrap();
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedEphemeralAuthority(<redacted>)"
    );
    let authority = prepared.into_authority();
    drop(guard);

    assert_eq!(
        authority.with_revocable::<ExternalRightsProbe, _, _>(&space, normal, |probe| probe.0,),
        Ok(73),
    );
}

#[test]
fn operation_checks_kind_ceiling_and_revocation_again() {
    let (space, binding) = ordinary("operation-checks");
    let cap = mint_probe(&space, 41, Rights::READ);
    let authority = binding.bind_ephemeral::<Probe>(cap, Rights::READ).unwrap();

    assert_eq!(
        authority.with_revocable::<Probe, _, _>(&space, Rights::READ, |probe| probe.0),
        Ok(41),
    );
    assert_eq!(
        authority
            .with_revocable::<OtherProbe, _, _>(&space, Rights::READ, |_| ())
            .unwrap_err(),
        AuthorityError::WrongResourceKind,
    );
    assert_eq!(
        authority
            .with_revocable::<Probe, _, _>(&space, Rights::WRITE, |_| ())
            .unwrap_err(),
        AuthorityError::RightsExceedCeiling,
    );

    assert_eq!(space.lock().revoke_slot(cap.slot()), 1);
    assert_eq!(
        authority
            .with_revocable::<Probe, _, _>(&space, Rights::READ, |_| ())
            .unwrap_err(),
        AuthorityError::InvalidOrRevoked,
        "the very next operation must observe revocation",
    );
}

#[test]
fn ownerless_ephemeral_binding_seals_exact_space_incarnation_and_revocation() {
    let first = SpinLock::new(CSpace::new("ownerless-first"));
    let second = SpinLock::new(CSpace::new("ownerless-second"));
    let first_cap = first.lock().mint(Arc::new(Probe(71)), Rights::READ);
    let second_cap = second.lock().mint(Arc::new(Probe(72)), Rights::READ);
    assert_eq!(
        first_cap, second_cap,
        "opaque numeric caps intentionally collide"
    );

    let authority =
        ComponentAuthority::bind_ephemeral_in::<Probe>(&first, first_cap, Rights::READ).unwrap();
    assert_eq!(
        authority.with_resource::<Probe, _, _>(&first, Rights::READ, |probe| probe.0),
        Ok(71)
    );
    assert_eq!(
        authority
            .with_resource::<Probe, _, _>(&second, Rights::READ, |probe| probe.0)
            .unwrap_err(),
        AuthorityError::WrongSpace
    );

    assert_eq!(first.lock().reset(), 1);
    assert_eq!(
        authority
            .with_resource::<Probe, _, _>(&first, Rights::READ, |probe| probe.0)
            .unwrap_err(),
        AuthorityError::IncarnationMismatch
    );

    let replacement = first.lock().mint(Arc::new(Probe(73)), Rights::READ);
    let replacement_authority =
        ComponentAuthority::bind_ephemeral_in::<Probe>(&first, replacement, Rights::READ).unwrap();
    assert_eq!(first.lock().revoke_slot(replacement.slot()), 1);
    assert_eq!(
        replacement_authority
            .with_resource::<Probe, _, _>(&first, Rights::READ, |probe| probe.0)
            .unwrap_err(),
        AuthorityError::InvalidOrRevoked
    );
    assert_eq!(
        ComponentAuthority::bind_ephemeral_in::<Probe>(&first, replacement, Rights::READ)
            .unwrap_err(),
        AuthorityError::InvalidOrRevoked
    );
}

#[test]
fn intrinsic_identity_rejects_same_numeric_cap_in_same_incarnation() {
    let (first, first_binding) = ordinary("first");
    let (second, second_binding) = ordinary("second");
    let first_cap = mint_probe(&first, 11, Rights::READ);
    let second_cap = mint_probe(&second, 22, Rights::READ);

    assert_eq!(first_cap, second_cap, "fresh spaces intentionally collide");
    assert_eq!(first.lock().incarnation(), second.lock().incarnation());
    assert_ne!(first.lock().identity(), second.lock().identity());

    let authority = first_binding
        .bind_ephemeral::<Probe>(first_cap, Rights::READ)
        .unwrap();
    assert_eq!(
        authority.with_revocable::<Probe, _, _>(&first, Rights::READ, |probe| probe.0),
        Ok(11),
    );
    assert_eq!(
        authority
            .with_revocable::<Probe, _, _>(&second, Rights::READ, |probe| probe.0)
            .unwrap_err(),
        AuthorityError::WrongSpace,
    );
    assert_eq!(
        second_binding
            .with_revocable::<Probe, _, _>(&authority, Rights::READ, |probe| probe.0)
            .unwrap_err(),
        AuthorityError::WrongSpace,
    );
}

#[test]
fn incarnation_is_bound_at_construction_and_operation_time() {
    let (space, binding) = ordinary("restartable");
    assert_eq!(
        ComponentAuthoritySpace::new(space.clone(), 2).unwrap_err(),
        AuthorityError::IncarnationMismatch,
    );
    let cap = mint_probe(&space, 7, Rights::READ);
    let authority = binding.bind_ephemeral::<Probe>(cap, Rights::READ).unwrap();

    assert_eq!(space.lock().reset(), 1);
    let replacement = mint_probe(&space, 8, Rights::READ);
    assert_ne!(cap, replacement);
    assert_eq!(
        authority
            .with_revocable::<Probe, _, _>(&space, Rights::READ, |_| ())
            .unwrap_err(),
        AuthorityError::IncarnationMismatch,
    );
    assert_eq!(
        binding
            .bind_ephemeral::<Probe>(replacement, Rights::READ)
            .unwrap_err(),
        AuthorityError::IncarnationMismatch,
    );
}

#[test]
fn authority_diagnostics_redact_handle_and_space_identity() {
    let (space, binding) = ordinary("redacted");
    let cap = mint_probe(&space, 9, Rights::READ);
    let authority = binding.bind_ephemeral::<Probe>(cap, Rights::READ).unwrap();
    let diagnostic = format!("{authority:?}");

    assert!(diagnostic.contains("cap: \"<redacted>\""));
    assert!(diagnostic.contains("cspace: \"<redacted>\""));
    assert!(!diagnostic.contains(&cap.to_string()));
}

struct MemoryBlob(&'static [u8]);

impl BlobBackend for MemoryBlob {
    fn len(&self) -> Result<u64, BlobBackendFault> {
        Ok(self.0.len() as u64)
    }

    fn read_exact(&self, offset: u64, destination: &mut [u8]) -> Result<(), BlobBackendFault> {
        let start = usize::try_from(offset).map_err(|_| BlobBackendFault)?;
        let end = start
            .checked_add(destination.len())
            .ok_or(BlobBackendFault)?;
        let source = self.0.get(start..end).ok_or(BlobBackendFault)?;
        destination.copy_from_slice(source);
        Ok(())
    }
}

fn persistent_blob(
    rights: DurableRights,
) -> (SharedCSpace, Cap, PersistentDerivationWitness<BlobResource>) {
    let space_id = SpaceId::new(0x51).unwrap();
    let mut cspace = CSpace::new_persistent("durable-blob", space_id);
    let reservation = cspace
        .reserve_persistent_slot(cspace.incarnation())
        .unwrap();
    let grant = GrantRecord {
        derivation_id: DerivationId::new(0x52).unwrap(),
        parent_id: None,
        object_id: ObjectId::new(0x53).unwrap(),
        target: reservation.target(),
        rights,
        resource_kind: ResourceKind::new(0x54).unwrap(),
        flags: GrantFlags::ROOT,
    };
    let (cap, witness) = cspace
        .install_reserved_root(
            &reservation,
            &grant,
            Arc::new(BlobResource::new(Arc::new(MemoryBlob(b"durable")))),
        )
        .unwrap();
    (Arc::new(SpinLock::new(cspace)), cap, witness)
}

#[test]
fn durable_authority_only_enters_through_attenuated_proxy() {
    let durable_rights = DurableRights::READ
        .union(DurableRights::GRANT)
        .union(DurableRights::REVOKE);
    let (source, source_cap, witness) = persistent_blob(durable_rights);
    let source_binding = ComponentAuthoritySpace::new(source.clone(), 1).unwrap();
    assert_eq!(
        source_binding
            .bind_ephemeral::<BlobResource>(
                source_cap,
                Rights::READ.union(Rights::GRANT).union(Rights::REVOKE),
            )
            .unwrap_err(),
        AuthorityError::RawPersistentAuthority,
    );

    let (target, target_binding) = ordinary("proxy-target");
    let mut target_table = ResourceTable::<ComponentAuthority>::new(1, 2).unwrap();
    for forbidden in [Rights::GRANT, Rights::REVOKE, Rights::INVOKE] {
        assert_eq!(
            install_persistent_proxy_owned::<BlobResource>(
                &mut target_table,
                BLOB_TYPE,
                &target_binding,
                &source_binding,
                source_cap,
                Rights::READ.union(forbidden),
            ),
            Err(PersistentProxyInstallError::Authority(
                AuthorityError::PersistentProxyRights,
            )),
        );
    }
    assert!(target_table.is_empty());
    assert!(target.lock().list().is_empty());

    let proxy_token = install_persistent_proxy_owned::<BlobResource>(
        &mut target_table,
        BLOB_TYPE,
        &target_binding,
        &source_binding,
        source_cap,
        Rights::READ,
    )
    .unwrap();
    assert_eq!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| (proxy.class(), proxy.kind(), proxy.rights_ceiling()))
            })
            .unwrap(),
        (
            AuthorityClass::PersistentProxy,
            HostResourceKind::Blob,
            Rights::READ,
        ),
    );
    assert_eq!(target.lock().list()[0].2, Rights::READ);
    assert_eq!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| {
                    proxy.with_persistent_proxy::<BlobResource, _, _>(
                        &target,
                        Rights::READ,
                        |blob| blob.read(0, 7),
                    )
                })
            })
            .unwrap(),
        Ok(Ok(b"durable".to_vec())),
    );
    assert_eq!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| ComponentHostServices::blob_read(proxy, &target, 0, 7))
            })
            .unwrap(),
        Ok(b"durable".to_vec()),
        "ordinary service entry points must preserve proxy revocation semantics",
    );
    assert_eq!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| {
                    proxy
                        .with_persistent_proxy::<BlobResource, _, _>(&target, Rights::WRITE, |_| ())
                        .unwrap_err()
                })
            })
            .unwrap(),
        AuthorityError::RightsExceedCeiling,
    );

    let identity = witness.identity();
    assert_eq!(
        source
            .lock()
            .complete_persistent_revoke(&witness, identity)
            .unwrap(),
        1,
    );
    assert_eq!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| {
                    proxy
                        .with_persistent_proxy::<BlobResource, _, _>(&target, Rights::READ, |_| ())
                        .unwrap_err()
                })
            })
            .unwrap(),
        AuthorityError::InvalidOrRevoked,
    );
    assert!(matches!(
        target_table
            .with_borrow(proxy_token, BLOB_TYPE, |borrowed| {
                borrowed.with(|proxy| ComponentHostServices::blob_read(proxy, &target, 0, 1))
            })
            .unwrap(),
        Err(vibeos_component_host::ComponentCallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    ));
}

#[test]
fn persistent_proxy_requires_source_grant_and_exact_source_incarnation() {
    let (source, source_cap, _) = persistent_blob(DurableRights::READ);
    let source_binding = ComponentAuthoritySpace::new(source.clone(), 1).unwrap();
    let (_target, target_binding) = ordinary("proxy-denied-target");
    let mut target_table = ResourceTable::<ComponentAuthority>::new(2, 2).unwrap();
    assert_eq!(
        install_persistent_proxy_owned::<BlobResource>(
            &mut target_table,
            BLOB_TYPE,
            &target_binding,
            &source_binding,
            source_cap,
            Rights::READ,
        ),
        Err(PersistentProxyInstallError::Authority(
            AuthorityError::PersistentGrantRequired,
        )),
    );
    let foreign = Arc::new(SpinLock::new(CSpace::new_persistent(
        "foreign-durable",
        SpaceId::new(0x61).unwrap(),
    )));
    let foreign_binding = ComponentAuthoritySpace::new(foreign, 1).unwrap();
    assert_eq!(
        install_persistent_proxy_owned::<BlobResource>(
            &mut target_table,
            BLOB_TYPE,
            &target_binding,
            &foreign_binding,
            source_cap,
            Rights::READ,
        ),
        Err(PersistentProxyInstallError::Authority(
            AuthorityError::InvalidOrRevoked,
        )),
    );
    assert!(target_table.is_empty());
}

#[test]
fn full_component_table_prevents_proxy_mint_without_stranding_a_cap() {
    let durable_rights = DurableRights::READ.union(DurableRights::GRANT);
    let (source, source_cap, _) = persistent_blob(durable_rights);
    let source_binding = ComponentAuthoritySpace::new(source, 1).unwrap();
    let (target, target_binding) = ordinary("full-proxy-target");
    let existing_cap = target.lock().mint(
        Arc::new(BlobResource::new(Arc::new(MemoryBlob(b"existing")))),
        Rights::READ,
    );
    let existing = target_binding
        .bind_ephemeral::<BlobResource>(existing_cap, Rights::READ)
        .unwrap();
    let mut target_table = ResourceTable::new(3, 1).unwrap();
    target_table.insert_owned(BLOB_TYPE, existing).unwrap();
    let caps_before = target.lock().list().len();

    assert_eq!(
        install_persistent_proxy_owned::<BlobResource>(
            &mut target_table,
            BLOB_TYPE,
            &target_binding,
            &source_binding,
            source_cap,
            Rights::READ,
        ),
        Err(PersistentProxyInstallError::TargetTable(
            ResourceError::TableFull,
        )),
    );
    assert_eq!(target_table.len(), 1);
    assert_eq!(target.lock().list().len(), caps_before);
}

#[test]
fn owned_drop_reclaims_one_slot_and_teardown_requires_an_empty_table() {
    let (space, binding) = ordinary("lifecycle");
    let first_cap = space.lock().mint(
        Arc::new(BlobResource::new(Arc::new(MemoryBlob(b"first")))),
        Rights::READ,
    );
    let second_cap = space.lock().mint(
        Arc::new(BlobResource::new(Arc::new(MemoryBlob(b"second")))),
        Rights::READ,
    );
    let first = binding
        .bind_ephemeral::<BlobResource>(first_cap, Rights::READ)
        .unwrap();
    let second = binding
        .bind_ephemeral::<BlobResource>(second_cap, Rights::READ)
        .unwrap();
    let mut table = ResourceTable::new(4, 2).unwrap();
    let first_token = table.insert_owned(BLOB_TYPE, first).unwrap();
    let second_token = table.insert_owned(BLOB_TYPE, second).unwrap();

    assert_eq!(binding.teardown(&table), Err(AuthorityError::TableNotEmpty));
    assert_eq!(space.lock().incarnation(), 1);

    let first = table.drop_owned(first_token, BLOB_TYPE).unwrap();
    assert_eq!(binding.revoke_dropped(first), Ok(1));
    assert_eq!(
        space.lock().lookup(first_cap, Rights::READ).err(),
        Some(vibeos_core::cap::CapError::Invalid),
    );
    let _second = table.drop_owned(second_token, BLOB_TYPE).unwrap();
    assert!(table.is_empty());

    assert_eq!(binding.teardown(&table), Ok(1));
    assert!(space.lock().list().is_empty());
    assert_eq!(space.lock().incarnation(), 2);
    assert_eq!(
        binding.teardown(&table),
        Err(AuthorityError::IncarnationMismatch),
    );
}

#[test]
fn stale_dropped_authority_cannot_revoke_a_reused_slot() {
    let (space, binding) = ordinary("stale-drop");
    let stale_cap = mint_probe(&space, 1, Rights::READ);
    let stale = binding
        .bind_ephemeral::<Probe>(stale_cap, Rights::READ)
        .unwrap();
    assert_eq!(space.lock().revoke_slot(stale_cap.slot()), 1);
    let replacement = mint_probe(&space, 2, Rights::READ);
    assert_eq!(replacement.slot(), stale_cap.slot());
    assert_ne!(replacement, stale_cap);

    assert_eq!(
        binding.revoke_dropped(stale),
        Err(AuthorityError::InvalidOrRevoked),
    );
    assert_eq!(
        space
            .lock()
            .lookup_as::<Probe>(replacement, Rights::READ)
            .unwrap()
            .0,
        2,
    );
}

#[test]
fn persistent_proxy_requires_a_distinct_volatile_target_and_cannot_teardown_durable_space() {
    let rights = DurableRights::READ.union(DurableRights::GRANT);
    let (source, source_cap, _) = persistent_blob(rights);
    let source_binding = ComponentAuthoritySpace::new(source.clone(), 1).unwrap();
    let mut same_table = ResourceTable::new(5, 1).unwrap();
    assert_eq!(
        install_persistent_proxy_owned::<BlobResource>(
            &mut same_table,
            BLOB_TYPE,
            &source_binding,
            &source_binding,
            source_cap,
            Rights::READ,
        ),
        Err(PersistentProxyInstallError::Authority(
            AuthorityError::PersistentProxyTarget,
        )),
    );
    assert!(same_table.is_empty());
    assert_eq!(
        source_binding.teardown(&same_table),
        Err(AuthorityError::TeardownRejected),
    );
    assert_eq!(source.lock().incarnation(), 1);

    let (persistent_target, _, _) = persistent_blob(rights);
    let target_binding = ComponentAuthoritySpace::new(persistent_target.clone(), 1).unwrap();
    let target_caps = persistent_target.lock().list().len();
    let mut target_table = ResourceTable::new(6, 1).unwrap();
    assert_eq!(
        install_persistent_proxy_owned::<BlobResource>(
            &mut target_table,
            BLOB_TYPE,
            &target_binding,
            &source_binding,
            source_cap,
            Rights::READ,
        ),
        Err(PersistentProxyInstallError::Authority(
            AuthorityError::PersistentProxyTarget,
        )),
    );
    assert!(target_table.is_empty());
    assert_eq!(persistent_target.lock().list().len(), target_caps);
}
