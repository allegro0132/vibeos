use std::any::Any;
use std::sync::Arc;

use vibeos_component_host::{
    transfer_owned, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostResource, HostResourceKind, OwnedTransferError, SharedCSpace,
};
use vibeos_component_runtime::resource::{ResourceError, ResourceTable, ResourceTypeId};
use vibeos_core::cap::{CSpace, Cap, Resource, Rights};
use vibeos_core::sync::SpinLock;

const SOURCE_TYPE: ResourceTypeId = ResourceTypeId(11);
const TARGET_TYPE: ResourceTypeId = ResourceTypeId(21);

struct Probe(u32);

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
