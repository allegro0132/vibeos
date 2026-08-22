use alloc::sync::Arc;

use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_core::cap::{Resource, Rights};

use crate::{
    map_cap_error, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostResource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedTransferError {
    /// A cross-principal move requires an exact supervisor derive/proxy path.
    CrossSpaceSupervisorRequired,
    SourceTable(ResourceError),
    TargetTable(ResourceError),
    Authority(AuthorityError),
}

/// Transactionally move one ownership entry between tables in the same CSpace.
///
/// All fallible table reservations and authority checks occur before the
/// allocation-free table commit. On failure, `OwnTransfer` restores the source
/// entry and `Reservation` restores target capacity. A cross-CSpace move is a
/// cross-principal authority transfer and must instead use a separately reviewed
/// supervisor path that derives or proxies the target authority before retiring
/// the source handle.
#[allow(clippy::too_many_arguments)]
pub fn transfer_owned<T: ComponentHostResource>(
    source_table: &mut ResourceTable<ComponentAuthority>,
    source_token: ResourceToken,
    source_type: ResourceTypeId,
    source_space: &ComponentAuthoritySpace,
    target_table: &mut ResourceTable<ComponentAuthority>,
    target_type: ResourceTypeId,
    target_space: &ComponentAuthoritySpace,
    rights: Rights,
) -> Result<ResourceToken, OwnedTransferError> {
    if !Arc::ptr_eq(&source_space.inner.cspace, &target_space.inner.cspace) {
        return Err(OwnedTransferError::CrossSpaceSupervisorRequired);
    }

    let target_reservation = target_table
        .reserve()
        .map_err(OwnedTransferError::TargetTable)?;
    let source_transfer = source_table
        .begin_take_owned(source_token, source_type)
        .map_err(OwnedTransferError::SourceTable)?;
    let guard = source_space.inner.cspace.lock();
    source_space
        .check_incarnation(&guard)
        .map_err(OwnedTransferError::Authority)?;
    target_space
        .check_incarnation(&guard)
        .map_err(OwnedTransferError::Authority)?;
    let held = validate_source::<T>(
        source_transfer
            .authority()
            .map_err(OwnedTransferError::SourceTable)?,
        &guard,
        rights,
    )
    .map_err(OwnedTransferError::Authority)?;
    if held != rights {
        return Err(OwnedTransferError::Authority(
            AuthorityError::RightsExceedCeiling,
        ));
    }
    drop(guard);

    // No capability relocation is needed: ownership of the exact same
    // authority value moves directly between the two component tables.
    let authority = source_transfer
        .commit()
        .expect("a live source transfer remains committable");
    Ok(target_reservation.commit(target_type, authority))
}

fn validate_source<T: Resource>(
    source: &ComponentAuthority,
    cspace: &vibeos_core::cap::CSpace,
    rights: Rights,
) -> Result<Rights, AuthorityError> {
    if cspace.identity() != source.cspace_identity {
        return Err(AuthorityError::WrongSpace);
    }
    if cspace.incarnation() != source.cspace_incarnation {
        return Err(AuthorityError::IncarnationMismatch);
    }
    let held = cspace.rights_of(source.cap).map_err(map_cap_error)?;
    if !source.rights_ceiling.contains(held) || !source.rights_ceiling.contains(rights) {
        return Err(AuthorityError::RightsExceedCeiling);
    }
    if !held.contains(rights) {
        return Err(AuthorityError::InsufficientRights);
    }
    drop(
        cspace
            .lookup_revocable::<T>(source.cap, Rights::NONE)
            .map_err(map_cap_error)?,
    );
    Ok(held)
}
