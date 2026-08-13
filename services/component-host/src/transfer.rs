use alloc::sync::Arc;

use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_core::cap::{move_cap, Resource, Rights};

use crate::{
    map_cap_error, AuthorityClass, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostResource,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedTransferError {
    SourceTable(ResourceError),
    TargetTable(ResourceError),
    Authority(AuthorityError),
}

/// Transactionally move one component resource-table ownership entry.
///
/// All fallible table reservations and authority checks occur before the
/// allocation-free table commit. On failure, `OwnTransfer` restores the source
/// entry and `Reservation` restores target capacity. Cross-CSpace moves use the
/// supervisor's atomic capability relocation primitive; no second live cap or
/// component-table owner remains.
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
    let target_reservation = target_table
        .reserve()
        .map_err(OwnedTransferError::TargetTable)?;
    let source_transfer = source_table
        .begin_take_owned(source_token, source_type)
        .map_err(OwnedTransferError::SourceTable)?;
    let same_space = Arc::ptr_eq(&source_space.inner.cspace, &target_space.inner.cspace);
    if same_space {
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
        return Ok(target_reservation.commit(target_type, authority));
    }

    let target_authority = move_target::<T>(
        source_transfer
            .authority()
            .map_err(OwnedTransferError::SourceTable)?,
        source_space,
        target_space,
        rights,
    )
    .map_err(OwnedTransferError::Authority)?;

    // From here both operations are allocation-free and cannot fail for live
    // guards. Commit the target before making the source handle stale.
    let target_token = target_reservation.commit(target_type, target_authority);
    let _retired = source_transfer
        .commit()
        .expect("a live source transfer remains committable");
    Ok(target_token)
}

fn move_target<T: ComponentHostResource>(
    source: &ComponentAuthority,
    source_space: &ComponentAuthoritySpace,
    target_space: &ComponentAuthoritySpace,
    rights: Rights,
) -> Result<ComponentAuthority, AuthorityError> {
    if source.class != AuthorityClass::Ephemeral {
        return Err(AuthorityError::RawPersistentAuthority);
    }
    if source.kind != T::HOST_KIND {
        return Err(AuthorityError::WrongResourceKind);
    }
    if !source.rights_ceiling.contains(rights) {
        return Err(AuthorityError::RightsExceedCeiling);
    }

    let target_cap = {
        // Pointer order gives every cross-space caller the same lock order.
        let source_pointer = Arc::as_ptr(&source_space.inner.cspace) as usize;
        let target_pointer = Arc::as_ptr(&target_space.inner.cspace) as usize;
        if source_pointer < target_pointer {
            let source_guard = source_space.inner.cspace.lock();
            source_space.check_incarnation(&source_guard)?;
            validate_source::<T>(source, &source_guard, rights)?;
            let mut target_guard = target_space.inner.cspace.lock();
            target_space.check_incarnation(&target_guard)?;
            let mut source_guard = source_guard;
            move_cap(&mut source_guard, source.cap, rights, &mut target_guard)
                .map_err(map_cap_error)?
        } else {
            let mut target_guard = target_space.inner.cspace.lock();
            target_space.check_incarnation(&target_guard)?;
            let source_guard = source_space.inner.cspace.lock();
            source_space.check_incarnation(&source_guard)?;
            validate_source::<T>(source, &source_guard, rights)?;
            let mut source_guard = source_guard;
            move_cap(&mut source_guard, source.cap, rights, &mut target_guard)
                .map_err(map_cap_error)?
        }
    };

    Ok(target_space.authority(target_cap, T::HOST_KIND, rights, AuthorityClass::Ephemeral))
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
