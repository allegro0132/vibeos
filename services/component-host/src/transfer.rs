use alloc::sync::Arc;
use core::{fmt, marker::PhantomData};

use vibeos_component_runtime::resource::{
    CrossTableBorrowAlias, CrossTableBorrowScope, OwnTransfer, Reservation, ResourceError,
    ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_core::cap::{
    CSpace, CSpaceIdentity, Resource, Rights, SupervisedTransferReceipt, SupervisedTransferRequest,
    SupervisedTransferStage,
};

use crate::{
    map_cap_error, AuthorityClass, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostResource, PersistentProxy,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedTransferError {
    /// A cross-principal move requires an exact supervisor derive/proxy path.
    CrossSpaceSupervisorRequired,
    SourceTable(ResourceError),
    TargetTable(ResourceError),
    Authority(AuthorityError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisedBorrowError {
    Table(ResourceError),
    Authority(AuthorityError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisedRevokeError {
    Table(ResourceError),
    Authority(AuthorityError),
}

/// Linear table-side preparation for one supervised cross-CSpace transfer.
///
/// Target capacity is reserved before source ownership is detached. Until the
/// fused registry/capability transaction accepts this guard, dropping it
/// restores the source entry and releases the target reservation.
#[must_use = "the prepared table transaction must be finalized or rolled back"]
pub struct SupervisedOwnTransferGuard<'source, 'target> {
    source_transfer: OwnTransfer<'source, ComponentAuthority>,
    target_reservation: Reservation<'target, ComponentAuthority>,
    target_type: ResourceTypeId,
}

impl fmt::Debug for SupervisedOwnTransferGuard<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SupervisedOwnTransferGuard(<active>)")
    }
}

/// Non-copy table state sealed into one core supervised-transfer stage.
///
/// Core drops this value on every prepare, postflight, or capability error, so
/// both table guards roll back. Only the postflight-success finalizer receives
/// it together with the matching one-shot capability receipt.
#[must_use = "the fused registry transaction owns finalization of this state"]
pub struct PreparedSupervisedOwnTransfer<'source, 'target> {
    source_transfer: OwnTransfer<'source, ComponentAuthority>,
    target_reservation: Reservation<'target, ComponentAuthority>,
    target_type: ResourceTypeId,
    target_cspace_identity: CSpaceIdentity,
    target_cspace_incarnation: u64,
    kind: crate::HostResourceKind,
    rights: Rights,
    class: AuthorityClass,
}

impl fmt::Debug for PreparedSupervisedOwnTransfer<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSupervisedOwnTransfer(<active>)")
    }
}

impl<'source, 'target> SupervisedOwnTransferGuard<'source, 'target> {
    /// Read-only host validation and core request preparation for an exact
    /// reserved-space pair. No CSpace or ResourceTable mutation occurs here.
    pub fn prepare_in<T: ComponentHostResource>(
        self,
        source_space: &CSpace,
        target_space: &CSpace,
        rights: Rights,
    ) -> Result<
        SupervisedTransferStage<PreparedSupervisedOwnTransfer<'source, 'target>>,
        AuthorityError,
    > {
        validate_supervised_route::<T>(source_space, target_space, rights)?;
        let source = self
            .source_transfer
            .authority()
            .map_err(|_| AuthorityError::InvalidOrRevoked)?;
        let class = validate_supervised_source::<T>(source, source_space, rights)?;
        let request = match class {
            AuthorityClass::EphemeralGrantSource => {
                SupervisedTransferRequest::prepare_attenuated_grant::<T>(
                    source_space,
                    source.cap,
                    rights,
                    target_space,
                )
            }
            AuthorityClass::PersistentProxy => unsafe {
                // The preceding validation proved the exact local proxy type
                // and class and revalidated its private durable parent.
                SupervisedTransferRequest::prepare_revocable_proxy_relocate::<PersistentProxy<T>>(
                    source_space,
                    source.cap,
                    rights,
                    target_space,
                )
            },
            AuthorityClass::Ephemeral => Err(vibeos_core::cap::CapError::InsufficientRights),
        }
        .map_err(map_cap_error)?;
        let prepared = PreparedSupervisedOwnTransfer {
            source_transfer: self.source_transfer,
            target_reservation: self.target_reservation,
            target_type: self.target_type,
            target_cspace_identity: target_space.identity(),
            target_cspace_incarnation: target_space.incarnation(),
            kind: T::HOST_KIND,
            rights,
            class: match class {
                AuthorityClass::EphemeralGrantSource => AuthorityClass::Ephemeral,
                AuthorityClass::PersistentProxy => AuthorityClass::PersistentProxy,
                AuthorityClass::Ephemeral => unreachable!("ordinary ephemeral source rejected"),
            },
        };
        Ok(request.attach(prepared))
    }
}

impl PreparedSupervisedOwnTransfer<'_, '_> {
    /// Consume the core's one-shot target selector and publish target ownership
    /// before retiring source ownership. This performs no allocation, lookup,
    /// validation, capability operation, or recoverable failure.
    pub fn commit(self, receipt: SupervisedTransferReceipt) -> ResourceToken {
        let target_authority = ComponentAuthority {
            cspace_identity: self.target_cspace_identity,
            cspace_incarnation: self.target_cspace_incarnation,
            cap: receipt.into_target_cap(),
            kind: self.kind,
            rights_ceiling: self.rights,
            class: self.class,
        };
        let target_token = self
            .target_reservation
            .commit(self.target_type, target_authority);
        drop(
            self.source_transfer
                .commit()
                .expect("prepared source transfer remains committable"),
        );
        target_token
    }
}

/// Host-only resolver for one invocation-scoped, non-capability borrow alias.
///
/// The underlying alias is lifetime-branded by `component-runtime`; this
/// wrapper adds exact source/target CSpace gates and operation-time revocation
/// checks without placing any entry or Cap in the target table.
pub struct SupervisedBorrowScope<'call, 'spaces, T: ComponentHostResource> {
    scope: CrossTableBorrowScope<'call, ComponentAuthority, ComponentAuthority>,
    source_space: &'spaces CSpace,
    rights: Rights,
    _resource: PhantomData<T>,
}

impl<T: ComponentHostResource> core::fmt::Debug for SupervisedBorrowScope<'_, '_, T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SupervisedBorrowScope(<active>)")
    }
}

impl<'call, T: ComponentHostResource> SupervisedBorrowScope<'call, '_, T> {
    pub fn alias(&self) -> CrossTableBorrowAlias<'call> {
        self.scope.alias()
    }

    pub fn with_alias<R>(
        &self,
        alias: &CrossTableBorrowAlias<'_>,
        operation: impl for<'resource> FnOnce(&'resource T) -> R,
    ) -> Result<R, SupervisedBorrowError> {
        self.scope
            .with_alias(alias, |borrowed| {
                borrowed.with(|authority| {
                    authority.with_resource_in::<T, _, _>(self.source_space, self.rights, operation)
                })
            })
            .map_err(SupervisedBorrowError::Table)?
            .map_err(SupervisedBorrowError::Authority)
    }
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

/// Reserve target capacity and detach exact source ownership before entering a
/// reserved-space pair transaction.
///
/// This performs every fallible ResourceTable operation. It does not inspect
/// or mutate either CSpace. Dropping the returned guard is a complete table
/// rollback until the fused pair transaction hands it to its finalizer.
pub fn prepare_owned_supervised<'source, 'target>(
    source_table: &'source mut ResourceTable<ComponentAuthority>,
    source_token: ResourceToken,
    source_type: ResourceTypeId,
    target_table: &'target mut ResourceTable<ComponentAuthority>,
    target_type: ResourceTypeId,
) -> Result<SupervisedOwnTransferGuard<'source, 'target>, OwnedTransferError> {
    let target_reservation = target_table
        .reserve()
        .map_err(OwnedTransferError::TargetTable)?;
    let source_transfer = source_table
        .begin_take_owned(source_token, source_type)
        .map_err(OwnedTransferError::SourceTable)?;
    Ok(SupervisedOwnTransferGuard {
        source_transfer,
        target_reservation,
        target_type,
    })
}

/// Remove one exact owned entry and revoke its local volatile authority.
///
/// Type, CSpace identity/incarnation, authority class, rights shape, and local
/// resource representation are checked while `OwnTransfer` can still restore
/// the table entry. Only then is `revoke_exact_admin` committed. A recoverable
/// rejection changes neither the table nor CSpace; after successful revocation
/// the allocation-free table commit leaves no entry or live local capability.
/// Persistent proxies are retired locally even when their private durable
/// parent was already revoked.
pub fn revoke_owned_supervised<T: ComponentHostResource>(
    table: &mut ResourceTable<ComponentAuthority>,
    token: ResourceToken,
    resource_type: ResourceTypeId,
    cspace: &mut CSpace,
) -> Result<usize, SupervisedRevokeError> {
    let transfer = table
        .begin_take_owned(token, resource_type)
        .map_err(SupervisedRevokeError::Table)?;
    let authority = transfer.authority().map_err(SupervisedRevokeError::Table)?;
    validate_supervised_revoke_source::<T>(authority, cspace)
        .map_err(SupervisedRevokeError::Authority)?;
    let revoked = cspace
        .revoke_exact_admin(authority.cap)
        .map_err(map_cap_error)
        .map_err(SupervisedRevokeError::Authority)?;
    drop(
        transfer
            .commit()
            .expect("validated owned revoke remains committable"),
    );
    Ok(revoked)
}

/// Execute one invocation-scoped cross-principal borrow without minting,
/// deriving, moving, or publishing a capability in the target.
#[allow(clippy::too_many_arguments)]
pub fn with_supervised_borrow<'spaces, T: ComponentHostResource, R>(
    source_table: &'spaces ResourceTable<ComponentAuthority>,
    source_token: ResourceToken,
    source_type: ResourceTypeId,
    source_space: &'spaces CSpace,
    target_table: &'spaces ResourceTable<ComponentAuthority>,
    target_type: ResourceTypeId,
    target_space: &'spaces CSpace,
    rights: Rights,
    operation: impl for<'call> FnOnce(SupervisedBorrowScope<'call, 'spaces, T>) -> R,
) -> Result<R, SupervisedBorrowError> {
    validate_supervised_route::<T>(source_space, target_space, rights)
        .map_err(SupervisedBorrowError::Authority)?;
    source_table
        .with_cross_table_borrow(
            source_token,
            source_type,
            target_table,
            target_type,
            |scope| {
                let validation_alias = scope.alias();
                scope
                    .with_alias(&validation_alias, |borrowed| {
                        borrowed.with(|authority| {
                            authority.with_resource_in::<T, _, _>(source_space, rights, |_| ())
                        })
                    })
                    .map_err(SupervisedBorrowError::Table)?
                    .map_err(SupervisedBorrowError::Authority)?;
                Ok(operation(SupervisedBorrowScope {
                    scope,
                    source_space,
                    rights,
                    _resource: PhantomData,
                }))
            },
        )
        .map_err(SupervisedBorrowError::Table)?
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

fn validate_supervised_source<T: ComponentHostResource>(
    source: &ComponentAuthority,
    cspace: &CSpace,
    rights: Rights,
) -> Result<AuthorityClass, AuthorityError> {
    if cspace.identity() != source.cspace_identity {
        return Err(AuthorityError::WrongSpace);
    }
    if cspace.incarnation() != source.cspace_incarnation {
        return Err(AuthorityError::IncarnationMismatch);
    }
    if source.kind != T::HOST_KIND {
        return Err(AuthorityError::WrongResourceKind);
    }
    if !source.rights_ceiling.contains(rights) {
        return Err(AuthorityError::RightsExceedCeiling);
    }
    let held = cspace.rights_of(source.cap).map_err(map_cap_error)?;
    match source.class {
        AuthorityClass::EphemeralGrantSource => {
            if held != source.rights_ceiling.union(Rights::GRANT) {
                return Err(if held.contains(Rights::GRANT) {
                    AuthorityError::RightsExceedCeiling
                } else {
                    AuthorityError::SupervisorGrantRequired
                });
            }
            drop(
                cspace
                    .lookup_revocable::<T>(source.cap, Rights::NONE)
                    .map_err(map_cap_error)?,
            );
        }
        AuthorityClass::PersistentProxy => {
            if !source.rights_ceiling.contains(held) {
                return Err(AuthorityError::RightsExceedCeiling);
            }
            if !held.contains(rights) {
                return Err(AuthorityError::InsufficientRights);
            }
            let token = cspace
                .lookup_revocable::<PersistentProxy<T>>(source.cap, Rights::NONE)
                .map_err(map_cap_error)?;
            token
                .try_with(|proxy| proxy.try_with(rights, |_| ()))
                .map_err(map_cap_error)??;
        }
        AuthorityClass::Ephemeral => return Err(AuthorityError::SupervisorGrantRequired),
    }
    if !held.contains(rights) {
        return Err(AuthorityError::InsufficientRights);
    }
    Ok(source.class)
}

fn validate_supervised_route<T: ComponentHostResource>(
    source_space: &CSpace,
    target_space: &CSpace,
    rights: Rights,
) -> Result<(), AuthorityError> {
    if core::ptr::eq(source_space, target_space)
        || source_space.identity() == target_space.identity()
    {
        return Err(AuthorityError::SupervisorDistinctSpacesRequired);
    }
    if source_space.persistent_space_id().is_some() || target_space.persistent_space_id().is_some()
    {
        return Err(AuthorityError::PersistentProxyTarget);
    }
    if !T::OPERATION_RIGHTS.contains(rights)
        || rights.intersect(Rights::GRANT.union(Rights::REVOKE).union(Rights::INVOKE))
            != Rights::NONE
    {
        return Err(AuthorityError::RightsExceedCeiling);
    }
    Ok(())
}

fn validate_supervised_revoke_source<T: ComponentHostResource>(
    authority: &ComponentAuthority,
    cspace: &CSpace,
) -> Result<(), AuthorityError> {
    if cspace.identity() != authority.cspace_identity {
        return Err(AuthorityError::WrongSpace);
    }
    if cspace.incarnation() != authority.cspace_incarnation {
        return Err(AuthorityError::IncarnationMismatch);
    }
    if authority.kind != T::HOST_KIND {
        return Err(AuthorityError::WrongResourceKind);
    }
    let held = cspace.rights_of(authority.cap).map_err(map_cap_error)?;
    match authority.class {
        AuthorityClass::Ephemeral => {
            if !authority.rights_ceiling.contains(held)
                || !T::OPERATION_RIGHTS.contains(authority.rights_ceiling)
            {
                return Err(AuthorityError::RightsExceedCeiling);
            }
            drop(
                cspace
                    .lookup_revocable::<T>(authority.cap, Rights::NONE)
                    .map_err(map_cap_error)?,
            );
        }
        AuthorityClass::EphemeralGrantSource => {
            if held != authority.rights_ceiling.union(Rights::GRANT)
                || !T::OPERATION_RIGHTS.contains(authority.rights_ceiling)
            {
                return Err(AuthorityError::RightsExceedCeiling);
            }
            drop(
                cspace
                    .lookup_revocable::<T>(authority.cap, Rights::NONE)
                    .map_err(map_cap_error)?,
            );
        }
        AuthorityClass::PersistentProxy => {
            if !authority.rights_ceiling.contains(held)
                || !T::OPERATION_RIGHTS.contains(authority.rights_ceiling)
            {
                return Err(AuthorityError::RightsExceedCeiling);
            }
            drop(
                cspace
                    .lookup_revocable::<PersistentProxy<T>>(authority.cap, Rights::NONE)
                    .map_err(map_cap_error)?,
            );
        }
    }
    Ok(())
}
