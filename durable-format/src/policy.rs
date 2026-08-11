//! Composition helpers for independently owned durable authority policies.

use alloc::vec::Vec;

use crate::{
    DerivationId, RecoveredGrant, RecoveryError, RecoveryPreflight, RootConstraint, RootPolicy,
    SpaceId,
};

/// One independently owned SpaceId partition in the global external-root
/// policy. A caller may omit a partition with no live roots; `finish` still
/// rejects every live root not selected by the resulting union.
#[derive(Clone, Copy)]
pub struct RootPolicyPartition<'a> {
    pub space: SpaceId,
    pub constraints: &'a [RootConstraint],
}

pub fn select_root_policy_union(
    preflight: &RecoveryPreflight,
    partitions: &[RootPolicyPartition<'_>],
) -> Result<Vec<RootPolicy>, RecoveryError> {
    let mut constraints = Vec::new();
    for (index, partition) in partitions.iter().enumerate() {
        if partitions[..index]
            .iter()
            .any(|other| other.space == partition.space)
        {
            return Err(RecoveryError::InvalidRootConstraint);
        }
        for (constraint_index, constraint) in partition.constraints.iter().enumerate() {
            if constraint.space != partition.space
                || partition.constraints[..constraint_index]
                    .iter()
                    .any(|other| {
                        other.first_slot <= constraint.last_slot_inclusive
                            && constraint.first_slot <= other.last_slot_inclusive
                    })
            {
                return Err(RecoveryError::InvalidRootConstraint);
            }
            constraints.push(*constraint);
        }
    }
    preflight.select_roots(&constraints)
}

/// Tombstones are global records, but recovered CSpace validators are owned by
/// one `SpaceId` each. This result preserves the caller's partition order while
/// assigning every explicit tombstone to the space of its original committed
/// grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstonePartition {
    pub space: SpaceId,
    pub tombstones: Vec<DerivationId>,
}

/// Failure to partition global tombstones across independent policy owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombstonePartitionError {
    DuplicateSpace,
    ForeignSpace,
    UnknownDerivation,
    CrossSpaceDerivation,
}

/// Partition global tombstones without allowing authority ancestry to cross an
/// independently validated CSpace boundary. `committed` must be the preflight
/// history, not the live-only grant set returned by `finish`, because the grant
/// named by a tombstone is no longer live there.
pub fn partition_tombstones_by_space(
    committed: &[RecoveredGrant],
    tombstones: &[DerivationId],
    spaces: &[SpaceId],
) -> Result<Vec<TombstonePartition>, TombstonePartitionError> {
    let mut partitions = Vec::with_capacity(spaces.len());
    for (index, space) in spaces.iter().copied().enumerate() {
        if spaces[..index].contains(&space) {
            return Err(TombstonePartitionError::DuplicateSpace);
        }
        partitions.push(TombstonePartition {
            space,
            tombstones: Vec::new(),
        });
    }

    // Reject foreign grants even when they are fully tombstoned and therefore
    // absent from the live grant set. Also reject a derived edge whose parent
    // belongs to another policy partition: a tombstone on that parent would
    // otherwise silently revoke authority across validator boundaries.
    for recovered in committed {
        let grant = &recovered.grant;
        if !spaces.contains(&grant.target.space) {
            return Err(TombstonePartitionError::ForeignSpace);
        }
        if let Some(parent_id) = grant.parent_id {
            let parent = committed
                .iter()
                .find(|candidate| candidate.grant.derivation_id == parent_id)
                .ok_or(TombstonePartitionError::UnknownDerivation)?;
            if parent.grant.target.space != grant.target.space {
                return Err(TombstonePartitionError::CrossSpaceDerivation);
            }
        }
    }

    for tombstone in tombstones {
        let grant = committed
            .iter()
            .find(|candidate| candidate.grant.derivation_id == *tombstone)
            .ok_or(TombstonePartitionError::UnknownDerivation)?;
        let partition = partitions
            .iter_mut()
            .find(|partition| partition.space == grant.grant.target.space)
            .ok_or(TombstonePartitionError::ForeignSpace)?;
        partition.tombstones.push(*tombstone);
    }
    Ok(partitions)
}
