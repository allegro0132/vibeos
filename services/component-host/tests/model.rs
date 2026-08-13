use std::any::Any;
use std::sync::Arc;

use vibeos_component_host::{
    transfer_owned, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostResource, HostResourceKind, OwnedTransferError, SharedCSpace,
};
use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_core::cap::{CSpace, Cap, CapError, Resource, Rights};
use vibeos_core::sync::SpinLock;

const RESOURCE_TYPE: ResourceTypeId = ResourceTypeId(31);
const FOREIGN_TYPE: ResourceTypeId = ResourceTypeId(32);
const STEPS: usize = 512;

struct Probe(u64);

impl Resource for Probe {
    fn kind(&self) -> &'static str {
        "model-probe"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ComponentHostResource for Probe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

struct Side {
    cspace: SharedCSpace,
    binding: ComponentAuthoritySpace,
    table: ResourceTable<ComponentAuthority>,
    token: Option<ResourceToken>,
    cap: Option<Cap>,
    value: Option<u64>,
}

impl Side {
    fn new(name: &str, generation: u64, maximum: u16) -> Self {
        let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
        let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
        Self {
            cspace,
            binding,
            table: ResourceTable::new(generation, maximum).unwrap(),
            token: None,
            cap: None,
            value: None,
        }
    }

    fn insert(&mut self, value: u64) {
        if self.token.is_some() {
            return;
        }
        let cap = self
            .cspace
            .lock()
            .mint(Arc::new(Probe(value)), Rights::READ);
        let authority = self
            .binding
            .bind_ephemeral::<Probe>(cap, Rights::READ)
            .unwrap();
        match self.table.insert_owned(RESOURCE_TYPE, authority) {
            Ok(token) => {
                self.token = Some(token);
                self.cap = Some(cap);
                self.value = Some(value);
            }
            Err(failure) => {
                let (error, _authority) = failure.into_parts();
                assert_eq!(error, ResourceError::TableFull);
                assert_eq!(self.cspace.lock().revoke_slot(cap.slot()), 1);
            }
        }
    }

    fn assert_model(&mut self) {
        assert_eq!(self.table.len(), usize::from(self.token.is_some()));
        match (self.token, self.cap, self.value) {
            (Some(token), Some(cap), Some(value)) => {
                assert_eq!(self.table.contains(token, RESOURCE_TYPE), Ok(true));
                let expected = self.cspace.lock().lookup(cap, Rights::READ).is_ok();
                let observed = self
                    .table
                    .with_borrow(token, RESOURCE_TYPE, |borrowed| {
                        borrowed.with(|authority| {
                            authority.with_revocable::<Probe, _, _>(
                                &self.cspace,
                                Rights::READ,
                                |probe| probe.0,
                            )
                        })
                    })
                    .unwrap();
                if expected {
                    assert_eq!(observed, Ok(value));
                } else {
                    assert_eq!(observed, Err(AuthorityError::InvalidOrRevoked));
                }
            }
            (None, None, None) => assert!(self.table.is_empty()),
            _ => panic!("state model fields diverged"),
        }
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn model_move(source: &mut Side, target: &mut Side, hostile: bool) {
    let Some(token) = source.token else {
        return;
    };
    if target.token.is_some() {
        return;
    }
    let old_cap = source.cap.unwrap();
    let old_value = source.value.unwrap();
    let source_was_live = source.cspace.lock().lookup(old_cap, Rights::READ).is_ok();
    let result = transfer_owned::<Probe>(
        &mut source.table,
        token,
        if hostile { FOREIGN_TYPE } else { RESOURCE_TYPE },
        &source.binding,
        &mut target.table,
        RESOURCE_TYPE,
        &target.binding,
        Rights::READ,
    );
    if hostile {
        assert_eq!(
            result,
            Err(OwnedTransferError::SourceTable(ResourceError::WrongType)),
        );
        assert_eq!(source.table.contains(token, RESOURCE_TYPE), Ok(true));
        let still_live = source.cspace.lock().lookup(old_cap, Rights::READ).is_ok();
        let operation_live = source
            .table
            .with_borrow(token, RESOURCE_TYPE, |borrowed| {
                borrowed.with(|authority| {
                    authority
                        .with_revocable::<Probe, _, _>(&source.cspace, Rights::READ, |_| ())
                        .is_ok()
                })
            })
            .unwrap();
        assert_eq!(still_live, operation_live);
    } else {
        if !source_was_live {
            assert_eq!(
                result,
                Err(OwnedTransferError::Authority(
                    AuthorityError::InvalidOrRevoked,
                )),
            );
            assert_eq!(source.table.contains(token, RESOURCE_TYPE), Ok(true));
            return;
        }
        let target_token = result.unwrap();
        assert_eq!(
            source.cspace.lock().lookup(old_cap, Rights::READ).err(),
            Some(CapError::Invalid),
        );
        source.token = None;
        source.cap = None;
        source.value = None;
        target.token = Some(target_token);
        target.cap = target.cspace.lock().list().last().map(|entry| entry.0);
        target.value = Some(old_value);
    }
}

/// Deterministic state-machine coverage across the table/capability boundary.
/// "Trap" is modelled by beginning and abandoning an ownership transaction;
/// the RAII guard must restore the source exactly as a cancelled Canonical ABI
/// call does before any authority transfer is committed.
#[test]
fn seeded_resource_capability_state_machine_preserves_linear_ownership() {
    for initial_seed in [1_u64, 0x9e37_79b9_7f4a_7c15, u64::MAX - 58] {
        let mut seed = initial_seed;
        let mut left = Side::new("model-left", 1, 1);
        let mut right = Side::new("model-right", 2, 1);
        let mut value = 1_u64;

        for _ in 0..STEPS {
            match next(&mut seed) % 8 {
                0 => {
                    left.insert(value);
                    value = value.wrapping_add(1);
                }
                1 => {
                    right.insert(value);
                    value = value.wrapping_add(1);
                }
                2 => model_move(&mut left, &mut right, false),
                3 => model_move(&mut right, &mut left, false),
                4 => model_move(&mut left, &mut right, true),
                5 => model_move(&mut right, &mut left, true),
                6 => {
                    let side = if next(&mut seed) & 1 == 0 {
                        &mut left
                    } else {
                        &mut right
                    };
                    if let Some(token) = side.token {
                        let transfer = side.table.begin_take_owned(token, RESOURCE_TYPE).unwrap();
                        drop(transfer);
                        assert_eq!(side.table.contains(token, RESOURCE_TYPE), Ok(true));
                    }
                }
                _ => {
                    let side = if next(&mut seed) & 1 == 0 {
                        &mut left
                    } else {
                        &mut right
                    };
                    if let Some(cap) = side.cap {
                        side.cspace.lock().revoke_slot(cap.slot());
                    }
                }
            }
            left.assert_model();
            right.assert_model();
            assert!(left.table.len() + right.table.len() <= 2);
        }
    }
}
