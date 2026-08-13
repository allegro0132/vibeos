use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vibeos_component_format::TrapCode;
use vibeos_component_host::{
    transfer_owned, AuthorityError, ComponentAuthority, ComponentAuthoritySpace,
    ComponentHostDispatcher, OwnedTransferError, RandomBackend, RandomBackendFault, RandomResource,
    SharedCSpace, VibeHostManifest, MAX_RANDOM_FILL_BYTES,
};
use vibeos_component_runtime::decode::inspect_component;
use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_component_runtime::sync::{SyncError, SynchronousComponent, TypedPoll};
use vibeos_component_runtime::value::CanonicalValue;
use vibeos_core::cap::{CSpace, Cap, Rights};
use vibeos_core::sync::SpinLock;
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const RANDOM_COMPONENT: &str = include_str!("fixtures/host-random.component.wat");
const RESOURCE_TYPE: ResourceTypeId = ResourceTypeId(1);
const STEPS: usize = 512;

struct CountingRandom {
    calls: AtomicUsize,
}

impl RandomBackend for CountingRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomBackendFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        destination.fill(0xa7);
        Ok(())
    }
}

struct Side {
    cspace: SharedCSpace,
    binding: ComponentAuthoritySpace,
    table: ResourceTable<ComponentAuthority>,
    token: Option<ResourceToken>,
    cap: Option<Cap>,
}

impl Side {
    fn new(name: &str, generation: u64) -> Self {
        let cspace = Arc::new(SpinLock::new(CSpace::new(name)));
        let binding = ComponentAuthoritySpace::new(cspace.clone(), 1).unwrap();
        Self {
            cspace,
            binding,
            table: ResourceTable::new(generation, 1).unwrap(),
            token: None,
            cap: None,
        }
    }

    fn insert(&mut self, backend: &Arc<CountingRandom>) {
        if self.token.is_some() {
            return;
        }
        let cap = self
            .cspace
            .lock()
            .mint(Arc::new(RandomResource::new(backend.clone())), Rights::READ);
        let authority = self
            .binding
            .bind_ephemeral::<RandomResource>(cap, Rights::READ)
            .unwrap();
        self.token = Some(self.table.insert_owned(RESOURCE_TYPE, authority).unwrap());
        self.cap = Some(cap);
    }

    fn drop_resource(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let authority = self.table.drop_owned(token, RESOURCE_TYPE).unwrap();
        let was_live = self.cap_is_live();
        let revoked = self.binding.revoke_dropped(authority);
        assert_eq!(revoked.is_ok(), was_live);
        self.cap = None;
    }

    fn revoke(&mut self) {
        if let Some(cap) = self.cap.filter(|_| self.cap_is_live()) {
            assert_eq!(self.cspace.lock().revoke_slot(cap.slot()), 1);
        }
    }

    fn cap_is_live(&self) -> bool {
        self.cap
            .is_some_and(|cap| self.cspace.lock().lookup(cap, Rights::READ).is_ok())
    }

    fn assert_invariants(&mut self) {
        assert_eq!(self.table.len(), usize::from(self.token.is_some()));
        let published = self.cspace.lock().list().len();
        let cap_is_live = self.cap_is_live();
        assert_eq!(published, usize::from(cap_is_live));
        match self.token {
            Some(token) => {
                assert_eq!(self.table.contains(token, RESOURCE_TYPE), Ok(true));
                let observed = self
                    .table
                    .with_borrow(token, RESOURCE_TYPE, |borrowed| {
                        borrowed.with(|authority| {
                            authority
                                .with_resource::<RandomResource, _, _>(
                                    &self.cspace,
                                    Rights::READ,
                                    |_| (),
                                )
                                .is_ok()
                        })
                    })
                    .unwrap();
                assert_eq!(observed, self.cap_is_live());
            }
            None => assert!(self.table.is_empty()),
        }
    }
}

fn instantiate(source: &str) -> SynchronousComponent {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn dispatcher(cspace: SharedCSpace, source: &str) -> ComponentHostDispatcher {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let manifest = VibeHostManifest::from_plan(&plan).unwrap();
    ComponentHostDispatcher::new(cspace, manifest)
}

fn invoke(
    side: &mut Side,
    source: &str,
    len: u32,
) -> (Result<CanonicalValue, TrapCode>, SynchronousComponent) {
    let token = side.token.expect("model operation requires one resource");
    let mut component = instantiate(source);
    let mut host = dispatcher(side.cspace.clone(), source);
    let mut call = component
        .start_typed_call_with_host(
            &mut side.table,
            &mut host,
            "run",
            vec![CanonicalValue::Resource(token), CanonicalValue::U32(len)],
            100_000,
            100,
        )
        .unwrap();
    let terminal = (0..100_000)
        .find_map(|_| match call.poll() {
            TypedPoll::Pending(_) => None,
            TypedPoll::Ready(value) => Some(Ok(value)),
            TypedPoll::HostFailed(error) => panic!("joint-model host failed: {error:?}"),
            TypedPoll::Trapped(trap) => Some(Err(trap)),
        })
        .expect("bounded model call terminates");
    drop(call);
    (terminal, component)
}

fn assert_bytes(value: &CanonicalValue, len: usize) {
    let CanonicalValue::Result(Ok(Some(payload))) = value else {
        panic!("successful random call returned a non-result payload: {value:?}");
    };
    let CanonicalValue::List(bytes) = payload.as_ref() else {
        panic!("host pointer or another non-list value escaped: {payload:?}");
    };
    assert_eq!(bytes.len(), len);
    assert!(bytes.iter().all(|value| *value == CanonicalValue::U8(0xa7)));
}

fn assert_denied(value: &CanonicalValue) {
    assert_eq!(
        value,
        &CanonicalValue::Result(Err(Some(Box::new(CanonicalValue::Enum(0)))))
    );
}

fn grow_source() -> String {
    let source = RANDOM_COMPONENT
        .replace("(memory (export \"memory\") 1 1)", "(memory (export \"memory\") 1 2)")
        .replace(
            "(import \"env\" \"memory\" (memory 1 1))",
            "(import \"env\" \"memory\" (memory 1 2))",
        )
        .replace(
            "      local.get $source\n      local.get $len",
            "      i32.const 1\n      memory.grow\n      drop\n      local.get $source\n      local.get $len",
        );
    assert_ne!(source, RANDOM_COMPONENT);
    source
}

fn alias_source() -> String {
    let source = RANDOM_COMPONENT.replace(
        r#"(data (i32.const 0) "\00\40\00\00")"#,
        r#"(data (i32.const 0) "\00\02\00\00")"#,
    );
    assert_ne!(source, RANDOM_COMPONENT);
    source
}

fn trap_source() -> String {
    let source = RANDOM_COMPONENT.replace(
        "      call $fill\n      i32.const 512)",
        "      call $fill\n      unreachable)",
    );
    assert_ne!(source, RANDOM_COMPONENT);
    source
}

fn invoke_normal(side: &mut Side, backend: &CountingRandom, len: u32) {
    let before = backend.calls.load(Ordering::SeqCst);
    let live = side.cap_is_live();
    let (result, component) = invoke(side, RANDOM_COMPONENT, len);
    assert!(!component.is_poisoned());
    let value = result.unwrap();
    if live {
        assert_bytes(&value, len as usize);
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            before + usize::from(len != 0)
        );
    } else {
        assert_denied(&value);
        assert_eq!(backend.calls.load(Ordering::SeqCst), before);
    }
}

fn invoke_grow(side: &mut Side, backend: &CountingRandom, source: &str) {
    let before = backend.calls.load(Ordering::SeqCst);
    let (result, component) = invoke(side, source, 3);
    assert_eq!(result, Err(TrapCode::LimitExceeded));
    assert!(component.is_poisoned());
    assert_eq!(backend.calls.load(Ordering::SeqCst), before);
}

fn invoke_alias(side: &mut Side, backend: &CountingRandom, source: &str) {
    let before = backend.calls.load(Ordering::SeqCst);
    let (result, component) = invoke(side, source, 3);
    assert_eq!(result, Err(TrapCode::CanonicalAbi));
    assert!(component.is_poisoned());
    assert_eq!(backend.calls.load(Ordering::SeqCst), before);
}

fn invoke_trap(side: &mut Side, backend: &CountingRandom, source: &str) {
    let before = backend.calls.load(Ordering::SeqCst);
    let live = side.cap_is_live();
    let (result, component) = invoke(side, source, 2);
    assert_eq!(result, Err(TrapCode::Unreachable));
    assert!(component.is_poisoned());
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        before + usize::from(live)
    );
}

fn probe_exhaustion(side: &mut Side, backend: &Arc<CountingRandom>) {
    if side.token.is_none() {
        return;
    }
    let cap = side
        .cspace
        .lock()
        .mint(Arc::new(RandomResource::new(backend.clone())), Rights::READ);
    let authority = side
        .binding
        .bind_ephemeral::<RandomResource>(cap, Rights::READ)
        .unwrap();
    let failure = side
        .table
        .insert_owned(RESOURCE_TYPE, authority)
        .unwrap_err();
    let (error, authority) = failure.into_parts();
    assert_eq!(error, ResourceError::TableFull);
    assert_eq!(side.binding.revoke_dropped(authority), Ok(1));
}

fn move_resource(source: &mut Side, target: &mut Side) {
    let (Some(token), None) = (source.token, target.token) else {
        return;
    };
    let was_live = source.cap_is_live();
    let result = transfer_owned::<RandomResource>(
        &mut source.table,
        token,
        RESOURCE_TYPE,
        &source.binding,
        &mut target.table,
        RESOURCE_TYPE,
        &target.binding,
        Rights::READ,
    );
    if was_live {
        let token = result.unwrap();
        source.token = None;
        source.cap = None;
        target.token = Some(token);
        target.cap = target.cspace.lock().list().last().map(|item| item.0);
        assert!(target.cap.is_some());
    } else {
        assert_eq!(
            result,
            Err(OwnedTransferError::Authority(
                AuthorityError::InvalidOrRevoked
            ))
        );
        assert_eq!(source.table.contains(token, RESOURCE_TYPE), Ok(true));
    }
}

fn probe_cross_table(source: &Side, target: &mut Side, backend: &CountingRandom) {
    let (Some(foreign), Some(_)) = (source.token, target.token) else {
        return;
    };
    let before = backend.calls.load(Ordering::SeqCst);
    let mut component = instantiate(RANDOM_COMPONENT);
    let mut host = dispatcher(target.cspace.clone(), RANDOM_COMPONENT);
    assert!(matches!(
        component.start_typed_call_with_host(
            &mut target.table,
            &mut host,
            "run",
            vec![CanonicalValue::Resource(foreign), CanonicalValue::U32(1)],
            100_000,
            100,
        ),
        Err(SyncError::Resource)
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), before);
}

fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

/// C3.6 joint state-machine evidence. Real Component/Canonical ABI execution
/// is interleaved with the same resource tables and CSpaces being moved,
/// dropped, revoked, exhausted and rolled back after traps.
#[test]
fn seeded_canonical_abi_and_capability_state_never_strands_authority() {
    let grow = grow_source();
    let alias = alias_source();
    let trap = trap_source();
    let backend = Arc::new(CountingRandom {
        calls: AtomicUsize::new(0),
    });

    for initial_seed in [1_u64, 0x9e37_79b9_7f4a_7c15, u64::MAX - 58] {
        let mut seed = initial_seed;
        let mut left = Side::new("joint-left", initial_seed | 1);
        let mut right = Side::new("joint-right", initial_seed.wrapping_add(2) | 1);
        left.insert(&backend);

        // A deterministic prefix guarantees every acceptance transition is
        // live even if a later pseudo-random operation becomes a no-op.
        invoke_normal(&mut left, &backend, 4);
        invoke_grow(&mut left, &backend, &grow);
        invoke_alias(&mut left, &backend, &alias);
        invoke_trap(&mut left, &backend, &trap);
        probe_exhaustion(&mut left, &backend);
        right.insert(&backend);
        probe_cross_table(&left, &mut right, &backend);
        right.drop_resource();
        move_resource(&mut left, &mut right);
        right.revoke();
        invoke_normal(&mut right, &backend, 1);
        right.drop_resource();
        right.insert(&backend);
        move_resource(&mut right, &mut left);

        for _ in 0..STEPS {
            let choose_left = next(&mut seed) & 1 == 0;
            let operation = next(&mut seed) % 12;
            let (selected, peer) = if choose_left {
                (&mut left, &mut right)
            } else {
                (&mut right, &mut left)
            };
            match operation {
                0 => selected.insert(&backend),
                1 if selected.token.is_some() => {
                    invoke_normal(selected, &backend, (next(&mut seed) % 8) as u32)
                }
                2 if selected.token.is_some() => invoke_grow(selected, &backend, &grow),
                3 if selected.token.is_some() => invoke_alias(selected, &backend, &alias),
                4 if selected.token.is_some() => invoke_trap(selected, &backend, &trap),
                5 => probe_exhaustion(selected, &backend),
                6 => move_resource(selected, peer),
                7 => selected.revoke(),
                8 => selected.drop_resource(),
                9 => probe_cross_table(peer, selected, &backend),
                10 => {
                    if let Some(token) = selected.token {
                        let transfer = selected
                            .table
                            .begin_take_owned(token, RESOURCE_TYPE)
                            .unwrap();
                        drop(transfer);
                        assert_eq!(selected.table.contains(token, RESOURCE_TYPE), Ok(true));
                    }
                }
                11 if selected.token.is_some() => {
                    let before = backend.calls.load(Ordering::SeqCst);
                    let (result, _) = invoke(
                        selected,
                        RANDOM_COMPONENT,
                        u32::try_from(MAX_RANDOM_FILL_BYTES + 1).unwrap(),
                    );
                    assert!(result.is_ok());
                    assert_eq!(backend.calls.load(Ordering::SeqCst), before);
                }
                _ => {}
            }
            left.assert_invariants();
            right.assert_invariants();
            assert!(left.table.len() + right.table.len() <= 2);
        }

        left.drop_resource();
        right.drop_resource();
        left.assert_invariants();
        right.assert_invariants();
        assert!(left.cspace.lock().list().is_empty());
        assert!(right.cspace.lock().list().is_empty());
    }
}
