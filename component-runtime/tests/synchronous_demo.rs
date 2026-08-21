use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, FuncAddr, InstantiationOutcome, Store as DlrStore, Value,
};
use vibeos_component_format::TrapCode;
use vibeos_component_runtime::{
    decode::inspect_component,
    resource::{ResourceTable, ResourceToken, ResourceTypeId},
    sync::{SyncError, SynchronousComponent, TypedCall, TypedPoll},
    value::CanonicalValue,
    world::WorldContract,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

const COMPONENT: &str = include_str!("fixtures/rich.component.wat");
const WORLD: &str = include_str!("../../component-format/tests/corpus/wit/world.wit");
const EXACT_WORLD: &str = "vibe:fixture/typed-filter@1.0.0";
const TRANSFORM: &str = "vibe:fixture/filter@1.0.0#transform";
const RANDOM_SOURCE: ResourceTypeId = ResourceTypeId(1);

fn instantiate() -> SynchronousComponent {
    instantiate_source(COMPONENT)
}

fn instantiate_source(source: &str) -> SynchronousComponent {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract::parse(WORLD, EXACT_WORLD).unwrap();
    plan.check_world(&world).unwrap();
    SynchronousComponent::instantiate(
        &plan,
        &ProfileEngine::new(),
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn arguments(token: ResourceToken, label: &str, payload: &[u8]) -> Vec<CanonicalValue> {
    vec![
        CanonicalValue::Record(vec![
            CanonicalValue::String(label.to_owned()),
            CanonicalValue::List(payload.iter().copied().map(CanonicalValue::U8).collect()),
            CanonicalValue::Flags(vec![0b11]),
        ]),
        CanonicalValue::Resource(token),
    ]
}

fn expected(label: &str, payload: &[u8]) -> CanonicalValue {
    CanonicalValue::Variant {
        case: 0,
        payload: Some(Box::new(CanonicalValue::Tuple(vec![
            CanonicalValue::String(label.to_ascii_uppercase()),
            CanonicalValue::List(
                payload
                    .iter()
                    .map(|byte| CanonicalValue::U8(byte ^ 0x5a))
                    .collect(),
            ),
        ]))),
    }
}

fn drive(call: &mut TypedCall<'_, u32>) -> (CanonicalValue, usize) {
    let mut pending = 0;
    let mut previous = call.metrics();
    for _ in 0..50_000 {
        match call.poll() {
            TypedPoll::Pending(metrics) => {
                pending += 1;
                assert!(metrics.consumed_work >= previous.consumed_work);
                assert!(metrics.remaining_work <= previous.remaining_work);
                assert_eq!(metrics.consumed_work + metrics.remaining_work, 100_000);
                previous = metrics;
            }
            TypedPoll::HostPending(operation) => {
                panic!("host-free demo unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Ready(value) => return (value, pending),
            TypedPoll::HostFailed(error) => panic!("unexpected host failure: {error:?}"),
            TypedPoll::Trapped(trap) => panic!("unexpected typed-call trap: {trap:?}"),
        }
    }
    panic!("bounded typed call failed to terminate")
}

fn read_u32(component: &SynchronousComponent, offset: u32) -> u32 {
    let mut bytes = [0; 4];
    component
        .read_export_memory(TRANSFORM, offset, &mut bytes)
        .unwrap();
    u32::from_le_bytes(bytes)
}

fn invoke_reference(
    store: &mut DlrStore<()>,
    function: FuncAddr,
    values: Vec<Value>,
) -> Vec<Value> {
    // SAFETY: every address is resolved from this store's just-instantiated,
    // import-free fixture and each argument list matches its validated type.
    unsafe { store.invoke_simple(function, values) }.unwrap()
}

fn invoke_reference_i32(store: &mut DlrStore<()>, function: FuncAddr, values: Vec<Value>) -> u32 {
    match invoke_reference(store, function, values).as_slice() {
        [Value::I32(value)] => *value,
        _ => panic!("reference function returned the wrong shape"),
    }
}

#[test]
fn pinned_reference_engine_agrees_on_the_executable_fixture_and_abi_layout() {
    let component = wat::parse_str(COMPONENT).unwrap();
    let plan = inspect_component(&component).unwrap();
    let module = decode_and_validate(plan.embedded_modules()[0], &mut ()).unwrap();
    let mut store = DlrStore::new(());
    // SAFETY: the embedded fixture is import-free and was decoded into this store.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { store.module_instantiate(&module, vec![], None) }.unwrap();
    let export = |name| -> ExternVal {
        // SAFETY: `module_addr` belongs to `store`; each kind is checked below.
        unsafe { store.instance_export(module_addr, name) }.unwrap()
    };
    let memory = export("memory").as_mem().unwrap();
    let realloc = export("cabi_realloc").as_func().unwrap();
    let transform = export("transform").as_func().unwrap();
    let post_return = export("cabi_post_transform").as_func().unwrap();
    let label = b"vibe";
    let payload = [1_u8, 2, 3];

    let label_pointer = invoke_reference_i32(
        &mut store,
        realloc,
        vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(4)],
    );
    let payload_pointer = invoke_reference_i32(
        &mut store,
        realloc,
        vec![Value::I32(0), Value::I32(0), Value::I32(1), Value::I32(3)],
    );
    // SAFETY: both spans were returned by this store's bounded guest allocator.
    let bytes = unsafe { store.mem_data_mut(memory) };
    bytes[label_pointer as usize..label_pointer as usize + label.len()].copy_from_slice(label);
    bytes[payload_pointer as usize..payload_pointer as usize + payload.len()]
        .copy_from_slice(&payload);

    let result_pointer = invoke_reference_i32(
        &mut store,
        transform,
        vec![
            Value::I32(label_pointer),
            Value::I32(label.len() as u32),
            Value::I32(payload_pointer),
            Value::I32(payload.len() as u32),
            Value::I32(0b11),
            Value::I32(0x1234_5678),
        ],
    );
    assert_eq!(result_pointer, 512);
    // SAFETY: `memory` still belongs to this store and no reference invocation is active.
    let bytes = unsafe { store.mem_data_mut(memory) };
    assert_eq!(bytes[512], 0);
    assert_eq!(&bytes[4096..4100], b"VIBE");
    assert_eq!(&bytes[8192..8195], &[0x5b, 0x58, 0x59]);
    assert_eq!(
        u32::from_le_bytes(bytes[516..520].try_into().unwrap()),
        4096
    );
    assert_eq!(u32::from_le_bytes(bytes[520..524].try_into().unwrap()), 4);
    assert_eq!(
        u32::from_le_bytes(bytes[524..528].try_into().unwrap()),
        8192
    );
    assert_eq!(u32::from_le_bytes(bytes[528..532].try_into().unwrap()), 3);

    assert!(invoke_reference(&mut store, post_return, vec![Value::I32(result_pointer)]).is_empty());
}

#[test]
fn typed_export_lowers_calls_lifts_and_runs_post_return_exactly_once() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(100, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 0x5a).unwrap();
    let label = "vibe";
    let payload = [1, 2, 3];

    let mut call = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, label, &payload),
            100_000,
            100,
        )
        .unwrap();
    let planned = call.metrics();
    assert!(planned.consumed_work > 0, "codec planning is charged once");

    let first = call.poll();
    let TypedPoll::Pending(after_realloc_poll) = first else {
        panic!("the first realloc step must leave the component call pending: {first:?}");
    };
    assert!(
        after_realloc_poll.consumed_work > planned.consumed_work,
        "actual realloc instructions must consume the shared work ledger"
    );

    let (result, pending) = drive(&mut call);
    assert_eq!(result, expected(label, &payload));
    assert!(pending > 0);
    assert!(call.metrics().consumed_work > after_realloc_poll.consumed_work);

    // A completed call is terminal and must not invoke post-return again.
    assert_eq!(call.poll(), TypedPoll::Trapped(TrapCode::Cancelled));
    drop(call);

    assert_eq!(read_u32(&component, 4), 4, "two allocations and two frees");
    assert_eq!(read_u32(&component, 8), 1, "one guest transform");
    assert_eq!(read_u32(&component, 12), 0b11, "flags cross the ABI");
    let first_guest_borrow = read_u32(&component, 16);
    assert_ne!(
        first_guest_borrow,
        token.guest_index(),
        "the primary resource handle must never be disclosed as a borrow"
    );
    assert_eq!(read_u32(&component, 20), 1, "post-return runs once");
    assert_eq!(read_u32(&component, 24), 512, "original retptr is returned");
    assert_eq!(
        read_u32(&component, 28),
        2,
        "arguments free in guest realloc"
    );
    assert!(!component.is_poisoned());
    assert_eq!(
        resources.contains(
            resources.token_from_guest_index(first_guest_borrow),
            RANDOM_SOURCE,
        ),
        Err(vibeos_component_runtime::resource::ResourceError::Stale),
        "the guest borrow alias expires before Ready",
    );

    // Successful post-return and cleanup leave the instance reusable.
    let mut second = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "again", &[4, 5]),
            100_000,
            100,
        )
        .unwrap();
    let (second_result, _) = drive(&mut second);
    assert_eq!(second_result, expected("again", &[4, 5]));
    drop(second);
    assert!(!component.is_poisoned());
    assert_eq!(read_u32(&component, 4), 8);
    assert_eq!(read_u32(&component, 8), 2);
    assert_eq!(read_u32(&component, 20), 2);
    assert_eq!(read_u32(&component, 28), 4);
    assert_ne!(read_u32(&component, 16), first_guest_borrow);
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(0x5a));
}

#[test]
fn planning_exhaustion_is_stable_and_happens_before_guest_execution() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(101, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 7).unwrap();
    let label = "a".repeat(512);
    let payload = vec![9; 512];

    let mut call = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, &label, &payload),
            8,
            8,
        )
        .unwrap();
    assert_eq!(call.metrics().consumed_work, 8);
    assert_eq!(call.poll(), TypedPoll::Trapped(TrapCode::FuelExhausted));
    assert_eq!(call.poll(), TypedPoll::Trapped(TrapCode::Cancelled));
    drop(call);

    assert_eq!(read_u32(&component, 4), 0, "realloc was never entered");
    assert_eq!(read_u32(&component, 8), 0, "transform was never entered");
    assert_eq!(read_u32(&component, 20), 0, "post-return was never entered");
    assert!(!component.is_poisoned());
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(7));
}

#[test]
fn cancellation_releases_the_continuation_and_poisons_the_instance() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(102, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 11).unwrap();
    let label = "pending-work".repeat(32);
    let payload = vec![0x33; 384];

    let mut cancelled = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, &label, &payload),
            100_000,
            1_000,
        )
        .unwrap();
    // Two realloc calls, the allocation-to-replay transition, replay itself,
    // then a bounded transform poll. The long input keeps that Core call
    // suspended when cancellation is requested.
    for _ in 0..5 {
        assert!(matches!(cancelled.poll(), TypedPoll::Pending(_)));
    }
    cancelled.cancel();
    assert_eq!(cancelled.poll(), TypedPoll::Trapped(TrapCode::Cancelled));
    drop(cancelled);
    assert_eq!(read_u32(&component, 20), 0);
    assert!(component.is_poisoned());
    assert!(matches!(
        component.start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "retry", &[1]),
            100_000,
            100,
        ),
        Err(SyncError::Poisoned)
    ));
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(11));
}

#[test]
fn dropping_an_active_call_releases_and_poisons_the_instance() {
    let mut component = instantiate();
    let mut resources = ResourceTable::new(103, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 12).unwrap();
    let label = "pending-work".repeat(32);
    let payload = vec![0x33; 384];
    let mut abandoned = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, &label, &payload),
            100_000,
            1_000,
        )
        .unwrap();
    for _ in 0..5 {
        assert!(matches!(abandoned.poll(), TypedPoll::Pending(_)));
    }
    drop(abandoned);
    assert!(component.is_poisoned());
    assert!(matches!(
        component.start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "retry", &[1]),
            100_000,
            100,
        ),
        Err(SyncError::Poisoned)
    ));
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(12));
}

#[test]
fn overlapping_realloc_result_traps_and_permanently_poisons() {
    let original = "      i32.const 0\n      local.get $pointer\n      local.get $new-size\n      i32.add\n      i32.store\n\n      local.get $pointer)";
    let replacement = "      ;; Hostile allocator: retain the same bump pointer.\n      i32.const 0\n      local.get $pointer\n      i32.store\n\n      local.get $pointer)";
    let hostile = COMPONENT.replacen(original, replacement, 1);
    assert_ne!(hostile, COMPONENT);
    let mut component = instantiate_source(&hostile);
    let mut resources = ResourceTable::new(104, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 13).unwrap();
    let mut call = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "overlap", &[1, 2, 3]),
            100_000,
            100,
        )
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("hostile allocator unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => panic!("hostile allocator host failed: {error:?}"),
            TypedPoll::Ready(value) => panic!("hostile allocator returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::CanonicalAbi);
    drop(call);
    assert!(component.is_poisoned());
    assert_eq!(read_u32(&component, 4), 2);
    assert_eq!(read_u32(&component, 8), 0);
    assert!(matches!(
        component.start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "retry", &[1]),
            100_000,
            100,
        ),
        Err(SyncError::Poisoned)
    ));
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(13));
}

#[test]
fn post_return_trap_is_observed_and_permanently_poisons() {
    let marker = "    (func (export \"cabi_post_transform\") (param $result-pointer i32)";
    let hostile = COMPONENT.replacen(
        marker,
        "    (func (export \"cabi_post_transform\") (param $result-pointer i32)\n      unreachable",
        1,
    );
    assert_ne!(hostile, COMPONENT);
    let mut component = instantiate_source(&hostile);
    let mut resources = ResourceTable::new(105, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 14).unwrap();
    let mut call = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "post", &[7, 8]),
            100_000,
            100,
        )
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("hostile post-return unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => {
                panic!("hostile post-return host failed: {error:?}")
            }
            TypedPoll::Ready(value) => panic!("hostile post-return returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::Unreachable);
    drop(call);
    assert!(component.is_poisoned());
    assert_eq!(read_u32(&component, 8), 1);
    assert_eq!(read_u32(&component, 20), 0);
    assert_eq!(read_u32(&component, 28), 0, "cleanup cannot follow a trap");
    assert!(matches!(
        component.start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "retry", &[1]),
            100_000,
            100,
        ),
        Err(SyncError::Poisoned)
    ));
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(14));
}

#[test]
fn argument_free_trap_after_post_return_permanently_poisons() {
    let marker = "      local.get $new-size\n      i32.eqz\n      if\n        i32.const 28";
    let hostile = COMPONENT.replacen(
        marker,
        "      local.get $new-size\n      i32.eqz\n      if\n        unreachable\n        i32.const 28",
        1,
    );
    assert_ne!(hostile, COMPONENT);
    let mut component = instantiate_source(&hostile);
    let mut resources = ResourceTable::new(106, 4).unwrap();
    let token = resources.insert_owned(RANDOM_SOURCE, 15).unwrap();
    let mut call = component
        .start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "free", &[9, 10]),
            100_000,
            100,
        )
        .unwrap();
    let trap = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {}
            TypedPoll::HostPending(operation) => {
                panic!("hostile free unexpectedly suspended at {operation:?}")
            }
            TypedPoll::Trapped(trap) => break trap,
            TypedPoll::HostFailed(error) => panic!("hostile free host failed: {error:?}"),
            TypedPoll::Ready(value) => panic!("hostile free returned {value:?}"),
        }
    };
    assert_eq!(trap, TrapCode::Unreachable);
    drop(call);
    assert!(component.is_poisoned());
    assert_eq!(read_u32(&component, 8), 1);
    assert_eq!(read_u32(&component, 20), 1, "post-return completed first");
    assert_eq!(read_u32(&component, 28), 0);
    assert!(matches!(
        component.start_typed_call(
            &mut resources,
            TRANSFORM,
            arguments(token, "retry", &[1]),
            100_000,
            100,
        ),
        Err(SyncError::Poisoned)
    ));
    assert_eq!(resources.drop_owned(token, RANDOM_SOURCE), Ok(15));
}
