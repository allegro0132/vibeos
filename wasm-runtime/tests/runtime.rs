use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, InstantiationOutcome, Store as DlrStore, Value,
};
use vibeos_component_format::{LimitKind, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, inspect_core_with_limits, AdmissionDetail, CoreCallSlot, CoreCallSlotState,
    CoreComponentGroup, CoreHostCall, CoreHostImport, CoreInstanceExportImport, CoreModuleImport,
    CoreSlotPollResult, CoreValue, CoreValueType, OwnerAllocationReservation, PollResult,
    ProfileEngine, ValidatedCore,
};

fn compile(wat: &str) -> ValidatedCore {
    let bytes = wat::parse_str(wat).unwrap();
    ValidatedCore::new(&bytes, OwnerAllocationReservation::profile_default()).unwrap()
}

fn compile_in(engine: &ProfileEngine, wat: &str) -> ValidatedCore {
    let bytes = wat::parse_str(wat).unwrap();
    ValidatedCore::new_in(
        engine,
        &bytes,
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn run(
    wat: &str,
    export: &str,
    inputs: &[CoreValue],
    total: u64,
    quantum: u64,
) -> (PollResult, usize) {
    let module = compile(wat);
    let mut instance = module.instantiate().unwrap();
    let mut call = instance.begin_call(export, inputs, total, quantum).unwrap();
    let mut polls = 0;
    loop {
        polls += 1;
        let result = call.poll();
        if !matches!(result, PollResult::Pending { .. }) {
            return (result, polls);
        }
        assert!(polls < 20_000, "bounded call failed to terminate");
    }
}

fn poll_to_terminal(call: &mut vibeos_wasm_runtime::Invocation<'_>) -> PollResult {
    loop {
        let result = call.poll();
        if !matches!(result, PollResult::Pending { .. }) {
            return result;
        }
    }
}

fn poll_instance_to_host(instance: &mut vibeos_wasm_runtime::CoreInstance) -> CoreHostCall {
    loop {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::HostCall(call) => return call,
            other => panic!("expected host call, got {other:?}"),
        }
    }
}

fn poll_instance_to_terminal(instance: &mut vibeos_wasm_runtime::CoreInstance) -> PollResult {
    loop {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            result @ (PollResult::Ready(_) | PollResult::Trapped(_)) => return result,
            PollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
}

fn poll_group_to_terminal(group: &mut CoreComponentGroup, instance: usize) -> PollResult {
    loop {
        match group.poll_call(instance) {
            PollResult::Pending { .. } => {}
            result @ (PollResult::Ready(_) | PollResult::Trapped(_)) => return result,
            PollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
}

fn poll_group_slot_to_terminal(
    group: &mut CoreComponentGroup,
    slot: &mut CoreCallSlot,
) -> CoreSlotPollResult {
    loop {
        match group.poll_call_slot(slot) {
            CoreSlotPollResult::Pending { .. } => {}
            result @ (CoreSlotPollResult::Ready(_) | CoreSlotPollResult::Trapped(_)) => {
                return result;
            }
            CoreSlotPollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
}

#[test]
fn component_group_enforces_the_image_memory_ceiling_at_runtime() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (memory 1 4)
              (func (export "grow") (param i32) (result i32)
                local.get 0
                memory.grow))"#,
    );

    // Two pages are permitted. The first grow reaches the exact ceiling; a
    // second grow is trapped by the store limiter instead of silently relying
    // on the outer owner reservation or host allocator to fail.
    let mut group = CoreComponentGroup::new_with_memory_limit(&engine, 1, 2 * 65_536).unwrap();
    group.add_instance(&module, &[]).unwrap();
    group
        .start_call(0, "grow", &[CoreValue::I32(1)], 100_000, 10_000)
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    group
        .start_call(0, "grow", &[CoreValue::I32(1)], 100_000, 10_000)
        .unwrap();
    assert!(matches!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Trapped(_)
    ));

    // A non-page-aligned ceiling below the module's initial page also fails
    // closed during instantiation.
    let mut too_small = CoreComponentGroup::new_with_memory_limit(&engine, 1, 65_535).unwrap();
    assert!(too_small.add_instance(&module, &[]).is_err());

    assert!(CoreComponentGroup::new_with_memory_limit(&engine, 1, 0).is_err());
    assert!(CoreComponentGroup::new_with_memory_limit(
        &engine,
        1,
        PROFILE_1_LIMITS.max_memory_pages as usize * 65_536 + 1,
    )
    .is_err());
}

#[test]
fn reserved_group_start_is_exact_linear_and_failure_atomic() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "identity") (param i32) (result i32)
                local.get 0)
              (func (export "same-type") (param i32) (result i32)
                local.get 0)
              (func (export "wide") (param i64) (result i64)
                local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group.add_instance(&module, &[]).unwrap();
    group.add_instance(&module, &[]).unwrap();

    let reservation = group.reserve_call(0, "identity").unwrap();
    assert_eq!(
        group.start_call_reserved(reservation, 1, "identity", &[CoreValue::I32(1)], 100, 10,),
        Err(TrapCode::Validation),
    );
    assert!(!group.any_active_call());

    let reservation = group.reserve_call(0, "identity").unwrap();
    assert_eq!(
        group.start_call_reserved(reservation, 0, "same-type", &[CoreValue::I32(1)], 100, 10,),
        Err(TrapCode::Validation),
    );
    assert!(!group.any_active_call());

    let reservation = group.reserve_call(0, "identity").unwrap();
    assert_eq!(
        group.start_call_reserved(reservation, 0, "identity", &[], 100, 10),
        Err(TrapCode::Validation),
    );
    assert!(!group.any_active_call());

    let reservation = group.reserve_call(0, "identity").unwrap();
    assert_eq!(
        group.start_call_reserved(reservation, 0, "identity", &[CoreValue::I64(1)], 100, 10,),
        Err(TrapCode::Validation),
    );
    assert!(!group.any_active_call());

    for (total, quantum) in [(0, 10), (100, 0), (10, 11)] {
        let reservation = group.reserve_call(0, "identity").unwrap();
        assert_eq!(
            group.start_call_reserved(
                reservation,
                0,
                "identity",
                &[CoreValue::I32(1)],
                total,
                quantum,
            ),
            Err(TrapCode::LimitExceeded),
        );
        assert!(!group.any_active_call());
    }

    let mut other_group = CoreComponentGroup::new(&engine, 1).unwrap();
    other_group.add_instance(&module, &[]).unwrap();
    let wrong_owner = group.reserve_call(0, "identity").unwrap();
    assert_eq!(
        other_group.start_call_reserved(wrong_owner, 0, "identity", &[CoreValue::I32(7)], 100, 10,),
        Err(TrapCode::Validation),
    );
    assert!(!other_group.any_active_call());

    let reservation = group.reserve_call(0, "identity").unwrap();
    group
        .start_call_reserved(reservation, 0, "identity", &[CoreValue::I32(42)], 100, 10)
        .unwrap();
    // The reservation was consumed by value, and active state excludes a
    // second reservation until this exact call reaches a terminal result.
    assert_eq!(
        group.reserve_call(0, "identity").err(),
        Some(TrapCode::Validation)
    );
    assert_eq!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Ready(vec![CoreValue::I32(42)])
    );
}

#[test]
fn reusable_group_slot_returns_inline_results_across_many_calls() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "identity") (param i32) (result i32)
                local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
    group.add_instance(&module, &[]).unwrap();
    let mut slot = group.reserve_call_slot(0, "identity").unwrap();
    let generation = slot.generation();
    assert_ne!(generation, 0);
    assert_eq!(slot.state(), CoreCallSlotState::Idle);

    for value in 0..512_i32 {
        group
            .start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(value)], 100, 10)
            .unwrap();
        assert_eq!(slot.state(), CoreCallSlotState::Active);
        assert_eq!(slot.generation(), generation);
        let result = poll_group_slot_to_terminal(&mut group, &mut slot);
        let CoreSlotPollResult::Ready(results) = result else {
            panic!("expected reusable call result, got {result:?}");
        };
        assert_eq!(results.as_slice(), &[CoreValue::I32(value)]);
        assert_eq!(results.len(), 1);
        assert!(!results.is_empty());
        assert_eq!(slot.state(), CoreCallSlotState::Idle);
        assert_eq!(group.call_metrics(0), None);
        let metrics = group.call_metrics_slot(&slot).unwrap();
        assert_eq!(metrics.consumed_fuel + metrics.remaining_fuel, 100);
    }
}

#[test]
fn reusable_group_slot_preserves_host_origin_resume_fuel_and_metrics() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (import "host" "value" (func $value (param i32) (result i32)))
              (func (export "wrapper") (param i32) (result i32)
                local.get 0
                call $value
                i32.const 1
                i32.add))"#,
    );
    let outer = compile_in(
        &engine,
        r#"(module
              (import "provider" "wrapper" (func $wrapper (param i32) (result i32)))
              (func (export "run") (param i32) (result i32)
                (local i32)
                i32.const 64
                local.set 1
                block $done
                  loop $again
                    local.get 1
                    i32.eqz
                    br_if $done
                    local.get 1
                    i32.const 1
                    i32.sub
                    local.set 1
                    br $again
                  end
                end
                local.get 0
                call $wrapper))"#,
    );
    let params = [CoreValueType::I32];
    let results = [CoreValueType::I32];
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group
        .add_instance(
            &provider,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 414,
                module: "host",
                name: "value",
                params: &params,
                results: &results,
            })],
        )
        .unwrap();
    group
        .add_instance(
            &outer,
            &[CoreModuleImport::InstanceExport(CoreInstanceExportImport {
                module: "provider",
                name: "wrapper",
                instance: 0,
                export: "wrapper",
            })],
        )
        .unwrap();
    let mut slot = group.reserve_call_slot(1, "run").unwrap();
    let wrong_slot = group.reserve_call_slot(1, "run").unwrap();
    group
        .start_call_slot(&mut slot, 1, "run", &[CoreValue::I32(40)], 10_000, 7)
        .unwrap();

    let mut pending_polls = 0;
    let host = loop {
        match group.poll_call_slot(&mut slot) {
            CoreSlotPollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => {
                pending_polls += 1;
                assert_eq!(consumed_fuel + remaining_fuel, 10_000);
            }
            CoreSlotPollResult::HostCall(call) => break call,
            other => panic!("expected slot host call, got {other:?}"),
        }
    };
    assert!(pending_polls > 2);
    assert_eq!(
        host,
        CoreHostCall::untrusted_description(0, 414, vec![CoreValue::I32(40)])
    );
    assert!(!group.has_active_call(0));
    assert!(group.has_active_call(1));
    assert_eq!(group.call_metrics(1), None);
    assert_eq!(group.call_metrics_slot(&wrong_slot), None);
    let before_debit = group.call_metrics_slot(&slot).unwrap();
    assert_eq!(group.debit_call_fuel(1, 7), Err(TrapCode::Validation));
    assert_eq!(
        group.debit_call_fuel_slot(&wrong_slot, 7),
        Err(TrapCode::Validation)
    );
    assert_eq!(group.call_metrics_slot(&slot), Some(before_debit));
    group.debit_call_fuel_slot(&slot, 7).unwrap();
    let after_debit = group.call_metrics_slot(&slot).unwrap();
    assert_eq!(after_debit.consumed_fuel, before_debit.consumed_fuel + 7);
    assert_eq!(after_debit.remaining_fuel + 7, before_debit.remaining_fuel);
    assert_eq!(group.credit_call_fuel(1, 2), Err(TrapCode::Validation));
    assert_eq!(
        group.credit_call_fuel_slot(&wrong_slot, 2),
        Err(TrapCode::Validation)
    );
    group.credit_call_fuel_slot(&slot, 2).unwrap();
    let after_credit = group.call_metrics_slot(&slot).unwrap();
    assert_eq!(after_credit.consumed_fuel + 2, after_debit.consumed_fuel);
    assert_eq!(after_credit.consumed_fuel, before_debit.consumed_fuel + 5);
    assert_eq!(after_credit.remaining_fuel, after_debit.remaining_fuel + 2);
    assert_eq!(group.cancel_call(1), Err(TrapCode::Validation));
    assert_eq!(
        group.cancel_call_slot(&wrong_slot),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        group.resume_host_call(1, 414, &[CoreValue::I32(41)]),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        group.resume_host_call_slot(&wrong_slot, 414, &[CoreValue::I32(41)]),
        Err(TrapCode::Validation)
    );
    group
        .resume_host_call_slot(&slot, 414, &[CoreValue::I32(41)])
        .unwrap();

    let result = poll_group_slot_to_terminal(&mut group, &mut slot);
    let CoreSlotPollResult::Ready(results) = result else {
        panic!("expected resumed slot result, got {result:?}");
    };
    assert_eq!(results.as_slice(), &[CoreValue::I32(42)]);
    assert_eq!(slot.state(), CoreCallSlotState::Idle);
    assert_eq!(group.call_metrics(1), None);
    assert_eq!(group.call_metrics_slot(&wrong_slot), None);
    let terminal = group.call_metrics_slot(&slot).unwrap();
    assert_eq!(terminal.consumed_fuel + terminal.remaining_fuel, 10_000);

    group
        .start_call_slot(&mut slot, 1, "run", &[CoreValue::I32(50)], 10_000, 7)
        .unwrap();
    loop {
        match group.poll_call_slot(&mut slot) {
            CoreSlotPollResult::Pending { .. } => {}
            CoreSlotPollResult::HostCall(_) => break,
            other => panic!("expected second slot host call, got {other:?}"),
        }
    }
    group.discard_call_slot(&mut slot).unwrap();
    assert_eq!(slot.state(), CoreCallSlotState::Idle);
    assert_eq!(
        group.resume_host_call(1, 414, &[CoreValue::I32(51)]),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        group.resume_host_call_slot(&slot, 414, &[CoreValue::I32(51)]),
        Err(TrapCode::Validation)
    );
}

#[test]
fn reusable_group_slot_restores_scratch_after_guest_trap() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "maybe") (param i32) (result i32)
                local.get 0
                i32.eqz
                if
                  unreachable
                end
                local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
    group.add_instance(&module, &[]).unwrap();
    let mut slot = group.reserve_call_slot(0, "maybe").unwrap();

    group
        .start_call_slot(&mut slot, 0, "maybe", &[CoreValue::I32(0)], 100, 10)
        .unwrap();
    assert!(matches!(
        poll_group_slot_to_terminal(&mut group, &mut slot),
        CoreSlotPollResult::Trapped(_)
    ));
    assert_eq!(slot.state(), CoreCallSlotState::Idle);

    group
        .start_call_slot(&mut slot, 0, "maybe", &[CoreValue::I32(9)], 100, 10)
        .unwrap();
    let CoreSlotPollResult::Ready(results) = poll_group_slot_to_terminal(&mut group, &mut slot)
    else {
        panic!("reusable slot did not recover from a terminal guest trap");
    };
    assert_eq!(results.as_slice(), &[CoreValue::I32(9)]);
    assert_eq!(slot.state(), CoreCallSlotState::Idle);

    group
        .start_call_slot(&mut slot, 0, "maybe", &[CoreValue::I32(9)], 100, 10)
        .unwrap();
    assert_eq!(group.cancel_call(0), Err(TrapCode::Validation));
    group.cancel_call_slot(&slot).unwrap();
    assert_eq!(
        group.poll_call_slot(&mut slot),
        CoreSlotPollResult::Trapped(TrapCode::Cancelled)
    );
    assert_eq!(slot.state(), CoreCallSlotState::Idle);
}

#[test]
fn reusable_group_slot_is_provenance_exact_and_generic_poll_fails_closed() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "identity") (param i32) (result i32) local.get 0)
              (func (export "same-type") (param i32) (result i32) local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group.add_instance(&module, &[]).unwrap();
    group.add_instance(&module, &[]).unwrap();
    let mut slot = group.reserve_call_slot(0, "identity").unwrap();
    let mut other_group = CoreComponentGroup::new(&engine, 1).unwrap();
    other_group.add_instance(&module, &[]).unwrap();

    assert_eq!(
        other_group.start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(1)], 100, 10,),
        Err(TrapCode::Validation)
    );
    assert_eq!(slot.state(), CoreCallSlotState::Idle);
    for (instance, export) in [(1, "identity"), (0, "same-type")] {
        assert_eq!(
            group.start_call_slot(&mut slot, instance, export, &[CoreValue::I32(1)], 100, 10,),
            Err(TrapCode::Validation)
        );
        assert_eq!(slot.state(), CoreCallSlotState::Idle);
        assert!(!group.any_active_call());
    }
    assert_eq!(
        group.start_call_slot(&mut slot, 0, "identity", &[], 100, 10),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        group.start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(1)], 10, 11,),
        Err(TrapCode::LimitExceeded)
    );
    assert_eq!(slot.state(), CoreCallSlotState::Idle);

    group
        .start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(7)], 100, 10)
        .unwrap();
    assert_eq!(
        group.start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(8)], 100, 10,),
        Err(TrapCode::Validation)
    );
    assert_eq!(other_group.call_metrics_slot(&slot), None);
    assert_eq!(
        other_group.cancel_call_slot(&slot),
        Err(TrapCode::Validation)
    );
    assert_eq!(slot.state(), CoreCallSlotState::Active);
    let CoreSlotPollResult::Ready(results) = poll_group_slot_to_terminal(&mut group, &mut slot)
    else {
        panic!("exact slot poll failed after double-start rejection");
    };
    assert_eq!(results.as_slice(), &[CoreValue::I32(7)]);
    let first_terminal = group.call_metrics_slot(&slot).unwrap();
    assert_eq!(group.call_metrics(0), None);

    let mut second = group.reserve_call_slot(0, "identity").unwrap();
    assert_ne!(slot.generation(), second.generation());
    assert_eq!(group.call_metrics_slot(&slot), Some(first_terminal));
    assert_eq!(group.call_metrics_slot(&second), None);
    group
        .start_call_slot(&mut second, 0, "identity", &[CoreValue::I32(8)], 100, 10)
        .unwrap();
    group
        .start_call(1, "identity", &[CoreValue::I32(9)], 100, 10)
        .unwrap();
    assert_eq!(group.call_metrics(0), None);
    assert_eq!(group.call_metrics_slot(&slot), None);
    assert!(group.call_metrics_slot(&second).is_some());
    assert_eq!(
        group.poll_call(0),
        PollResult::Trapped(TrapCode::Validation)
    );
    assert!(!group.any_active_call());
    assert_eq!(second.state(), CoreCallSlotState::Active);
    assert_eq!(
        group.poll_call_slot(&mut second),
        CoreSlotPollResult::Trapped(TrapCode::Validation)
    );
    assert_eq!(second.state(), CoreCallSlotState::Poisoned);
}

#[test]
fn reusable_group_slot_has_exact_discard_and_generic_teardown_poisoning() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "identity") (param i32) (result i32) local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
    group.add_instance(&module, &[]).unwrap();
    let mut slot = group.reserve_call_slot(0, "identity").unwrap();

    group
        .start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(3)], 100, 10)
        .unwrap();
    assert_eq!(group.discard_call(0), Err(TrapCode::Validation));
    assert!(group.has_active_call(0));
    assert_eq!(slot.state(), CoreCallSlotState::Active);
    group.discard_call_slot(&mut slot).unwrap();
    assert!(!group.any_active_call());
    assert_eq!(slot.state(), CoreCallSlotState::Idle);

    group
        .start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(4)], 100, 10)
        .unwrap();
    group.discard_all_calls();
    assert!(!group.any_active_call());
    assert_eq!(slot.state(), CoreCallSlotState::Active);
    assert_eq!(
        group.poll_call_slot(&mut slot),
        CoreSlotPollResult::Trapped(TrapCode::Validation)
    );
    assert_eq!(slot.state(), CoreCallSlotState::Poisoned);
    assert_eq!(
        group.start_call_slot(&mut slot, 0, "identity", &[CoreValue::I32(5)], 100, 10,),
        Err(TrapCode::Validation)
    );
}

#[test]
fn external_fuel_debit_and_credit_are_atomic_and_conservative() {
    let engine = ProfileEngine::new();
    let module = compile_in(
        &engine,
        r#"(module
              (func (export "identity") (param i32) (result i32)
                local.get 0))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
    group.add_instance(&module, &[]).unwrap();
    group
        .start_call(0, "identity", &[CoreValue::I32(9)], 100, 10)
        .unwrap();

    assert_eq!(group.call_metrics(0).unwrap().consumed_fuel, 0);
    group.debit_call_fuel(0, 40).unwrap();
    assert_eq!(
        group.call_metrics(0).unwrap(),
        vibeos_wasm_runtime::CallMetrics {
            consumed_fuel: 40,
            remaining_fuel: 60,
        }
    );
    let before_failed_debit = group.call_metrics(0).unwrap();
    assert_eq!(group.debit_call_fuel(0, 61), Err(TrapCode::FuelExhausted));
    assert_eq!(group.call_metrics(0), Some(before_failed_debit));

    group.debit_call_fuel(0, 10).unwrap();
    group.credit_call_fuel(0, 20).unwrap();
    assert_eq!(
        group.call_metrics(0).unwrap(),
        vibeos_wasm_runtime::CallMetrics {
            consumed_fuel: 30,
            remaining_fuel: 70,
        }
    );
    let before_over_credit = group.call_metrics(0).unwrap();
    assert_eq!(group.credit_call_fuel(0, 31), Err(TrapCode::FuelExhausted));
    assert_eq!(group.call_metrics(0), Some(before_over_credit));

    group.credit_call_fuel(0, 30).unwrap();
    assert_eq!(
        group.call_metrics(0).unwrap(),
        vibeos_wasm_runtime::CallMetrics {
            consumed_fuel: 0,
            remaining_fuel: 100,
        }
    );
    let before_guest_credit = group.call_metrics(0).unwrap();
    assert_eq!(group.credit_call_fuel(0, 1), Err(TrapCode::FuelExhausted));
    assert_eq!(group.call_metrics(0), Some(before_guest_credit));
    assert_eq!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Ready(vec![CoreValue::I32(9)])
    );
    let terminal = group.call_metrics(0).unwrap();
    assert_eq!(terminal.consumed_fuel + terminal.remaining_fuel, 100);
}

#[test]
fn single_instance_external_fuel_uses_the_same_atomic_ledger() {
    let module = compile(
        r#"(module
              (func (export "identity") (param i32) (result i32)
                local.get 0))"#,
    );
    let mut instance = module.instantiate().unwrap();
    assert_eq!(instance.debit_call_fuel(1), Err(TrapCode::Validation));
    assert_eq!(instance.credit_call_fuel(1), Err(TrapCode::Validation));
    instance
        .start_call("identity", &[CoreValue::I32(9)], 100, 10)
        .unwrap();

    instance.debit_call_fuel(40).unwrap();
    assert_eq!(
        instance.call_metrics().unwrap(),
        vibeos_wasm_runtime::CallMetrics {
            consumed_fuel: 40,
            remaining_fuel: 60,
        }
    );
    let before_failed_debit = instance.call_metrics().unwrap();
    assert_eq!(instance.debit_call_fuel(61), Err(TrapCode::FuelExhausted));
    assert_eq!(instance.call_metrics(), Some(before_failed_debit));

    instance.credit_call_fuel(20).unwrap();
    assert_eq!(
        instance.call_metrics().unwrap(),
        vibeos_wasm_runtime::CallMetrics {
            consumed_fuel: 20,
            remaining_fuel: 80,
        }
    );
    let before_over_credit = instance.call_metrics().unwrap();
    assert_eq!(instance.credit_call_fuel(21), Err(TrapCode::FuelExhausted));
    assert_eq!(instance.call_metrics(), Some(before_over_credit));

    assert_eq!(
        poll_instance_to_terminal(&mut instance),
        PollResult::Ready(vec![CoreValue::I32(9)])
    );
    let terminal = instance.call_metrics().unwrap();
    assert_eq!(terminal.consumed_fuel + terminal.remaining_fuel, 100);
    assert_eq!(instance.debit_call_fuel(1), Err(TrapCode::Validation));
    assert_eq!(instance.credit_call_fuel(1), Err(TrapCode::Validation));
}

#[test]
fn group_host_ids_are_global_and_transitive_origin_is_definition_exact() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (import "host" "value" (func $value (result i32)))
              (func (export "wrapper") (result i32)
                call $value
                i32.const 1
                i32.add))"#,
    );
    let outer = compile_in(
        &engine,
        r#"(module
              (import "provider" "wrapper" (func $wrapper (result i32)))
              (func (export "run") (result i32)
                call $wrapper))"#,
    );
    let results = [CoreValueType::I32];
    let host = CoreHostImport {
        id: 313,
        module: "host",
        name: "value",
        params: &[],
        results: &results,
    };
    let mut group = CoreComponentGroup::new(&engine, 3).unwrap();
    group
        .add_instance(&provider, &[CoreModuleImport::Host(host)])
        .unwrap();
    let collision = group
        .add_instance(&provider, &[CoreModuleImport::Host(host)])
        .unwrap_err();
    assert_eq!(collision.detail, AdmissionDetail::HostImportMismatch);
    group
        .add_instance(
            &outer,
            &[CoreModuleImport::InstanceExport(CoreInstanceExportImport {
                module: "provider",
                name: "wrapper",
                instance: 0,
                export: "wrapper",
            })],
        )
        .unwrap();

    group.start_call(1, "run", &[], 1_000, 100).unwrap();
    assert_eq!(
        group.poll_call(1),
        PollResult::HostCall(CoreHostCall::untrusted_description(0, 313, vec![]))
    );
    assert!(!group.has_active_call(0));
    assert!(group.has_active_call(1));
    group
        .resume_host_call(1, 313, &[CoreValue::I32(41)])
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 1),
        PollResult::Ready(vec![CoreValue::I32(42)])
    );
}

#[test]
fn component_group_links_exact_prior_functions_and_shared_memory() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (memory (export "memory") 1 1)
              (func (export "realloc")
                (param i32 i32 i32 i32) (result i32)
                i32.const 64))"#,
    );
    let guest = compile_in(
        &engine,
        r#"(module
              (import "env" "memory" (memory 1 1))
              (import "env" "realloc"
                (func $realloc (param i32 i32 i32 i32) (result i32)))
              (func (export "run") (result i32)
                (local $pointer i32)
                i32.const 0
                i32.const 0
                i32.const 4
                i32.const 4
                call $realloc
                local.tee $pointer
                i32.const 0x12345678
                i32.store
                local.get $pointer
                i32.load))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    assert_eq!(group.add_instance(&provider, &[]).unwrap(), 0);
    let imports = [
        CoreModuleImport::InstanceExport(CoreInstanceExportImport {
            module: "env",
            name: "memory",
            instance: 0,
            export: "memory",
        }),
        CoreModuleImport::InstanceExport(CoreInstanceExportImport {
            module: "env",
            name: "realloc",
            instance: 0,
            export: "realloc",
        }),
    ];
    assert_eq!(group.add_instance(&guest, &imports).unwrap(), 1);
    group.start_call(1, "run", &[], 10_000, 100).unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 1),
        PollResult::Ready(vec![CoreValue::I32(0x1234_5678)])
    );
    let mut bytes = [0_u8; 4];
    group.read_memory(0, "memory", 64, &mut bytes).unwrap();
    assert_eq!(u32::from_le_bytes(bytes), 0x1234_5678);
}

#[test]
fn component_group_memory_authority_tracks_aliases_growth_and_owner() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (memory (export "memory") 1 3))"#,
    );
    let alias = compile_in(
        &engine,
        r#"(module
              (import "env" "memory" (memory 1 3))
              (export "alias" (memory 0)))"#,
    );
    let mut group = CoreComponentGroup::new(&engine, 3).unwrap();
    assert_eq!(group.add_instance(&provider, &[]).unwrap(), 0);
    assert_eq!(group.add_instance(&provider, &[]).unwrap(), 1);
    assert_eq!(
        group
            .add_instance(
                &alias,
                &[CoreModuleImport::InstanceExport(CoreInstanceExportImport {
                    module: "env",
                    name: "memory",
                    instance: 0,
                    export: "memory",
                },)],
            )
            .unwrap(),
        2
    );
    group.seal().unwrap();

    let provider_authority = group.memory_authority(0, "memory").unwrap();
    let distinct_authority = group.memory_authority(1, "memory").unwrap();
    let alias_authority = group.memory_authority(2, "alias").unwrap();
    assert_eq!(
        format!("{provider_authority:?}"),
        "CoreMemoryAuthority(<opaque>)"
    );
    assert!(matches!(
        group.memory_authority(2, "missing"),
        Err(TrapCode::Validation)
    ));

    group
        .write_authorized_memory(&provider_authority, 8, &[1, 2, 3, 4])
        .unwrap();
    let mut bytes = [0_u8; 4];
    group
        .read_authorized_memory(&alias_authority, 8, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [1, 2, 3, 4]);

    group
        .write_authorized_memory(&alias_authority, 12, &[5, 6, 7, 8])
        .unwrap();
    group
        .read_authorized_memory(&provider_authority, 12, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [5, 6, 7, 8]);

    group
        .read_authorized_memory(&distinct_authority, 8, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0; 4]);
    group
        .write_authorized_memory(&distinct_authority, 8, &[9, 10, 11, 12])
        .unwrap();
    group
        .read_authorized_memory(&provider_authority, 8, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [1, 2, 3, 4]);

    assert_eq!(
        group.authorized_memory_size(&provider_authority),
        Ok(65_536)
    );
    assert_eq!(group.authorized_memory_size(&alias_authority), Ok(65_536));
    group
        .grow_authorized_memory_to(&alias_authority, 65_537)
        .unwrap();
    assert_eq!(
        group.authorized_memory_size(&provider_authority),
        Ok(2 * 65_536)
    );
    assert_eq!(
        group.authorized_memory_size(&alias_authority),
        Ok(2 * 65_536)
    );
    assert_eq!(
        group.authorized_memory_size(&distinct_authority),
        Ok(65_536)
    );

    group
        .write_authorized_memory(&provider_authority, 65_536, &[13, 14, 15, 16])
        .unwrap();
    group
        .read_authorized_memory(&alias_authority, 65_536, &mut bytes)
        .unwrap();
    assert_eq!(bytes, [13, 14, 15, 16]);
    assert_eq!(
        group.read_authorized_memory(&provider_authority, 2 * 65_536, &mut bytes[..1]),
        Err(TrapCode::MemoryOutOfBounds)
    );

    let mut foreign_group = CoreComponentGroup::new(&engine, 1).unwrap();
    foreign_group.add_instance(&provider, &[]).unwrap();
    foreign_group.seal().unwrap();
    assert_eq!(
        foreign_group.authorized_memory_size(&provider_authority),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        foreign_group.read_authorized_memory(&provider_authority, 0, &mut bytes),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        foreign_group.write_authorized_memory(&provider_authority, 0, &bytes),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        foreign_group.grow_authorized_memory_to(&provider_authority, 2 * 65_536),
        Err(TrapCode::Validation)
    );
}

#[test]
fn component_group_polls_provider_while_guest_host_call_is_suspended() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (memory (export "memory") 1 1)
              (func (export "realloc")
                (param i32 i32 i32 i32) (result i32)
                i32.const 128))"#,
    );
    let guest = compile_in(
        &engine,
        r#"(module
              (import "host" "value" (func $value (result i32)))
              (func (export "run") (result i32)
                call $value
                i32.const 1
                i32.add))"#,
    );
    let host_results = [CoreValueType::I32];
    let host = CoreHostImport {
        id: 71,
        module: "host",
        name: "value",
        params: &[],
        results: &host_results,
    };
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group.add_instance(&provider, &[]).unwrap();
    group
        .add_instance(&guest, &[CoreModuleImport::Host(host)])
        .unwrap();
    group.start_call(1, "run", &[], 10_000, 100).unwrap();
    let call = loop {
        match group.poll_call(1) {
            PollResult::Pending { .. } => {}
            PollResult::HostCall(call) => break call,
            other => panic!("expected guest host call, got {other:?}"),
        }
    };
    assert_eq!(call.id, 71);
    assert!(group.has_active_call(1));

    group
        .start_call(
            0,
            "realloc",
            &[
                CoreValue::I32(0),
                CoreValue::I32(0),
                CoreValue::I32(1),
                CoreValue::I32(4),
            ],
            1_000,
            100,
        )
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Ready(vec![CoreValue::I32(128)])
    );
    group.write_memory(0, "memory", 128, &[9, 8, 7, 6]).unwrap();
    group
        .resume_host_call(1, 71, &[CoreValue::I32(41)])
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 1),
        PollResult::Ready(vec![CoreValue::I32(42)])
    );
}

#[test]
fn component_group_keeps_suspended_host_calls_instance_exact() {
    let engine = ProfileEngine::new();
    let first = compile_in(
        &engine,
        r#"(module
              (import "host" "first" (func $host (result i32)))
              (func (export "run") (result i32) call $host))"#,
    );
    let second = compile_in(
        &engine,
        r#"(module
              (import "host" "second" (func $host (result i32)))
              (func (export "run") (result i32) call $host))"#,
    );
    let results = [CoreValueType::I32];
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group
        .add_instance(
            &first,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 81,
                module: "host",
                name: "first",
                params: &[],
                results: &results,
            })],
        )
        .unwrap();
    group
        .add_instance(
            &second,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 82,
                module: "host",
                name: "second",
                params: &[],
                results: &results,
            })],
        )
        .unwrap();

    group.start_call(0, "run", &[], 1_000, 100).unwrap();
    group.start_call(1, "run", &[], 1_000, 100).unwrap();
    assert_eq!(
        group.poll_call(0),
        PollResult::HostCall(CoreHostCall::untrusted_description(0, 81, vec![]))
    );
    assert_eq!(
        group.poll_call(1),
        PollResult::HostCall(CoreHostCall::untrusted_description(1, 82, vec![]))
    );

    assert_eq!(
        group.resume_host_call(0, 82, &[CoreValue::I32(1)]),
        Err(TrapCode::Validation),
    );
    assert_eq!(
        group.resume_host_call(1, 81, &[CoreValue::I32(2)]),
        Err(TrapCode::Validation),
    );
    group
        .resume_host_call(1, 82, &[CoreValue::I32(22)])
        .unwrap();
    group
        .resume_host_call(0, 81, &[CoreValue::I32(11)])
        .unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 1),
        PollResult::Ready(vec![CoreValue::I32(22)]),
    );
    assert_eq!(
        poll_group_to_terminal(&mut group, 0),
        PollResult::Ready(vec![CoreValue::I32(11)]),
    );
}

#[test]
fn provider_host_reentry_is_exposed_for_the_component_to_reject() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (import "host" "nested" (func $nested (result i32)))
              (func (export "realloc")
                (param i32 i32 i32 i32) (result i32)
                call $nested))"#,
    );
    let outer = compile_in(
        &engine,
        r#"(module
              (import "host" "outer" (func $outer (result i32)))
              (func (export "run") (result i32) call $outer))"#,
    );
    let results = [CoreValueType::I32];
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group
        .add_instance(
            &provider,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 91,
                module: "host",
                name: "nested",
                params: &[],
                results: &results,
            })],
        )
        .unwrap();
    group
        .add_instance(
            &outer,
            &[CoreModuleImport::Host(CoreHostImport {
                id: 92,
                module: "host",
                name: "outer",
                params: &[],
                results: &results,
            })],
        )
        .unwrap();

    group.start_call(1, "run", &[], 1_000, 100).unwrap();
    assert_eq!(
        group.poll_call(1),
        PollResult::HostCall(CoreHostCall::untrusted_description(1, 92, vec![]))
    );
    group
        .start_call(
            0,
            "realloc",
            &[
                CoreValue::I32(0),
                CoreValue::I32(0),
                CoreValue::I32(1),
                CoreValue::I32(4),
            ],
            1_000,
            100,
        )
        .unwrap();
    assert_eq!(
        group.poll_call(0),
        PollResult::HostCall(CoreHostCall::untrusted_description(0, 91, vec![]))
    );
    assert!(group.has_active_call(0));
    assert!(group.has_active_call(1));

    // The portable Core layer surfaces the nested call without running it.
    // The Component host-lowering state machine treats this as re-entry,
    // poisons the principal, and uses this bounded teardown primitive.
    group.discard_all_calls();
    assert!(!group.any_active_call());
    assert_eq!(
        group.resume_host_call(0, 91, &[CoreValue::I32(64)]),
        Err(TrapCode::Validation),
    );
    assert_eq!(
        group.resume_host_call(1, 92, &[CoreValue::I32(7)]),
        Err(TrapCode::Validation),
    );
}

#[test]
fn component_group_rejects_forward_wrong_kind_and_cross_engine_sources() {
    let engine = ProfileEngine::new();
    let memory_provider = compile_in(&engine, r#"(module (memory (export "memory") 1 1))"#);
    let memory_guest = compile_in(&engine, r#"(module (import "env" "memory" (memory 1 1)))"#);
    let function_guest = compile_in(&engine, r#"(module (import "env" "memory" (func)))"#);
    let mut group = CoreComponentGroup::new(&engine, 3).unwrap();
    let forward = CoreModuleImport::InstanceExport(CoreInstanceExportImport {
        module: "env",
        name: "memory",
        instance: 0,
        export: "memory",
    });
    assert_eq!(
        group
            .add_instance(&memory_guest, &[forward])
            .unwrap_err()
            .detail,
        AdmissionDetail::HostImportMismatch
    );
    group.add_instance(&memory_provider, &[]).unwrap();
    assert_eq!(
        group
            .add_instance(&function_guest, &[forward])
            .unwrap_err()
            .detail,
        AdmissionDetail::HostImportMismatch
    );

    let other_engine = ProfileEngine::new();
    let foreign = compile_in(&other_engine, "(module)");
    assert_eq!(
        group.add_instance(&foreign, &[]).unwrap_err().detail,
        AdmissionDetail::HostImportMismatch
    );
}

#[test]
fn component_group_seal_and_first_start_permanently_close_construction() {
    let engine = ProfileEngine::new();
    let runnable = compile_in(
        &engine,
        r#"(module (func (export "run") (result i32) i32.const 7))"#,
    );
    let late = compile_in(&engine, "(module)");

    let mut explicitly_sealed = CoreComponentGroup::new(&engine, 2).unwrap();
    explicitly_sealed.add_instance(&runnable, &[]).unwrap();
    explicitly_sealed.seal().unwrap();
    assert_eq!(
        explicitly_sealed
            .add_instance(&late, &[])
            .unwrap_err()
            .detail,
        AdmissionDetail::HostImportMismatch,
    );

    let mut execution_sealed = CoreComponentGroup::new(&engine, 2).unwrap();
    execution_sealed.add_instance(&runnable, &[]).unwrap();
    execution_sealed
        .start_call(0, "run", &[], 1_000, 100)
        .unwrap();
    assert_eq!(
        execution_sealed
            .add_instance(&late, &[])
            .unwrap_err()
            .detail,
        AdmissionDetail::HostImportMismatch,
    );
    assert_eq!(
        poll_group_to_terminal(&mut execution_sealed, 0),
        PollResult::Ready(vec![CoreValue::I32(7)]),
    );
    assert_eq!(
        execution_sealed
            .add_instance(&late, &[])
            .unwrap_err()
            .detail,
        AdmissionDetail::HostImportMismatch,
    );
}

#[test]
fn failed_shared_memory_initialization_poisons_every_group_operation() {
    let engine = ProfileEngine::new();
    let provider = compile_in(
        &engine,
        r#"(module
              (memory (export "memory") 1 1)
              (func (export "run")))"#,
    );
    let partially_mutating_guest = compile_in(
        &engine,
        r#"(module
              (import "env" "memory" (memory 1 1))
              ;; Wasmi applies active segments in order. This write succeeds,
              ;; then the following segment traps after shared state changed.
              (data (i32.const 0) "\aa")
              (data (i32.const 65536) "\bb"))"#,
    );
    let late = compile_in(&engine, "(module)");
    let memory = CoreModuleImport::InstanceExport(CoreInstanceExportImport {
        module: "env",
        name: "memory",
        instance: 0,
        export: "memory",
    });
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group.add_instance(&provider, &[]).unwrap();

    assert_eq!(
        group
            .add_instance(&partially_mutating_guest, &[memory])
            .unwrap_err()
            .detail,
        AdmissionDetail::Malformed,
    );
    assert_eq!(group.instance_count(), 1);
    assert!(!group.any_active_call());
    assert_eq!(group.call_metrics(0), None);
    assert_eq!(group.seal(), Err(TrapCode::Validation));
    assert_eq!(
        group.add_instance(&late, &[]).unwrap_err().detail,
        AdmissionDetail::HostImportMismatch,
    );
    assert_eq!(
        group.start_call(0, "run", &[], 1_000, 100),
        Err(TrapCode::Validation),
    );
    assert_eq!(
        group.poll_call(0),
        PollResult::Trapped(TrapCode::Validation)
    );
    assert_eq!(group.resume_host_call(0, 0, &[]), Err(TrapCode::Validation),);
    assert_eq!(group.cancel_call(0), Err(TrapCode::Validation));
    assert_eq!(group.discard_call(0), Err(TrapCode::Validation));
    let mut byte = [0_u8; 1];
    assert_eq!(
        group.read_memory(0, "memory", 0, &mut byte),
        Err(TrapCode::Validation),
    );
    assert_eq!(
        group.write_memory(0, "memory", 0, &[0]),
        Err(TrapCode::Validation),
    );
    assert_eq!(group.memory_size(0, "memory"), Err(TrapCode::Validation),);
    assert_eq!(
        group.grow_memory_to(0, "memory", 2 * 65_536),
        Err(TrapCode::Validation),
    );

    // Teardown helpers remain safe, but cannot make poisoned state reusable.
    group.cancel_all_calls();
    group.discard_all_calls();
    assert_eq!(
        group.start_call(0, "run", &[], 1_000, 100),
        Err(TrapCode::Validation),
    );
}

#[test]
fn component_group_requires_exact_imported_memory_minimum_and_maximum() {
    let engine = ProfileEngine::new();
    let provider = compile_in(&engine, r#"(module (memory (export "memory") 1 2))"#);
    let lower_minimum = compile_in(&engine, r#"(module (import "env" "memory" (memory 0 2)))"#);
    let wider_maximum = compile_in(&engine, r#"(module (import "env" "memory" (memory 1 3)))"#);
    let higher_minimum = compile_in(&engine, r#"(module (import "env" "memory" (memory 2 2)))"#);
    let narrower_maximum = compile_in(&engine, r#"(module (import "env" "memory" (memory 1 1)))"#);
    let exact = compile_in(
        &engine,
        r#"(module
              (import "env" "memory" (memory 1 2))
              (func (export "load") (result i32)
                i32.const 0
                i32.load))"#,
    );
    let memory = CoreModuleImport::InstanceExport(CoreInstanceExportImport {
        module: "env",
        name: "memory",
        instance: 0,
        export: "memory",
    });
    let mut group = CoreComponentGroup::new(&engine, 2).unwrap();
    group.add_instance(&provider, &[]).unwrap();

    // The first two are valid Wasm import subtypes, but Profile 1 requires
    // nominally exact limits instead of accepting the broader Core relation.
    for non_exact in [
        &lower_minimum,
        &wider_maximum,
        &higher_minimum,
        &narrower_maximum,
    ] {
        assert_eq!(
            group.add_instance(non_exact, &[memory]).unwrap_err().detail,
            AdmissionDetail::HostImportMismatch,
        );
    }

    assert_eq!(group.add_instance(&exact, &[memory]).unwrap(), 1);
    group
        .write_memory(0, "memory", 0, &0x1234_5678_u32.to_le_bytes())
        .unwrap();
    group.start_call(1, "load", &[], 1_000, 100).unwrap();
    assert_eq!(
        poll_group_to_terminal(&mut group, 1),
        PollResult::Ready(vec![CoreValue::I32(0x1234_5678)]),
    );
}

#[test]
fn integer_corpus_executes_and_matches_the_reference_engine() {
    let source = include_str!("../../component-format/tests/corpus/core/integer.wat");
    let bytes = wat::parse_str(source).unwrap();
    let selected = compile(source);
    assert_eq!(selected.summary().functions, 1);
    assert!(selected.reserved_compile_bytes() >= bytes.len() * 4);
    let mut instance = selected.instantiate().unwrap();
    let mut call = instance
        .begin_call("add", &[CoreValue::I32(20), CoreValue::I32(22)], 1_000, 20)
        .unwrap();
    assert_eq!(call.poll(), PollResult::Ready(vec![CoreValue::I32(42)]));

    let decoded = decode_and_validate(&bytes, &mut ()).unwrap();
    let mut store = DlrStore::new(());
    // SAFETY: the decoded fixture has no imports and belongs to this store.
    let InstantiationOutcome { module_addr, .. } =
        unsafe { store.module_instantiate(&decoded, vec![], None) }.unwrap();
    // SAFETY: the instance address belongs to the same store.
    let export: ExternVal = unsafe { store.instance_export(module_addr, "add") }.unwrap();
    // SAFETY: the function belongs to this store and its exact integer signature is used.
    let result = unsafe {
        store.invoke_simple(
            export.as_func().unwrap(),
            vec![Value::I32(20), Value::I32(22)],
        )
    }
    .unwrap();
    assert_eq!(result.as_slice(), &[Value::I32(42)]);
}

#[test]
fn host_import_allowlist_is_exact_and_default_instantiation_stays_closed() {
    let module = compile(
        r#"
        (module
          (import "vibe:fixture/random@1.0.0" "fill"
            (func $fill (param i32 i64) (result i64)))
          (func (export "run") (param i32 i64) (result i64)
            local.get 0
            local.get 1
            call $fill))
        "#,
    );
    assert_eq!(
        module.instantiate().err().unwrap().detail,
        AdmissionDetail::ImportRequiresLinker
    );

    let params = [CoreValueType::I32, CoreValueType::I64];
    let results = [CoreValueType::I64];
    let exact = CoreHostImport {
        id: 41,
        module: "vibe:fixture/random@1.0.0",
        name: "fill",
        params: &params,
        results: &results,
    };
    assert!(module.instantiate_with_imports(&[exact]).is_ok());

    let wrong_module = CoreHostImport {
        module: "vibe:fixture/random@2.0.0",
        ..exact
    };
    let wrong_name = CoreHostImport {
        name: "fill-unchecked",
        ..exact
    };
    let wrong_params = [CoreValueType::I64, CoreValueType::I64];
    let wrong_param_type = CoreHostImport {
        params: &wrong_params,
        ..exact
    };
    let wrong_results = [CoreValueType::I32];
    let wrong_result_type = CoreHostImport {
        results: &wrong_results,
        ..exact
    };
    for descriptors in [
        &[][..],
        core::slice::from_ref(&wrong_module),
        core::slice::from_ref(&wrong_name),
        core::slice::from_ref(&wrong_param_type),
        core::slice::from_ref(&wrong_result_type),
    ] {
        assert_eq!(
            module
                .instantiate_with_imports(descriptors)
                .err()
                .unwrap()
                .detail,
            AdmissionDetail::HostImportMismatch
        );
    }

    let extra = CoreHostImport {
        id: 42,
        module: "other",
        name: "other",
        params: &[],
        results: &[],
    };
    assert_eq!(
        module
            .instantiate_with_imports(&[exact, extra])
            .err()
            .unwrap()
            .detail,
        AdmissionDetail::HostImportMismatch
    );

    let memory_import = compile(
        r#"
        (module
          (import "env" "memory" (memory 1 1))
          (func (export "run")))
        "#,
    );
    let fake_function = CoreHostImport {
        id: 7,
        module: "env",
        name: "memory",
        params: &[],
        results: &[],
    };
    assert_eq!(
        memory_import
            .instantiate_with_imports(&[fake_function])
            .err()
            .unwrap()
            .detail,
        AdmissionDetail::HostImportMismatch
    );
}

#[test]
fn host_call_yields_outside_wasmi_and_resumes_with_exact_typed_results() {
    let module = compile(
        r#"
        (module
          (import "vibe:clock@1.0.0" "now"
            (func $now (param i32 i64) (result i64)))
          (func (export "run") (param i32 i64) (result i64)
            local.get 0
            local.get 1
            call $now
            i64.const 1
            i64.add))
        "#,
    );
    let params = [CoreValueType::I32, CoreValueType::I64];
    let results = [CoreValueType::I64];
    let import = CoreHostImport {
        id: 9,
        module: "vibe:clock@1.0.0",
        name: "now",
        params: &params,
        results: &results,
    };
    let mut instance = module.instantiate_with_imports(&[import]).unwrap();
    instance
        .start_call(
            "run",
            &[CoreValue::I32(3), CoreValue::I64(5)],
            10_000,
            1_000,
        )
        .unwrap();
    let request = poll_instance_to_host(&mut instance);
    assert_eq!(request.id, 9);
    assert_eq!(
        request.arguments,
        vec![CoreValue::I32(3), CoreValue::I64(5)]
    );
    let suspended = instance.call_metrics().unwrap();
    assert!(suspended.consumed_fuel > 0);
    assert_eq!(suspended.consumed_fuel + suspended.remaining_fuel, 10_000);

    assert_eq!(
        instance.resume_host_call(10, &[CoreValue::I64(40)]),
        Err(TrapCode::Validation)
    );
    assert_eq!(instance.resume_host_call(9, &[]), Err(TrapCode::Validation));
    assert_eq!(
        instance.resume_host_call(9, &[CoreValue::I32(40)]),
        Err(TrapCode::Validation)
    );
    instance.resume_host_call(9, &[CoreValue::I64(40)]).unwrap();
    assert_eq!(
        instance.resume_host_call(9, &[CoreValue::I64(41)]),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        poll_instance_to_terminal(&mut instance),
        PollResult::Ready(vec![CoreValue::I64(41)])
    );
    let completed = instance.call_metrics().unwrap();
    assert!(completed.consumed_fuel >= suspended.consumed_fuel);
    assert_eq!(completed.consumed_fuel + completed.remaining_fuel, 10_000);
}

#[test]
fn exact_host_termination_is_nonreturning_preserves_metrics_and_clears_the_mailbox() {
    let module = compile(
        r#"
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
          (memory (export "memory") 1 1)
          (func (export "_start")
            i32.const 7
            call $proc_exit
            i32.const 0
            i32.const 99
            i32.store8))
        "#,
    );
    let params = [CoreValueType::I32];
    let import = CoreHostImport {
        id: 77,
        module: "wasi_snapshot_preview1",
        name: "proc_exit",
        params: &params,
        results: &[],
    };
    let mut instance = module.instantiate_with_imports(&[import]).unwrap();
    instance.start_call("_start", &[], 10_000, 1_000).unwrap();
    let call = poll_instance_to_host(&mut instance);
    assert_eq!(
        call,
        CoreHostCall::untrusted_description(0, 77, vec![CoreValue::I32(7)])
    );
    let suspended = instance.call_metrics().unwrap();
    assert!(suspended.consumed_fuel > 0);
    assert_eq!(suspended.consumed_fuel + suspended.remaining_fuel, 10_000);

    let reconstructed =
        CoreHostCall::untrusted_description(call.origin_instance, call.id, call.arguments.clone());
    assert!(matches!(
        instance.host_termination_token(reconstructed),
        Err(TrapCode::Validation)
    ));
    let wrong = CoreHostCall::untrusted_description(0, 78, vec![CoreValue::I32(7)]);
    assert!(matches!(
        instance.host_termination_token(wrong),
        Err(TrapCode::Validation)
    ));
    assert!(instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(suspended));

    let token = instance.host_termination_token(call).unwrap();
    instance.terminate_suspended_host_call(token).unwrap();
    assert!(!instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(suspended));
    let mut byte = [0_u8; 1];
    instance.read_memory("memory", 0, &mut byte).unwrap();
    assert_eq!(byte, [0], "guest instructions after proc_exit must not run");
    assert_eq!(
        instance.resume_host_call(77, &[]),
        Err(TrapCode::Validation)
    );

    // A fresh call reaching the same import proves the terminal transition did
    // not leave a stale mailbox entry behind.
    instance.start_call("_start", &[], 10_000, 1_000).unwrap();
    let call = poll_instance_to_host(&mut instance);
    assert_eq!(call.id, 77);
    let token = instance.host_termination_token(call).unwrap();
    instance.terminate_suspended_host_call(token).unwrap();
}

#[test]
fn exact_host_termination_rejects_non_host_and_already_resolved_continuations() {
    let host_module = compile(
        r#"
        (module
          (import "host" "value" (func $value (result i32)))
          (func (export "run") (result i32)
            call $value))
        "#,
    );
    let results = [CoreValueType::I32];
    let import = CoreHostImport {
        id: 91,
        module: "host",
        name: "value",
        params: &[],
        results: &results,
    };
    let mut host = host_module.instantiate_with_imports(&[import]).unwrap();
    host.start_call("run", &[], 10_000, 1_000).unwrap();
    let call = poll_instance_to_host(&mut host);
    assert_eq!(call.id, 91);
    let resolved_token = host.host_termination_token(call).unwrap();
    host.resume_host_call(91, &[CoreValue::I32(42)]).unwrap();
    let resolved_metrics = host.call_metrics().unwrap();
    assert!(matches!(
        host.terminate_suspended_host_call(resolved_token),
        Err(TrapCode::Validation)
    ));
    assert!(host.has_active_call());
    assert_eq!(host.call_metrics(), Some(resolved_metrics));
    assert_eq!(
        poll_instance_to_terminal(&mut host),
        PollResult::Ready(vec![CoreValue::I32(42)])
    );

    // Mint another exact token, finish its rightful call normally, and prove
    // that the token cannot terminate a non-host continuation in any instance.
    host.start_call("run", &[], 10_000, 1_000).unwrap();
    let call = poll_instance_to_host(&mut host);
    let non_host_token = host.host_termination_token(call).unwrap();
    host.resume_host_call(91, &[CoreValue::I32(7)]).unwrap();
    assert_eq!(
        poll_instance_to_terminal(&mut host),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );

    let pending_module = compile(r#"(module (func (export "spin") (loop br 0)))"#);
    let mut pending = pending_module.instantiate().unwrap();
    pending.start_call("spin", &[], 1_000, 10).unwrap();
    assert!(matches!(pending.poll_call(), PollResult::Pending { .. }));
    let pending_metrics = pending.call_metrics().unwrap();
    assert!(matches!(
        pending.terminate_suspended_host_call(non_host_token),
        Err(TrapCode::Validation)
    ));
    assert!(pending.has_active_call());
    assert_eq!(pending.call_metrics(), Some(pending_metrics));
    pending.discard_call().unwrap();
}

#[test]
fn dropped_event_and_exact_argument_allocation_reuse_cannot_mint_termination() {
    let module = compile(
        r#"
        (module
          (import "host" "value" (func $value (param i32) (result i32)))
          (func (export "run") (result i32)
            i32.const 9
            call $value))
        "#,
    );
    let values = [CoreValueType::I32];
    let import = CoreHostImport {
        id: 119,
        module: "host",
        name: "value",
        params: &values,
        results: &values,
    };
    let mut instance = module.instantiate_with_imports(&[import]).unwrap();
    instance.start_call("run", &[], 10_000, 1_000).unwrap();
    let mut genuine = poll_instance_to_host(&mut instance);
    let origin_instance = genuine.origin_instance;
    let id = genuine.id;
    let allocation = core::mem::take(&mut genuine.arguments);
    let allocation_pointer = allocation.as_ptr();
    drop(genuine);

    // Reuse the exact allocation which previously held the genuine event's
    // arguments. Provenance is private evidence, never allocator identity.
    let reconstructed = CoreHostCall::untrusted_description(origin_instance, id, allocation);
    assert_eq!(reconstructed.arguments.as_ptr(), allocation_pointer);
    let suspended = instance.call_metrics().unwrap();
    assert!(matches!(
        instance.host_termination_token(reconstructed),
        Err(TrapCode::Validation)
    ));
    assert!(instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(suspended));

    instance
        .resume_host_call(119, &[CoreValue::I32(27)])
        .unwrap();
    assert_eq!(
        poll_instance_to_terminal(&mut instance),
        PollResult::Ready(vec![CoreValue::I32(27)])
    );
}

#[test]
fn stale_host_termination_token_cannot_terminate_next_same_import_occurrence() {
    let module = compile(
        r#"
        (module
          (import "host" "same" (func $same (result i32)))
          (func (export "run") (result i32)
            call $same))
        "#,
    );
    let results = [CoreValueType::I32];
    let import = CoreHostImport {
        id: 123,
        module: "host",
        name: "same",
        params: &[],
        results: &results,
    };
    let mut instance = module.instantiate_with_imports(&[import]).unwrap();

    instance.start_call("run", &[], 10_000, 1_000).unwrap();
    let first_call = poll_instance_to_host(&mut instance);
    let reconstructed = CoreHostCall::untrusted_description(
        first_call.origin_instance,
        first_call.id,
        first_call.arguments.clone(),
    );
    assert!(matches!(
        instance.host_termination_token(reconstructed),
        Err(TrapCode::Validation)
    ));
    let stale = instance.host_termination_token(first_call).unwrap();
    instance
        .resume_host_call(123, &[CoreValue::I32(1)])
        .unwrap();
    assert_eq!(
        poll_instance_to_terminal(&mut instance),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );

    instance.start_call("run", &[], 10_000, 1_000).unwrap();
    let second_call = poll_instance_to_host(&mut instance);
    let second_metrics = instance.call_metrics().unwrap();
    assert!(matches!(
        instance.terminate_suspended_host_call(stale),
        Err(TrapCode::Validation)
    ));
    assert!(instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(second_metrics));

    let current = instance.host_termination_token(second_call).unwrap();
    instance.terminate_suspended_host_call(current).unwrap();
    assert!(!instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(second_metrics));
}

#[test]
fn host_termination_token_is_instance_and_generation_exact() {
    let module = compile(
        r#"
        (module
          (import "host" "same" (func $same (result i32)))
          (func (export "run") (result i32)
            call $same))
        "#,
    );
    let results = [CoreValueType::I32];
    let import = CoreHostImport {
        id: 321,
        module: "host",
        name: "same",
        params: &[],
        results: &results,
    };
    let mut first = module.instantiate_with_imports(&[import]).unwrap();
    let mut second = module.instantiate_with_imports(&[import]).unwrap();
    first.start_call("run", &[], 10_000, 1_000).unwrap();
    second.start_call("run", &[], 10_000, 1_000).unwrap();
    let first_call = poll_instance_to_host(&mut first);
    let second_call = poll_instance_to_host(&mut second);
    let first_token = first.host_termination_token(first_call).unwrap();
    let second_metrics = second.call_metrics().unwrap();

    assert!(matches!(
        second.terminate_suspended_host_call(first_token),
        Err(TrapCode::Validation)
    ));
    assert!(second.has_active_call());
    assert_eq!(second.call_metrics(), Some(second_metrics));

    let second_token = second.host_termination_token(second_call).unwrap();
    second.terminate_suspended_host_call(second_token).unwrap();
    assert!(!second.has_active_call());

    // Consuming the first instance's token on the wrong instance did not
    // mutate its continuation; the rightful host may still resolve it.
    first.resume_host_call(321, &[CoreValue::I32(5)]).unwrap();
    assert_eq!(
        poll_instance_to_terminal(&mut first),
        PollResult::Ready(vec![CoreValue::I32(5)])
    );
}

#[test]
fn sequential_host_yields_cancel_and_drop_preserve_linear_continuations() {
    let module = compile(
        r#"
        (module
          (import "host" "first" (func $first (param i32) (result i32)))
          (import "host" "second" (func $second (param i32) (result i64)))
          (func (export "run") (param i32) (result i64)
            local.get 0
            call $first
            call $second))
        "#,
    );
    let i32_type = [CoreValueType::I32];
    let i64_type = [CoreValueType::I64];
    let imports = [
        CoreHostImport {
            id: 1,
            module: "host",
            name: "first",
            params: &i32_type,
            results: &i32_type,
        },
        CoreHostImport {
            id: 2,
            module: "host",
            name: "second",
            params: &i32_type,
            results: &i64_type,
        },
    ];
    let mut instance = module.instantiate_with_imports(&imports).unwrap();
    instance
        .start_call("run", &[CoreValue::I32(4)], 10_000, 1_000)
        .unwrap();
    assert_eq!(
        poll_instance_to_host(&mut instance),
        CoreHostCall::untrusted_description(0, 1, vec![CoreValue::I32(4)])
    );
    instance.resume_host_call(1, &[CoreValue::I32(7)]).unwrap();
    assert_eq!(
        poll_instance_to_host(&mut instance),
        CoreHostCall::untrusted_description(0, 2, vec![CoreValue::I32(7)])
    );
    instance.resume_host_call(2, &[CoreValue::I64(99)]).unwrap();
    assert_eq!(
        poll_instance_to_terminal(&mut instance),
        PollResult::Ready(vec![CoreValue::I64(99)])
    );

    instance
        .start_call("run", &[CoreValue::I32(1)], 10_000, 1_000)
        .unwrap();
    let _ = poll_instance_to_host(&mut instance);
    instance.cancel_call().unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Cancelled)
    );
    assert!(!instance.has_active_call());

    instance
        .start_call("run", &[CoreValue::I32(2)], 10_000, 1_000)
        .unwrap();
    let _ = poll_instance_to_host(&mut instance);
    instance.discard_call().unwrap();
    assert!(!instance.has_active_call());

    instance
        .start_call("run", &[CoreValue::I32(3)], 10_000, 1_000)
        .unwrap();
    let _ = poll_instance_to_host(&mut instance);
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Validation)
    );
    assert!(!instance.has_active_call());
}

#[test]
fn finite_work_resumes_across_quanta_and_total_fuel_is_monotonic() {
    let source = r#"
        (module
          (func (export "count") (param i32) (result i32)
            (local i32)
            local.get 0
            local.set 1
            block $done
              loop $again
                local.get 1
                i32.eqz
                br_if $done
                local.get 1
                i32.const 1
                i32.sub
                local.set 1
                br $again
              end
            end
            local.get 1))
    "#;
    let module = compile(source);
    let mut instance = module.instantiate().unwrap();
    let mut call = instance
        .begin_call("count", &[CoreValue::I32(64)], 10_000, 7)
        .unwrap();
    let mut previous_remaining = call.remaining_fuel();
    let mut yields = 0;
    loop {
        match call.poll() {
            PollResult::Pending { remaining_fuel, .. } => {
                yields += 1;
                assert!(remaining_fuel < previous_remaining);
                previous_remaining = remaining_fuel;
            }
            PollResult::Ready(values) => {
                assert_eq!(values, vec![CoreValue::I32(0)]);
                break;
            }
            other => panic!("unexpected terminal result: {other:?}"),
        }
    }
    assert!(yields > 2);
    assert_eq!(call.consumed_fuel() + call.remaining_fuel(), 10_000);
}

#[test]
fn infinite_work_yields_then_exhausts_exact_total_and_cancellation_wins() {
    let source = r#"(module (func (export "spin") (loop br 0)))"#;
    let module = compile(source);
    let mut instance = module.instantiate().unwrap();
    let mut call = instance.begin_call("spin", &[], 41, 10).unwrap();
    for _ in 0..4 {
        assert!(matches!(call.poll(), PollResult::Pending { .. }));
    }
    assert_eq!(call.poll(), PollResult::Trapped(TrapCode::FuelExhausted));
    assert_eq!(call.consumed_fuel(), 41);

    drop(call);
    let mut call = instance.begin_call("spin", &[], 1_000, 10).unwrap();
    assert!(matches!(call.poll(), PollResult::Pending { .. }));
    call.cancel();
    assert_eq!(call.poll(), PollResult::Trapped(TrapCode::Cancelled));
}

#[test]
fn instance_owned_call_state_is_exclusive_resumable_and_cleans_terminal_state() {
    let source = r#"
        (module
          (memory (export "memory") 1 1)
          (func (export "count") (param i32) (result i32)
            (local i32)
            local.get 0
            local.set 1
            block $done
              loop $again
                local.get 1
                i32.eqz
                br_if $done
                local.get 1
                i32.const 1
                i32.sub
                local.set 1
                br $again
              end
            end
            local.get 1)
          (func (export "identity") (param i32) (result i32)
            local.get 0))
    "#;
    let module = compile(source);
    let mut instance = module.instantiate().unwrap();

    instance
        .start_call("count", &[CoreValue::I32(64)], 10_000, 7)
        .unwrap();
    assert!(instance.has_active_call());
    assert_eq!(
        instance.start_call("identity", &[CoreValue::I32(1)], 100, 10),
        Err(TrapCode::Validation)
    );
    assert!(matches!(instance.poll_call(), PollResult::Pending { .. }));

    // Memory access is serialized by `&mut CoreInstance` and is permitted
    // while the interpreter continuation is suspended between polls.
    instance.write_memory("memory", 8, &[1, 2, 3, 4]).unwrap();
    let mut bytes = [0; 4];
    instance.read_memory("memory", 8, &mut bytes).unwrap();
    assert_eq!(bytes, [1, 2, 3, 4]);

    instance.cancel_call().unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Cancelled)
    );
    assert!(!instance.has_active_call());
    let cancelled = instance.call_metrics().unwrap();
    assert!(cancelled.consumed_fuel > 0);
    assert_eq!(cancelled.consumed_fuel + cancelled.remaining_fuel, 10_000);

    instance
        .start_call("identity", &[CoreValue::I32(42)], 100, 10)
        .unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(42)])
    );
    assert!(!instance.has_active_call());
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Validation)
    );
    assert_eq!(instance.cancel_call(), Err(TrapCode::Validation));
}

#[test]
fn dropping_legacy_invocation_discards_its_instance_owned_continuation() {
    let module = compile(r#"(module (func (export "spin") (loop br 0)))"#);
    let mut instance = module.instantiate().unwrap();
    let mut call = instance.begin_call("spin", &[], 1_000, 10).unwrap();
    assert!(matches!(call.poll(), PollResult::Pending { .. }));
    drop(call);

    assert!(!instance.has_active_call());
    instance.start_call("spin", &[], 10, 10).unwrap();
    assert!(matches!(instance.poll_call(), PollResult::Pending { .. }));
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::FuelExhausted)
    );
}

#[test]
fn owner_can_discard_an_instance_owned_continuation_without_another_poll() {
    let module = compile(r#"(module (func (export "spin") (loop br 0)))"#);
    let mut instance = module.instantiate().unwrap();
    instance.start_call("spin", &[], 1_000, 10).unwrap();
    assert!(matches!(instance.poll_call(), PollResult::Pending { .. }));

    let before = instance.call_metrics().unwrap();
    instance.discard_call().unwrap();
    assert!(!instance.has_active_call());
    assert_eq!(instance.call_metrics(), Some(before));
    assert_eq!(instance.discard_call(), Err(TrapCode::Validation));

    instance
        .start_call("spin", &[], 10, 10)
        .expect("discard makes the instance immediately reusable");
}

#[test]
fn memory_access_and_growth_obey_the_effective_maximum() {
    let source = r#"
        (module
          (memory (export "memory") 1 2)
          (func (export "grow") (param i32) (result i32)
            local.get 0
            memory.grow))
    "#;
    let module = compile(source);
    let mut instance = module.instantiate().unwrap();
    instance.write_memory("memory", 8, &[1, 2, 3, 4]).unwrap();
    let mut bytes = [0; 4];
    instance.read_memory("memory", 8, &mut bytes).unwrap();
    assert_eq!(bytes, [1, 2, 3, 4]);
    assert_eq!(instance.memory_size("memory").unwrap(), 65_536);

    let mut first = instance
        .begin_call("grow", &[CoreValue::I32(1)], 100_000, 10_000)
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut first),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    drop(first);
    let mut over = instance
        .begin_call("grow", &[CoreValue::I32(1)], 100_000, 10_000)
        .unwrap();
    assert_eq!(
        poll_to_terminal(&mut over),
        PollResult::Ready(vec![CoreValue::I32(-1)])
    );
    drop(over);
    assert_eq!(instance.memory_size("memory").unwrap(), 2 * 65_536);
}

#[test]
fn stable_core_traps_are_mapped_exactly() {
    let cases = [
        (
            r#"(module (func (export "f") unreachable))"#,
            TrapCode::Unreachable,
        ),
        (
            r#"(module (func (export "f") (result i32) i32.const 1 i32.const 0 i32.div_s))"#,
            TrapCode::IntegerDivisionByZero,
        ),
        (
            r#"(module (func (export "f") (result i32) i32.const -2147483648 i32.const -1 i32.div_s))"#,
            TrapCode::IntegerOverflow,
        ),
        (
            r#"(module (memory 1 1) (func (export "f") i32.const 65536 i32.load drop))"#,
            TrapCode::MemoryOutOfBounds,
        ),
        (
            r#"(module (type $t (func)) (table 1 1 funcref) (func (export "f") i32.const 0 call_indirect (type $t)))"#,
            TrapCode::TableOutOfBounds,
        ),
        (
            r#"(module (type $t (func)) (func $target (param i32)) (table 1 1 funcref) (elem (i32.const 0) $target) (func (export "f") i32.const 0 call_indirect (type $t)))"#,
            TrapCode::IndirectCallTypeMismatch,
        ),
        (
            r#"(module (type $t (func)) (table 1 1 funcref) (func (export "f") i32.const 1 call_indirect (type $t)))"#,
            TrapCode::TableOutOfBounds,
        ),
        (
            r#"(module (func $f (export "f") call $f))"#,
            TrapCode::CallDepthExceeded,
        ),
    ];
    for (source, expected) in cases {
        assert_eq!(
            run(source, "f", &[], 10_000, 1_000).0,
            PollResult::Trapped(expected)
        );
    }
}

#[test]
fn profile_rejects_disabled_proposals_before_compilation() {
    let cases = [
        r#"(module (func (result f32) f32.const 0))"#,
        r#"(module (global (mut i32) (i32.const 0)))"#,
        r#"(module (func (param i32) (result i32) local.get 0 i32.extend8_s))"#,
        r#"(module (func (result i32 i32) i32.const 1 i32.const 2))"#,
        r#"(module (memory 1 1) (func i32.const 0 i32.const 0 i32.const 0 memory.copy))"#,
        r#"(module (memory i64 1 2))"#,
    ];
    for source in cases {
        let bytes = wat::parse_str(source).unwrap();
        let error = inspect_core(&bytes).unwrap_err();
        assert_eq!(
            error.detail,
            AdmissionDetail::UnsupportedFeature,
            "{source}"
        );
        assert_eq!(error.trap, TrapCode::UnsupportedFeature);
    }
}

#[test]
fn structural_limits_and_declared_maxima_fail_at_admission() {
    let no_max = wat::parse_str("(module (memory 1))").unwrap();
    assert_eq!(
        inspect_core(&no_max).unwrap_err().detail,
        AdmissionDetail::MissingMaximum
    );

    let too_large = wat::parse_str("(module (memory 17 17))").unwrap();
    assert_eq!(
        inspect_core(&too_large).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::InitialMemoryPages)
    );

    let two_memories = wat::parse_str("(module (memory 1 1) (memory 1 1))").unwrap();
    assert_eq!(
        inspect_core(&two_memories).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::Memories)
    );

    let one_export = wat::parse_str("(module (func (export \"a\")))").unwrap();
    let mut limits = PROFILE_1_LIMITS;
    limits.max_exports = 0;
    assert_eq!(
        inspect_core_with_limits(&one_export, &limits)
            .unwrap_err()
            .detail,
        AdmissionDetail::Limit(LimitKind::Exports)
    );

    let bytes = wat::parse_str("(module (func))").unwrap();
    assert_eq!(
        ValidatedCore::new(&bytes, OwnerAllocationReservation::new(1))
            .unwrap_err()
            .detail,
        AdmissionDetail::AllocationReservation
    );
}

#[test]
fn start_code_and_oversized_runtime_budgets_fail_closed() {
    let bytes = wat::parse_str("(module (func $start) (start $start))").unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::UnsupportedFeature
    );

    let module = compile("(module (func (export \"f\")))");
    let mut instance = module.instantiate().unwrap();
    assert_eq!(
        instance
            .begin_call(
                "f",
                &[],
                PROFILE_1_LIMITS.total_fuel + 1,
                PROFILE_1_LIMITS.poll_quantum,
            )
            .err()
            .unwrap(),
        TrapCode::LimitExceeded
    );
    assert_eq!(
        instance
            .begin_call(
                "f",
                &[],
                PROFILE_1_LIMITS.total_fuel,
                PROFILE_1_LIMITS.poll_quantum + 1,
            )
            .err()
            .unwrap(),
        TrapCode::LimitExceeded
    );
}

#[test]
fn signature_limits_match_the_engine_limit_before_compilation() {
    let mut params = String::from("(module (func");
    for _ in 0..=PROFILE_1_LIMITS.max_params_per_function {
        params.push_str(" (param i32)");
    }
    params.push_str("))");
    let bytes = wat::parse_str(params).unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::Parameters)
    );

    let mut results = String::from("(module (func");
    for _ in 0..=PROFILE_1_LIMITS.max_results_per_function {
        results.push_str(" (result i32)");
    }
    for _ in 0..=PROFILE_1_LIMITS.max_results_per_function {
        results.push_str(" i32.const 0");
    }
    results.push_str("))");
    let bytes = wat::parse_str(results).unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::Results)
    );
}

#[test]
fn type_count_byte_is_not_confused_with_a_gc_rec_group() {
    let mut source = String::from("(module");
    for _ in 0..78 {
        source.push_str(" (type (func))");
    }
    source.push(')');
    let bytes = wat::parse_str(source).unwrap();
    assert_eq!(inspect_core(&bytes).unwrap().types, 78);
}

#[test]
fn locals_function_counts_and_control_nesting_reject_limit_plus_one() {
    let mut locals = String::from("(module (func");
    for _ in 0..=PROFILE_1_LIMITS.max_locals_per_function {
        locals.push_str(" (local i32)");
    }
    locals.push_str("))");
    let bytes = wat::parse_str(locals).unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::Locals)
    );

    let mut functions = String::from("(module");
    for _ in 0..=PROFILE_1_LIMITS.max_functions {
        functions.push_str(" (func)");
    }
    functions.push(')');
    let bytes = wat::parse_str(functions).unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::Functions)
    );

    let mut nesting = String::from("(module (func");
    for _ in 0..=PROFILE_1_LIMITS.max_core_nesting {
        nesting.push_str(" (block");
    }
    for _ in 0..=PROFILE_1_LIMITS.max_core_nesting {
        nesting.push(')');
    }
    nesting.push_str("))");
    let bytes = wat::parse_str(nesting).unwrap();
    assert_eq!(
        inspect_core(&bytes).unwrap_err().detail,
        AdmissionDetail::Limit(LimitKind::CoreNesting)
    );
}

#[test]
fn arbitrary_bounded_bytes_never_panic_or_reach_execution_unadmitted() {
    let mut state = 0x3d_u32;
    for len in 0..=192 {
        let mut bytes = vec![0_u8; len];
        for byte in &mut bytes {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let result = std::panic::catch_unwind(|| {
            if let Ok(module) =
                ValidatedCore::new(&bytes, OwnerAllocationReservation::profile_default())
            {
                let _ = module.instantiate();
            }
        });
        assert!(result.is_ok(), "host panic for input length {len}");
    }
}
