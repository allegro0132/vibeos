use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, InstantiationOutcome, Store as DlrStore, Value,
};
use vibeos_component_format::{LimitKind, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, inspect_core_with_limits, AdmissionDetail, CoreComponentGroup, CoreHostCall,
    CoreHostImport, CoreInstanceExportImport, CoreModuleImport, CoreValue, CoreValueType,
    OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
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
        PollResult::HostCall(CoreHostCall {
            origin_instance: 0,
            id: 313,
            arguments: vec![],
        })
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
        PollResult::HostCall(CoreHostCall {
            origin_instance: 0,
            id: 81,
            arguments: vec![]
        })
    );
    assert_eq!(
        group.poll_call(1),
        PollResult::HostCall(CoreHostCall {
            origin_instance: 1,
            id: 82,
            arguments: vec![]
        })
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
        PollResult::HostCall(CoreHostCall {
            origin_instance: 1,
            id: 92,
            arguments: vec![]
        })
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
        PollResult::HostCall(CoreHostCall {
            origin_instance: 0,
            id: 91,
            arguments: vec![]
        })
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
        CoreHostCall {
            origin_instance: 0,
            id: 1,
            arguments: vec![CoreValue::I32(4)]
        }
    );
    instance.resume_host_call(1, &[CoreValue::I32(7)]).unwrap();
    assert_eq!(
        poll_instance_to_host(&mut instance),
        CoreHostCall {
            origin_instance: 0,
            id: 2,
            arguments: vec![CoreValue::I32(7)]
        }
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
