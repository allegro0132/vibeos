use dlr_wasm_interpreter::{
    decode_and_validate, ExternVal, InstantiationOutcome, Store as DlrStore, Value,
};
use vibeos_component_format::{LimitKind, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, inspect_core_with_limits, AdmissionDetail, CoreValue, OwnerAllocationReservation,
    PollResult, ValidatedCore,
};

fn compile(wat: &str) -> ValidatedCore {
    let bytes = wat::parse_str(wat).unwrap();
    ValidatedCore::new(&bytes, OwnerAllocationReservation::profile_default()).unwrap()
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
