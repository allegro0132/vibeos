use vibeos_component_format::{LimitKind, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    inspect_core, map_wasmi_error, AdmissionDetail, AdmissionError, CoreComponentGroup,
    CoreInstance, CoreValue, OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
};
use wasmi::{
    errors::{InstantiationError, MemoryError, TableError},
    Error as WasmiError, TrapCode as WasmiTrapCode,
};

fn compile(source: &str) -> ValidatedCore {
    compile_in(&ProfileEngine::new(), source)
}

fn compile_in(engine: &ProfileEngine, source: &str) -> ValidatedCore {
    let bytes = wat::parse_str(source).unwrap();
    ValidatedCore::new_in(
        engine,
        &bytes,
        OwnerAllocationReservation::profile_default(),
    )
    .unwrap()
}

fn drive(
    instance: &mut CoreInstance,
    export: &str,
    inputs: &[CoreValue],
    total_fuel: u64,
    poll_quantum: u64,
) -> PollResult {
    instance
        .start_call(export, inputs, total_fuel, poll_quantum)
        .unwrap();
    for _ in 0..=PROFILE_1_LIMITS.max_call_depth as usize + 2 {
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            result @ (PollResult::Ready(_) | PollResult::Trapped(_)) => return result,
            PollResult::HostCall(call) => panic!("unexpected host call: {call:?}"),
        }
    }
    panic!("call exceeded its fuel- and call-depth-derived poll bound")
}

fn drive_default(instance: &mut CoreInstance, export: &str, inputs: &[CoreValue]) -> PollResult {
    drive(instance, export, inputs, 100_000, 10_000)
}

fn identity(trap: TrapCode) -> (u16, &'static str) {
    match trap {
        TrapCode::Validation => (0x0100, "validation"),
        TrapCode::UnsupportedFeature => (0x0101, "unsupported-feature"),
        TrapCode::LimitExceeded => (0x0102, "limit-exceeded"),
        TrapCode::Unreachable => (0x0200, "unreachable"),
        TrapCode::IntegerDivisionByZero => (0x0201, "integer-division-by-zero"),
        TrapCode::IntegerOverflow => (0x0202, "integer-overflow"),
        TrapCode::MemoryOutOfBounds => (0x0203, "memory-out-of-bounds"),
        TrapCode::TableOutOfBounds => (0x0204, "table-out-of-bounds"),
        TrapCode::IndirectCallTypeMismatch => (0x0205, "indirect-call-type-mismatch"),
        TrapCode::CallDepthExceeded => (0x0206, "call-depth-exceeded"),
        TrapCode::InvalidConversionToInteger => (0x0207, "invalid-conversion-to-integer"),
        TrapCode::FuelExhausted => (0x0300, "fuel-exhausted"),
        TrapCode::Cancelled => (0x0301, "cancelled"),
        TrapCode::CanonicalAbi => (0x0400, "canonical-abi"),
        TrapCode::ResourceMisuse => (0x0401, "resource-misuse"),
    }
}

fn is_core_facing(trap: TrapCode) -> bool {
    match trap {
        TrapCode::Validation
        | TrapCode::UnsupportedFeature
        | TrapCode::LimitExceeded
        | TrapCode::Unreachable
        | TrapCode::IntegerDivisionByZero
        | TrapCode::IntegerOverflow
        | TrapCode::MemoryOutOfBounds
        | TrapCode::TableOutOfBounds
        | TrapCode::IndirectCallTypeMismatch
        | TrapCode::CallDepthExceeded
        | TrapCode::InvalidConversionToInteger
        | TrapCode::FuelExhausted
        | TrapCode::Cancelled => true,
        TrapCode::CanonicalAbi | TrapCode::ResourceMisuse => false,
    }
}

fn assert_identity(trap: TrapCode) {
    let (code, name) = identity(trap);
    assert_eq!(trap.code(), code);
    assert_eq!(trap.name(), name);
}

fn assert_trap_twice(
    instance: &mut CoreInstance,
    export: &str,
    inputs: &[CoreValue],
    expected: TrapCode,
) {
    assert_identity(expected);
    for _ in 0..2 {
        assert_eq!(
            drive_default(instance, export, inputs),
            PollResult::Trapped(expected)
        );
        assert!(!instance.has_active_call());
    }
}

#[test]
fn core_trap_code_and_name_identity_is_frozen() {
    let core = [
        TrapCode::Validation,
        TrapCode::UnsupportedFeature,
        TrapCode::LimitExceeded,
        TrapCode::Unreachable,
        TrapCode::IntegerDivisionByZero,
        TrapCode::IntegerOverflow,
        TrapCode::MemoryOutOfBounds,
        TrapCode::TableOutOfBounds,
        TrapCode::IndirectCallTypeMismatch,
        TrapCode::CallDepthExceeded,
        TrapCode::InvalidConversionToInteger,
        TrapCode::FuelExhausted,
        TrapCode::Cancelled,
    ];
    for trap in core {
        assert!(is_core_facing(trap));
        assert_identity(trap);
    }
    assert!(!is_core_facing(TrapCode::CanonicalAbi));
    assert!(!is_core_facing(TrapCode::ResourceMisuse));
}

#[test]
fn pinned_wasmi_traps_have_one_explicit_vibe_mapping() {
    let cases = [
        (WasmiTrapCode::UnreachableCodeReached, TrapCode::Unreachable),
        (
            WasmiTrapCode::MemoryOutOfBounds,
            TrapCode::MemoryOutOfBounds,
        ),
        (WasmiTrapCode::TableOutOfBounds, TrapCode::TableOutOfBounds),
        (
            WasmiTrapCode::IndirectCallToNull,
            TrapCode::TableOutOfBounds,
        ),
        (
            WasmiTrapCode::IntegerDivisionByZero,
            TrapCode::IntegerDivisionByZero,
        ),
        (WasmiTrapCode::IntegerOverflow, TrapCode::IntegerOverflow),
        (WasmiTrapCode::BadConversionToInteger, TrapCode::Validation),
        (WasmiTrapCode::StackOverflow, TrapCode::CallDepthExceeded),
        (
            WasmiTrapCode::BadSignature,
            TrapCode::IndirectCallTypeMismatch,
        ),
        (WasmiTrapCode::OutOfFuel, TrapCode::FuelExhausted),
        (
            WasmiTrapCode::GrowthOperationLimited,
            TrapCode::LimitExceeded,
        ),
    ];
    for (source, expected) in cases {
        assert_eq!(map_wasmi_error(&WasmiError::from(source)), expected);
        assert_identity(expected);
    }
}

#[test]
fn pinned_wasmi_resource_and_instantiation_errors_have_typed_mappings() {
    let memory_cases = [
        (MemoryError::OutOfSystemMemory, TrapCode::LimitExceeded),
        (MemoryError::OutOfBoundsGrowth, TrapCode::MemoryOutOfBounds),
        (MemoryError::OutOfBoundsAccess, TrapCode::MemoryOutOfBounds),
        (MemoryError::InvalidMemoryType, TrapCode::Validation),
        (MemoryError::InvalidStaticBufferSize, TrapCode::Validation),
        (
            MemoryError::ResourceLimiterDeniedAllocation,
            TrapCode::LimitExceeded,
        ),
        (MemoryError::MinimumSizeOverflow, TrapCode::LimitExceeded),
        (MemoryError::MaximumSizeOverflow, TrapCode::LimitExceeded),
        (
            MemoryError::OutOfFuel { required_fuel: 1 },
            TrapCode::FuelExhausted,
        ),
    ];
    for (source, expected) in memory_cases {
        assert_eq!(map_wasmi_error(&WasmiError::from(source)), expected);
        assert_eq!(
            map_wasmi_error(&WasmiError::from(
                InstantiationError::FailedToInstantiateMemory(source),
            )),
            expected
        );
        assert_identity(expected);
    }

    let table_cases = [
        (TableError::OutOfSystemMemory, TrapCode::LimitExceeded),
        (TableError::MinimumSizeOverflow, TrapCode::LimitExceeded),
        (TableError::MaximumSizeOverflow, TrapCode::LimitExceeded),
        (
            TableError::ResourceLimiterDeniedAllocation,
            TrapCode::LimitExceeded,
        ),
        (TableError::GrowOutOfBounds, TrapCode::TableOutOfBounds),
        (TableError::InitOutOfBounds, TrapCode::TableOutOfBounds),
        (TableError::FillOutOfBounds, TrapCode::TableOutOfBounds),
        (TableError::SetOutOfBounds, TrapCode::TableOutOfBounds),
        (TableError::CopyOutOfBounds, TrapCode::TableOutOfBounds),
        (
            TableError::ElementTypeMismatch,
            TrapCode::IndirectCallTypeMismatch,
        ),
        (
            TableError::OutOfFuel { required_fuel: 1 },
            TrapCode::FuelExhausted,
        ),
    ];
    for (source, expected) in table_cases {
        assert_eq!(map_wasmi_error(&WasmiError::from(source)), expected);
        assert_eq!(
            map_wasmi_error(&WasmiError::from(
                InstantiationError::FailedToInstantiateTable(source),
            )),
            expected
        );
        assert_identity(expected);
    }

    for source in [
        InstantiationError::TooManyInstances,
        InstantiationError::TooManyTables,
        InstantiationError::TooManyMemories,
    ] {
        assert_eq!(
            map_wasmi_error(&WasmiError::from(source)),
            TrapCode::LimitExceeded
        );
    }
}

#[test]
fn arithmetic_and_unreachable_traps_are_repeatable_and_reusable() {
    let arithmetic = compile(
        r#"(module
              (func (export "div32") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.div_s)
              (func (export "div64") (param i64 i64) (result i64)
                local.get 0
                local.get 1
                i64.div_s))"#,
    );
    let mut instance = arithmetic.instantiate().unwrap();
    assert_eq!(
        drive_default(
            &mut instance,
            "div32",
            &[CoreValue::I32(7), CoreValue::I32(1)],
        ),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
    assert_trap_twice(
        &mut instance,
        "div32",
        &[CoreValue::I32(7), CoreValue::I32(0)],
        TrapCode::IntegerDivisionByZero,
    );
    assert_eq!(
        drive_default(
            &mut instance,
            "div64",
            &[CoreValue::I64(i64::MIN), CoreValue::I64(1)],
        ),
        PollResult::Ready(vec![CoreValue::I64(i64::MIN)])
    );
    assert_trap_twice(
        &mut instance,
        "div64",
        &[CoreValue::I64(i64::MIN), CoreValue::I64(-1)],
        TrapCode::IntegerOverflow,
    );
    assert_eq!(
        drive_default(
            &mut instance,
            "div32",
            &[CoreValue::I32(9), CoreValue::I32(3)],
        ),
        PollResult::Ready(vec![CoreValue::I32(3)])
    );

    let conditional = compile(
        r#"(module
              (func (export "maybe") (param i32) (result i32)
                local.get 0
                if
                  unreachable
                end
                i32.const 7))"#,
    );
    let mut instance = conditional.instantiate().unwrap();
    assert_eq!(
        drive_default(&mut instance, "maybe", &[CoreValue::I32(0)]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
    assert_trap_twice(
        &mut instance,
        "maybe",
        &[CoreValue::I32(1)],
        TrapCode::Unreachable,
    );
    assert_eq!(
        drive_default(&mut instance, "maybe", &[CoreValue::I32(0)]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
}

#[test]
fn memory_and_indirect_call_boundaries_have_stable_diagnostics() {
    let memory = compile(
        r#"(module
              (memory 1 1)
              (func (export "load") (param i32) (result i32)
                local.get 0
                i32.load))"#,
    );
    let mut instance = memory.instantiate().unwrap();
    assert_eq!(
        drive_default(&mut instance, "load", &[CoreValue::I32(65_532)]),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );
    assert_trap_twice(
        &mut instance,
        "load",
        &[CoreValue::I32(65_533)],
        TrapCode::MemoryOutOfBounds,
    );
    assert_eq!(
        drive_default(&mut instance, "load", &[CoreValue::I32(65_532)]),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );

    let indirect = compile(
        r#"(module
              (type $expected (func (result i32)))
              (type $wrong (func (param i32) (result i32)))
              (func $good (type $expected) (result i32) i32.const 7)
              (func $wrong (type $wrong) (param i32) (result i32) local.get 0)
              (table 3 3 funcref)
              (elem (i32.const 0) $good)
              (elem (i32.const 2) $wrong)
              (func (export "dispatch") (param i32) (result i32)
                local.get 0
                call_indirect (type $expected)))"#,
    );
    let mut instance = indirect.instantiate().unwrap();
    assert_eq!(
        drive_default(&mut instance, "dispatch", &[CoreValue::I32(0)]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
    assert_trap_twice(
        &mut instance,
        "dispatch",
        &[CoreValue::I32(1)],
        TrapCode::TableOutOfBounds,
    );
    assert_trap_twice(
        &mut instance,
        "dispatch",
        &[CoreValue::I32(2)],
        TrapCode::IndirectCallTypeMismatch,
    );
    assert_trap_twice(
        &mut instance,
        "dispatch",
        &[CoreValue::I32(3)],
        TrapCode::TableOutOfBounds,
    );
    assert_eq!(
        drive_default(&mut instance, "dispatch", &[CoreValue::I32(0)]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
}

#[test]
fn call_depth_and_fuel_terminals_are_stable_and_reusable() {
    let depth = compile(
        r#"(module
              (func $depth (export "depth") (param i32) (result i32)
                local.get 0
                i32.eqz
                if (result i32)
                  i32.const 0
                else
                  local.get 0
                  i32.const 1
                  i32.sub
                  call $depth
                end))"#,
    );
    let mut instance = depth.instantiate().unwrap();
    assert_eq!(
        drive_default(
            &mut instance,
            "depth",
            &[CoreValue::I32((PROFILE_1_LIMITS.max_call_depth - 1) as i32,)],
        ),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );
    assert_trap_twice(
        &mut instance,
        "depth",
        &[CoreValue::I32(PROFILE_1_LIMITS.max_call_depth as i32)],
        TrapCode::CallDepthExceeded,
    );
    assert_eq!(
        drive_default(&mut instance, "depth", &[CoreValue::I32(0)]),
        PollResult::Ready(vec![CoreValue::I32(0)])
    );

    let fuel = compile(
        r#"(module
              (func (export "spin") (loop br 0))
              (func (export "safe") (result i32) i32.const 7))"#,
    );
    let mut instance = fuel.instantiate().unwrap();
    assert_identity(TrapCode::FuelExhausted);
    for _ in 0..2 {
        assert_eq!(
            drive(&mut instance, "spin", &[], 1, 1),
            PollResult::Trapped(TrapCode::FuelExhausted)
        );
        assert!(!instance.has_active_call());
    }
    assert_eq!(
        drive_default(&mut instance, "safe", &[]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
}

#[test]
fn validation_unsupported_and_limit_admission_codes_are_exact() {
    const EMPTY_CORE: &[u8] = b"\0asm\x01\0\0\0";
    let engine = ProfileEngine::new();
    assert!(inspect_core(EMPTY_CORE).is_ok());
    assert!(ValidatedCore::new_in(
        &engine,
        EMPTY_CORE,
        OwnerAllocationReservation::profile_default(),
    )
    .is_ok());

    let malformed = &EMPTY_CORE[..EMPTY_CORE.len() - 1];
    let unsupported = wat::parse_str("(module (func (result f32) f32.const 0))").unwrap();
    let oversized = vec![0; PROFILE_1_LIMITS.max_core_module_bytes + 1];
    let cases = [
        (
            malformed,
            AdmissionError {
                trap: TrapCode::Validation,
                detail: AdmissionDetail::Malformed,
            },
        ),
        (
            unsupported.as_slice(),
            AdmissionError {
                trap: TrapCode::UnsupportedFeature,
                detail: AdmissionDetail::UnsupportedFeature,
            },
        ),
        (
            oversized.as_slice(),
            AdmissionError {
                trap: TrapCode::LimitExceeded,
                detail: AdmissionDetail::Limit(LimitKind::CoreModuleBytes),
            },
        ),
    ];
    for (bytes, expected) in cases {
        assert_identity(expected.trap);
        for _ in 0..2 {
            assert_eq!(inspect_core(bytes), Err(expected));
            assert_eq!(
                ValidatedCore::new_in(
                    &engine,
                    bytes,
                    OwnerAllocationReservation::profile_default(),
                )
                .err(),
                Some(expected)
            );
        }
    }

    let callable = compile(
        r#"(module
              (func (export "identity") (param i32) (result i32)
                local.get 0))"#,
    );
    let mut instance = callable.instantiate().unwrap();
    assert_eq!(
        instance.start_call("missing", &[], 100, 10),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        instance.start_call("identity", &[], 100, 10),
        Err(TrapCode::Validation)
    );
    assert_eq!(
        instance.start_call("identity", &[CoreValue::I64(7)], 100, 10),
        Err(TrapCode::Validation)
    );
    assert!(!instance.has_active_call());
    assert_eq!(
        drive_default(&mut instance, "identity", &[CoreValue::I32(7)]),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
}

#[test]
fn active_segment_instantiation_out_of_bounds_uses_runtime_trap_codes() {
    let engine = ProfileEngine::new();
    let data_oob = compile_in(
        &engine,
        r#"(module
              (memory 1 1)
              (data (i32.const 65536) "\aa"))"#,
    );
    let expected_memory = AdmissionError {
        trap: TrapCode::MemoryOutOfBounds,
        detail: AdmissionDetail::Malformed,
    };
    for _ in 0..2 {
        assert_eq!(data_oob.instantiate().err(), Some(expected_memory));
        let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
        assert_eq!(group.add_instance(&data_oob, &[]), Err(expected_memory));
    }

    let element_oob = compile_in(
        &engine,
        r#"(module
              (type $t (func))
              (func $target)
              (table 1 1 funcref)
              (elem (i32.const 1) $target))"#,
    );
    let expected_table = AdmissionError {
        trap: TrapCode::TableOutOfBounds,
        detail: AdmissionDetail::Malformed,
    };
    for _ in 0..2 {
        assert_eq!(element_oob.instantiate().err(), Some(expected_table));
        let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
        assert_eq!(group.add_instance(&element_oob, &[]), Err(expected_table));
    }

    let adjacent = compile_in(
        &engine,
        r#"(module
              (type $t (func))
              (func $target)
              (memory 1 1)
              (table 1 1 funcref)
              (data (i32.const 65535) "\aa")
              (elem (i32.const 0) $target))"#,
    );
    assert!(adjacent.instantiate().is_ok());
    let mut group = CoreComponentGroup::new(&engine, 1).unwrap();
    assert_eq!(group.add_instance(&adjacent, &[]), Ok(0));
}

#[test]
fn initial_memory_policy_failure_is_limit_exceeded_at_instantiation() {
    let engine = ProfileEngine::new();
    let module = compile_in(&engine, "(module (memory 1 1))");
    let expected = AdmissionError {
        trap: TrapCode::LimitExceeded,
        detail: AdmissionDetail::Malformed,
    };
    assert_identity(expected.trap);
    for _ in 0..2 {
        let mut group = CoreComponentGroup::new_with_memory_limit(&engine, 1, 65_535).unwrap();
        assert_eq!(group.add_instance(&module, &[]), Err(expected));
    }
}
