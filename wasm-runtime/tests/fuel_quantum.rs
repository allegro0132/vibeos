use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, TrapCode, WasmiFuelCosts, PROFILE_1_LIMITS,
};
use vibeos_wasm_runtime::{
    CallMetrics, CoreValue, OwnerAllocationReservation, PollResult, ValidatedCore,
};

fn compile(wat: &str) -> ValidatedCore {
    let bytes = wat::parse_str(wat).unwrap();
    ValidatedCore::new(&bytes, OwnerAllocationReservation::profile_default()).unwrap()
}

#[test]
fn engine_and_call_boundaries_pin_the_two_independent_budgets() {
    let identity = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    assert!(identity.runtime().consume_fuel());
    assert_eq!(
        identity.runtime().fuel_costs(),
        WasmiFuelCosts::Wasmi110Default
    );

    let module = compile(r#"(module (func (export "value") (result i32) i32.const 7))"#);
    let mut instance = module.instantiate().unwrap();

    for (total_fuel, poll_quantum) in [
        (0, 1),
        (1, 0),
        (1, 2),
        (PROFILE_1_LIMITS.total_fuel + 1, 1),
        (
            PROFILE_1_LIMITS.total_fuel,
            PROFILE_1_LIMITS.poll_quantum + 1,
        ),
    ] {
        assert_eq!(
            instance.start_call("value", &[], total_fuel, poll_quantum),
            Err(TrapCode::LimitExceeded)
        );
        assert!(!instance.has_active_call());
    }

    instance
        .start_call(
            "value",
            &[],
            PROFILE_1_LIMITS.total_fuel,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
    let metrics = instance.call_metrics().unwrap();
    assert!(metrics.consumed_fuel <= PROFILE_1_LIMITS.poll_quantum);
    assert_eq!(
        metrics.consumed_fuel + metrics.remaining_fuel,
        PROFILE_1_LIMITS.total_fuel
    );
}

#[test]
fn preemptible_spin_yields_exact_quanta_then_exhausts_the_total() {
    let module = compile(r#"(module (func (export "spin") (loop br 0)))"#);
    let mut instance = module.instantiate().unwrap();
    instance.start_call("spin", &[], 41, 10).unwrap();

    for (consumed_fuel, remaining_fuel) in [(9, 32), (19, 22), (29, 12), (39, 2)] {
        assert_eq!(
            instance.poll_call(),
            PollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            }
        );
        assert!(instance.has_active_call());
        assert_eq!(
            instance.call_metrics(),
            Some(CallMetrics {
                consumed_fuel,
                remaining_fuel,
            })
        );
    }

    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::FuelExhausted)
    );
    assert!(!instance.has_active_call());
    assert_eq!(
        instance.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 41,
            remaining_fuel: 0,
        })
    );
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Validation)
    );
}

#[test]
fn cancellation_wins_without_executing_another_quantum_and_state_is_reusable() {
    let module = compile(
        r#"(module
              (func (export "spin") (loop br 0))
              (func (export "value") (result i32) i32.const 7))"#,
    );
    let mut instance = module.instantiate().unwrap();
    instance.start_call("spin", &[], 41, 10).unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Pending {
            consumed_fuel: 9,
            remaining_fuel: 32,
        }
    );
    let before_cancel = instance.call_metrics().unwrap();

    instance.cancel_call().unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Cancelled)
    );
    assert_eq!(instance.call_metrics(), Some(before_cancel));
    assert!(!instance.has_active_call());
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Validation)
    );

    instance.start_call("value", &[], 10, 10).unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(7)])
    );
}

#[test]
fn cancellation_has_priority_when_the_total_is_already_debited() {
    let module = compile(r#"(module (func (export "spin") (loop br 0)))"#);
    let mut instance = module.instantiate().unwrap();
    instance.start_call("spin", &[], 10, 10).unwrap();
    instance.debit_call_fuel(10).unwrap();
    instance.cancel_call().unwrap();

    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::Cancelled)
    );
    assert_eq!(
        instance.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 10,
            remaining_fuel: 0,
        })
    );
}

#[test]
fn an_indivisible_charge_above_the_quantum_fails_closed() {
    let module = compile(
        r#"(module
              (memory (export "memory") 1 16)
              (func (export "grow-ten") (result i32)
                i32.const 10
                memory.grow)
              (func (export "pages") (result i32)
                memory.size))"#,
    );
    let mut instance = module.instantiate().unwrap();
    let total_fuel = 20_000;
    let poll_quantum = PROFILE_1_LIMITS.poll_quantum;
    let expected_metrics = CallMetrics {
        consumed_fuel: 4,
        remaining_fuel: 19_996,
    };
    for _ in 0..2 {
        instance
            .start_call("grow-ten", &[], total_fuel, poll_quantum)
            .unwrap();
        assert_eq!(
            instance.poll_call(),
            PollResult::Trapped(TrapCode::LimitExceeded)
        );
        let metrics = instance.call_metrics().unwrap();
        assert_eq!(metrics, expected_metrics);
        assert_eq!(instance.memory_size("memory"), Ok(65_536));
        assert!(!instance.has_active_call());
    }

    instance
        .start_call("grow-ten", &[], poll_quantum, poll_quantum)
        .unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Trapped(TrapCode::FuelExhausted)
    );
    assert_eq!(
        instance.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 4,
            remaining_fuel: 9_996,
        })
    );
    assert_eq!(instance.memory_size("memory"), Ok(65_536));
    assert!(!instance.has_active_call());

    instance.start_call("pages", &[], 10, 10).unwrap();
    assert_eq!(
        instance.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
}

#[test]
fn a_dynamic_charge_at_the_quantum_boundary_resumes_without_resetting_total_fuel() {
    const SOURCE: &str = r#"(module
          (memory (export "memory") 1 16)
          (func (export "grow-nine") (result i32)
            i32.const 9
            memory.grow))"#;

    let module = compile(SOURCE);
    let mut exact = module.instantiate().unwrap();
    exact.start_call("grow-nine", &[], 20_000, 9_220).unwrap();
    assert_eq!(
        exact.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    assert_eq!(
        exact.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 9_220,
            remaining_fuel: 10_780,
        })
    );
    assert_eq!(exact.memory_size("memory"), Ok(10 * 65_536));

    let mut resumed = module.instantiate().unwrap();
    resumed.start_call("grow-nine", &[], 20_000, 9_219).unwrap();
    assert_eq!(
        resumed.poll_call(),
        PollResult::Pending {
            consumed_fuel: 4,
            remaining_fuel: 19_996,
        }
    );
    assert_eq!(resumed.memory_size("memory"), Ok(65_536));
    assert_eq!(
        resumed.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    assert_eq!(
        resumed.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 9_220,
            remaining_fuel: 10_780,
        })
    );
    assert_eq!(resumed.memory_size("memory"), Ok(10 * 65_536));

    let mut exact_dynamic = module.instantiate().unwrap();
    exact_dynamic
        .start_call("grow-nine", &[], 20_000, 9_216)
        .unwrap();
    assert_eq!(
        exact_dynamic.poll_call(),
        PollResult::Pending {
            consumed_fuel: 4,
            remaining_fuel: 19_996,
        }
    );
    assert_eq!(exact_dynamic.memory_size("memory"), Ok(65_536));
    assert_eq!(
        exact_dynamic.poll_call(),
        PollResult::Ready(vec![CoreValue::I32(1)])
    );
    assert_eq!(
        exact_dynamic.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 9_220,
            remaining_fuel: 10_780,
        })
    );
    assert_eq!(exact_dynamic.memory_size("memory"), Ok(10 * 65_536));

    let mut dynamic_plus_one = module.instantiate().unwrap();
    dynamic_plus_one
        .start_call("grow-nine", &[], 20_000, 9_215)
        .unwrap();
    assert_eq!(
        dynamic_plus_one.poll_call(),
        PollResult::Trapped(TrapCode::LimitExceeded)
    );
    assert_eq!(
        dynamic_plus_one.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 4,
            remaining_fuel: 19_996,
        })
    );
    assert_eq!(dynamic_plus_one.memory_size("memory"), Ok(65_536));

    let mut insufficient = module.instantiate().unwrap();
    insufficient
        .start_call("grow-nine", &[], 9_219, 9_219)
        .unwrap();
    assert_eq!(
        insufficient.poll_call(),
        PollResult::Trapped(TrapCode::FuelExhausted)
    );
    assert_eq!(
        insufficient.call_metrics(),
        Some(CallMetrics {
            consumed_fuel: 4,
            remaining_fuel: 9_215,
        })
    );
    assert_eq!(insufficient.memory_size("memory"), Ok(65_536));
}

#[test]
fn legacy_invocation_delivers_each_terminal_once() {
    let module = compile(
        r#"(module
              (func (export "value") (result i32) i32.const 7)
              (func (export "spin") (loop br 0)))"#,
    );
    let mut instance = module.instantiate().unwrap();

    {
        let mut call = instance.begin_call("value", &[], 10, 10).unwrap();
        assert_eq!(call.poll(), PollResult::Ready(vec![CoreValue::I32(7)]));
        let terminal_metrics = (call.consumed_fuel(), call.remaining_fuel());
        assert_eq!(call.poll(), PollResult::Trapped(TrapCode::Validation));
        assert_eq!(
            (call.consumed_fuel(), call.remaining_fuel()),
            terminal_metrics
        );
    }

    {
        let mut call = instance.begin_call("spin", &[], 1, 1).unwrap();
        assert_eq!(call.poll(), PollResult::Trapped(TrapCode::FuelExhausted));
        let terminal_metrics = (call.consumed_fuel(), call.remaining_fuel());
        assert_eq!(call.poll(), PollResult::Trapped(TrapCode::Validation));
        assert_eq!(
            (call.consumed_fuel(), call.remaining_fuel()),
            terminal_metrics
        );
    }

    {
        let mut call = instance.begin_call("spin", &[], 10, 10).unwrap();
        call.cancel();
        assert_eq!(call.poll(), PollResult::Trapped(TrapCode::Cancelled));
        let terminal_metrics = (call.consumed_fuel(), call.remaining_fuel());
        assert_eq!(call.poll(), PollResult::Trapped(TrapCode::Validation));
        assert_eq!(
            (call.consumed_fuel(), call.remaining_fuel()),
            terminal_metrics
        );
    }
}
