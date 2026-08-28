#![cfg(feature = "c88-f4-acceptance")]

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, TrapCode,
    PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
};
use vibeos_component_runtime::{
    decode::{
        current_component_validation_engine, inspect_component,
        inspect_component_for_profile_2_candidate, DecodeError,
    },
    float_candidate::{
        FloatCandidateComponent, FloatCandidateError, FloatCandidateLifecycle,
        FloatCandidateLifecyclePoll, FloatCandidateLimits, FloatCandidateState,
    },
    value::{CanonicalF32, CanonicalF64, CanonicalValue},
};
use vibeos_wasm_runtime::{
    profile_2_candidate_required_compile_bytes, AdmissionDetail, AdmissionError,
};

const COMPONENT: &str =
    include_str!("../../policy/image/artifacts/c88-float-candidate.component.wat");

fn component_bytes() -> Vec<u8> {
    wat::parse_str(COMPONENT).expect("the pinned F4 Component WAT must remain valid")
}

fn limits(bytes: &[u8]) -> FloatCandidateLimits {
    let plan = inspect_component_for_profile_2_candidate(bytes).unwrap();
    FloatCandidateLimits {
        compile_reservation_bytes: profile_2_candidate_required_compile_bytes(
            plan.embedded_modules()[0],
        )
        .unwrap(),
        memory_bytes: 65_536,
        total_fuel: 50_000,
        poll_quantum: 50,
    }
}

fn lifecycle(bytes: &[u8]) -> FloatCandidateLifecycle {
    let plan = inspect_component_for_profile_2_candidate(bytes).unwrap();
    FloatCandidateComponent::compile(&plan, limits(bytes))
        .unwrap()
        .activate()
        .unwrap()
}

fn run_ready(lifecycle: &mut FloatCandidateLifecycle, left: u32, right: u64) -> CanonicalValue {
    lifecycle
        .start_call(
            0,
            CanonicalF32::from_bits(left),
            CanonicalF64::from_bits(right),
        )
        .unwrap();
    for _ in 0..10_000 {
        match lifecycle.poll_call().unwrap() {
            FloatCandidateLifecyclePoll::Pending(_) => {}
            FloatCandidateLifecyclePoll::Ready(value) => return value,
            FloatCandidateLifecyclePoll::Faulted(trap) => {
                panic!("successful candidate call trapped: {trap:?}")
            }
        }
    }
    panic!("candidate call did not terminate")
}

fn compile_with_limits(bytes: &[u8], limits: FloatCandidateLimits) -> FloatCandidateLifecycle {
    let plan = inspect_component_for_profile_2_candidate(bytes).unwrap();
    FloatCandidateComponent::compile(&plan, limits)
        .unwrap()
        .activate()
        .unwrap()
}

#[test]
fn explicit_candidate_activation_joins_f3_bits_to_f2_without_promoting_code5() {
    let bytes = component_bytes();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Unsupported)
    ));
    let plan = inspect_component_for_profile_2_candidate(&bytes).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert!(!plan.runtime_ready());
    assert!(!plan.profile().execution_enabled());
    assert!(plan.executable_exports().next().is_none());
    assert!(plan.host_imports().next().is_none());
    assert!(current_validation_engine_identity(plan.profile()).is_none());
    assert!(current_component_validation_engine(plan.profile()).is_none());

    let mut lifecycle = FloatCandidateComponent::compile(&plan, limits(&bytes))
        .unwrap()
        .activate()
        .unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Idle);
    assert_eq!(lifecycle.live_instances(), 1);
    assert_eq!(lifecycle.metrics().peak_live_instances, 1);

    assert_eq!(
        run_ready(&mut lifecycle, 0x3fc0_0000, 0),
        CanonicalValue::F64(CanonicalF64::from_bits(0x3ff8_0000_0000_0000))
    );
    assert_eq!(
        run_ready(&mut lifecycle, 0xff80_0001, 0),
        CanonicalValue::F64(CanonicalF64::from_bits(
            PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS
        ))
    );
    assert_eq!(lifecycle.metrics().calls_completed, 2);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 0);
    assert_eq!(lifecycle.live_instances(), 1);

    assert_eq!(
        run_ready(&mut lifecycle, 0x3fc0_0000, 0x4002_0000_0000_0000),
        CanonicalValue::F64(CanonicalF64::from_bits(0x400e_0000_0000_0000))
    );
    assert_eq!(
        run_ready(&mut lifecycle, 0x8000_0000, 0x8000_0000_0000_0000),
        CanonicalValue::F64(CanonicalF64::from_bits(0x8000_0000_0000_0000))
    );
    assert_eq!(
        run_ready(&mut lifecycle, 0, 1),
        CanonicalValue::F64(CanonicalF64::from_bits(1))
    );
}

#[test]
fn cancellation_fault_recovery_and_revoke_reclaim_whole_instances_once() {
    let bytes = component_bytes();
    let mut lifecycle = lifecycle(&bytes);

    lifecycle
        .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert!(matches!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Pending(_)
    ));
    assert_eq!(
        lifecycle.start_call(0, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0)),
        Err(FloatCandidateError::Busy)
    );
    lifecycle.cancel().unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Cancelled);
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.metrics().cancellations, 1);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 1);
    assert_eq!(lifecycle.poll_call(), Err(FloatCandidateError::NotRunning));

    lifecycle.recover().unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Idle);
    assert_eq!(lifecycle.live_instances(), 1);
    lifecycle
        .start_call(1, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert_eq!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Faulted(TrapCode::Unreachable)
    );
    assert_eq!(
        lifecycle.state(),
        FloatCandidateState::Faulted(TrapCode::Unreachable)
    );
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.metrics().faults, 1);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 2);

    lifecycle.recover().unwrap();
    assert_eq!(
        run_ready(&mut lifecycle, 0x3f80_0000, 0),
        CanonicalValue::F64(CanonicalF64::from_bits(0x3ff0_0000_0000_0000))
    );
    lifecycle
        .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert!(matches!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Pending(_)
    ));
    lifecycle.revoke();
    lifecycle.revoke();
    assert_eq!(lifecycle.state(), FloatCandidateState::Revoked);
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.metrics().revocations, 1);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 3);
    assert_eq!(lifecycle.recover(), Err(FloatCandidateError::Revoked));
    assert_eq!(
        lifecycle.start_call(0, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0)),
        Err(FloatCandidateError::Revoked)
    );
    assert_eq!(lifecycle.metrics().peak_live_instances, 1);
}

#[test]
fn compile_memory_fuel_and_quantum_quotas_fail_before_candidate_work() {
    let bytes = component_bytes();
    let plan = inspect_component_for_profile_2_candidate(&bytes).unwrap();
    let exact = limits(&bytes);

    let short = FloatCandidateLimits {
        compile_reservation_bytes: exact.compile_reservation_bytes - 1,
        ..exact
    };
    assert!(matches!(
        FloatCandidateComponent::compile(&plan, short),
        Err(FloatCandidateError::CoreAdmission(AdmissionError {
            detail: AdmissionDetail::AllocationReservation,
            ..
        }))
    ));

    let surplus = FloatCandidateLimits {
        compile_reservation_bytes: exact.compile_reservation_bytes + 1,
        ..exact
    };
    assert!(matches!(
        FloatCandidateComponent::compile(&plan, surplus),
        Err(FloatCandidateError::InvalidLimits)
    ));

    for invalid in [
        FloatCandidateLimits {
            compile_reservation_bytes: 0,
            ..exact
        },
        FloatCandidateLimits {
            total_fuel: 0,
            ..exact
        },
        FloatCandidateLimits {
            poll_quantum: exact.total_fuel + 1,
            ..exact
        },
    ] {
        assert!(matches!(
            FloatCandidateComponent::compile(&plan, invalid),
            Err(FloatCandidateError::InvalidLimits)
        ));
    }

    let too_small_for_declared_minimum = FloatCandidateLimits {
        memory_bytes: 65_535,
        ..exact
    };
    assert!(matches!(
        FloatCandidateComponent::compile(&plan, too_small_for_declared_minimum)
            .unwrap()
            .activate(),
        Err(FloatCandidateError::Instantiation(TrapCode::LimitExceeded))
    ));

    let exact_component = FloatCandidateComponent::compile(&plan, exact).unwrap();
    assert_eq!(exact_component.limits(), exact);
    assert_eq!(exact_component.activate().unwrap().live_instances(), 1);
}

#[test]
fn finite_fuel_exhaustion_reclaims_and_cold_recovery_remains_bounded() {
    let bytes = component_bytes();
    let mut bounded = limits(&bytes);
    bounded.total_fuel = 50;
    bounded.poll_quantum = 7;
    let mut lifecycle = compile_with_limits(&bytes, bounded);

    lifecycle
        .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    let mut previous_consumed = 0;
    for _ in 0..32 {
        match lifecycle.poll_call().unwrap() {
            FloatCandidateLifecyclePoll::Pending(metrics) => {
                assert!(metrics.consumed_fuel > previous_consumed);
                assert!(metrics.consumed_fuel - previous_consumed <= bounded.poll_quantum);
                assert!(metrics.consumed_fuel <= bounded.total_fuel);
                assert_eq!(
                    metrics.consumed_fuel + metrics.remaining_fuel,
                    bounded.total_fuel
                );
                previous_consumed = metrics.consumed_fuel;
            }
            FloatCandidateLifecyclePoll::Faulted(TrapCode::FuelExhausted) => break,
            other => panic!("infinite candidate produced unexpected poll: {other:?}"),
        }
    }
    assert_eq!(
        lifecycle.state(),
        FloatCandidateState::Faulted(TrapCode::FuelExhausted)
    );
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.metrics().faults, 1);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 1);

    lifecycle.recover().unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Idle);
    assert_eq!(lifecycle.live_instances(), 1);
    assert_eq!(
        run_ready(&mut lifecycle, 0x3f80_0000, 0),
        CanonicalValue::F64(CanonicalF64::from_bits(0x3ff0_0000_0000_0000))
    );
}

#[test]
fn component_export_must_bind_the_exact_core_run_without_extra_wiring() {
    let misbound = wat::parse_str(
        r#"(component
          (core module $guest
            (memory (export "memory") 1 2)
            (func (export "run") (param i32 f32 f64) (result f64)
              local.get 2)
            (func (export "other") (param i32 f32 f64) (result f64)
              local.get 1
              f64.promote_f32
              local.get 2
              f64.add))
          (core instance $guest-instance (instantiate $guest))
          (alias core export $guest-instance "other" (core func $lifted-core))
          (type $run-type
            (func
              (param "mode" u32)
              (param "left" f32)
              (param "right" f64)
              (result f64)))
          (func $run (type $run-type) (canon lift (core func $lifted-core)))
          (export "run" (func $run)))"#,
    )
    .unwrap();
    let plan = inspect_component_for_profile_2_candidate(&misbound).unwrap();
    assert!(!plan.has_exact_float_candidate_execution_binding());
    assert_eq!(
        FloatCandidateComponent::required_compile_reservation(&plan),
        Err(FloatCandidateError::InvalidPlan)
    );

    let extra_alias = COMPONENT.replacen(
        "(type $run-type",
        "(alias core export $guest-instance \"run\" (core func $unused-run))\n\n  (type $run-type",
        1,
    );
    let extra_alias = wat::parse_str(&extra_alias).unwrap();
    let plan = inspect_component_for_profile_2_candidate(&extra_alias).unwrap();
    assert!(plan.has_exact_float_candidate_execution_binding());
    assert_eq!(plan.summary().aliases, 2);
    assert_eq!(
        FloatCandidateComponent::required_compile_reservation(&plan),
        Err(FloatCandidateError::InvalidPlan)
    );
}
