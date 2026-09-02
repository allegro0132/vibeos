#![cfg(feature = "c89-float-executable")]

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, ProfileStage,
    PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
};
use vibeos_component_runtime::{
    decode::{current_component_validation_engine, inspect_component_for_profile, DecodeError},
    float_candidate::{
        FloatCandidateError, FloatCandidateLifecyclePoll, FloatCandidateLimits,
        FloatCandidateState, FloatExecutableComponent,
    },
    value::{CanonicalF32, CanonicalF64, CanonicalValue},
};

const COMPONENT: &str =
    include_str!("../../policy/image/artifacts/c88-float-candidate.component.wat");

fn bytes() -> Vec<u8> {
    wat::parse_str(COMPONENT).unwrap()
}

fn limits(plan: &vibeos_component_runtime::decode::ComponentPlan<'_>) -> FloatCandidateLimits {
    FloatCandidateLimits {
        compile_reservation_bytes: FloatExecutableComponent::required_compile_reservation(plan)
            .unwrap(),
        memory_bytes: 2 * 65_536,
        total_fuel: 100_000,
        poll_quantum: 100,
    }
}

#[test]
fn code6_is_current_and_executable_while_code5_remains_inert() {
    let bytes = bytes();
    let profile = ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE;
    assert_eq!(profile.stage, ProfileStage::Executable);
    assert!(profile.execution_enabled());
    let engine = current_validation_engine_identity(profile).unwrap();
    assert_eq!(engine.profile(), profile);
    assert_eq!(engine.wasmi().name(), "vibeos-wasmi-softfloat");
    assert_eq!(engine.wasmi().version(), "1.1.0-vibeos-f2.1");
    assert!(current_component_validation_engine(profile).is_some());

    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(matches!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_2_SYNC_FLOAT),
        Err(DecodeError::Unsupported)
    ));

    let plan = inspect_component_for_profile(&bytes, profile).unwrap();
    assert!(plan.runtime_ready());
    assert!(plan.has_exact_float_candidate_execution_binding());
    assert!(plan.imports().is_empty());
    assert!(plan.host_imports().next().is_none());
    let mut lifecycle = FloatExecutableComponent::compile(&plan, limits(&plan))
        .unwrap()
        .activate()
        .unwrap();
    lifecycle
        .start_call(
            0,
            CanonicalF32::from_bits(0xff80_0001),
            CanonicalF64::from_bits(0),
        )
        .unwrap();
    loop {
        match lifecycle.poll_call().unwrap() {
            FloatCandidateLifecyclePoll::Pending(_) => {}
            FloatCandidateLifecyclePoll::Ready(value) => {
                assert_eq!(
                    value,
                    CanonicalValue::F64(CanonicalF64::from_bits(
                        PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS
                    ))
                );
                break;
            }
            FloatCandidateLifecyclePoll::Faulted(trap) => panic!("unexpected trap: {trap:?}"),
        }
    }
}

#[test]
fn code6_lifecycle_reclaims_on_cancel_fault_recovery_and_revoke() {
    let bytes = bytes();
    let plan =
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE)
            .unwrap();
    let mut lifecycle = FloatExecutableComponent::compile(&plan, limits(&plan))
        .unwrap()
        .activate()
        .unwrap();
    lifecycle
        .start_call(2, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert!(matches!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Pending(_)
    ));
    lifecycle.cancel().unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Cancelled);
    assert_eq!(lifecycle.live_instances(), 0);
    lifecycle.recover().unwrap();
    lifecycle
        .start_call(1, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert!(matches!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Faulted(_)
    ));
    lifecycle.recover().unwrap();
    lifecycle.revoke();
    assert_eq!(lifecycle.state(), FloatCandidateState::Revoked);
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.recover(), Err(FloatCandidateError::Revoked));
    assert_eq!(lifecycle.metrics().peak_live_instances, 1);
}

#[test]
fn adjacent_code6_identity_is_not_current() {
    let mut adjacent = ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE;
    adjacent.runtime_abi += 1;
    assert!(current_validation_engine_identity(adjacent).is_none());
    assert!(current_component_validation_engine(adjacent).is_none());
}
