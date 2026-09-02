#![cfg(feature = "c88-f4-float-candidate")]

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, TrapCode,
    PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
};
use vibeos_component_image_adapter::project_float_candidate;
use vibeos_component_runtime::{
    decode::current_component_validation_engine,
    float_candidate::{
        FloatCandidateError, FloatCandidateLifecycle, FloatCandidateLifecyclePoll,
        FloatCandidateState,
    },
    value::{CanonicalF32, CanonicalF64, CanonicalValue},
};
use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;

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
                panic!("candidate success path trapped: {trap:?}")
            }
        }
    }
    panic!("candidate call did not terminate")
}

#[test]
fn exact_image_pin_projects_only_an_inert_candidate_receipt() {
    let pin = C88_F4_FLOAT_CANDIDATE;
    let projection = project_float_candidate(pin).unwrap();
    assert_eq!(projection.activation_label(), pin.activation_label());
    assert_eq!(projection.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert_eq!(projection.limits().memory_bytes, pin.limits().memory_bytes);
    assert_eq!(projection.limits().total_fuel, pin.limits().total_fuel);
    assert_eq!(projection.limits().poll_quantum, pin.limits().poll_quantum);
    assert_eq!(projection.limits().resources, 0);

    let plan = projection.validated_plan().unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert!(!plan.profile().execution_enabled());
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert!(plan.imports().is_empty());
    assert!(plan.host_imports().next().is_none());
    assert!(plan.executable_exports().next().is_none());
    assert_eq!(plan.summary().resources, 0);
    assert!(current_component_validation_engine(plan.profile()).is_none());
    assert!(current_validation_engine_identity(plan.profile()).is_none());
}

#[test]
fn image_pinned_activation_preserves_bits_and_closes_every_terminal_path() {
    let mut lifecycle = project_float_candidate(C88_F4_FLOAT_CANDIDATE)
        .unwrap()
        .activate_candidate()
        .unwrap();
    assert_eq!(lifecycle.state(), FloatCandidateState::Idle);
    assert_eq!(lifecycle.live_instances(), 1);
    assert_eq!(lifecycle.metrics().peak_live_instances, 1);
    assert_eq!(lifecycle.limits().memory_bytes, 2 * 65_536);

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
    lifecycle.recover().unwrap();

    lifecycle
        .start_call(1, CanonicalF32::from_bits(0), CanonicalF64::from_bits(0))
        .unwrap();
    assert_eq!(
        lifecycle.poll_call().unwrap(),
        FloatCandidateLifecyclePoll::Faulted(TrapCode::Unreachable)
    );
    assert_eq!(lifecycle.live_instances(), 0);
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
    assert_eq!(lifecycle.state(), FloatCandidateState::Revoked);
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.recover(), Err(FloatCandidateError::Revoked));
    assert_eq!(lifecycle.metrics().cancellations, 1);
    assert_eq!(lifecycle.metrics().faults, 1);
    assert_eq!(lifecycle.metrics().revocations, 1);
    assert_eq!(lifecycle.metrics().reclaimed_instances, 3);
    assert_eq!(lifecycle.metrics().peak_live_instances, 1);
}
