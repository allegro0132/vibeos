#![cfg(feature = "c810-s4-acceptance")]

use vibeos_component_admission::{
    admit, admit_simd_acceptance_candidate, AdmissionError, AdmissionPolicy, ArtifactTrust,
    AuthorityOffer, CallerAuthority, CommandStreamMode, ComponentArtifact, InstanceLimits,
    ProfileIdentity, SimdAcceptanceAdmissionPolicy, SimdCandidateError, SimdCandidatePoll,
    SimdCandidateState, SIMD_ACCEPTANCE_ACTIVATION_LABEL,
};
use vibeos_component_format::{current_validation_engine_identity, ProfileStage, TrapCode};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::{
    decode::{current_component_validation_engine, inspect_component_for_profile_4_candidate},
    world::WorldContract,
};
use vibeos_core::cap::Rights;
use vibeos_wasm_runtime::profile_4_candidate_required_compile_bytes;

const EXACT_WORLD: &str = "vibe:simd/validation@1.0.0";
const WIT: &str = r#"
    package vibe:simd@1.0.0;
    world validation {
        export run: func(mode: u32, input: list<u8>) -> list<u8>;
    }
"#;

const COMPONENT: &str = r#"
    (component
      (core module $guest
        (memory (export "memory") 1 1)
        (data (i32.const 0) "\00\10\00\00")
        (func (export "cabi_realloc")
          (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32)
          (result i32)
          local.get $new-size
          i32.eqz
          if
            i32.const 0
            return
          end
          local.get $old
          if
            local.get $old
            return
          end
          i32.const 4096)
        (func (export "run") (param $mode i32) (param $input i32) (param $length i32) (result i32)
          local.get $mode
          i32.const 1
          i32.eq
          if unreachable end
          local.get $mode
          i32.const 2
          i32.eq
          if
            loop $spin br $spin end
          end
          local.get $mode
          i32x4.splat
          i32x4.extract_lane 0
          drop
          i32.const 512)
        (func (export "cabi_post_run") (param i32)))
      (core instance $instance (instantiate $guest))
      (alias core export $instance "memory" (core memory $memory))
      (alias core export $instance "cabi_realloc" (core func $realloc))
      (alias core export $instance "run" (core func $run))
      (alias core export $instance "cabi_post_run" (core func $post-return))
      (type $bytes (list u8))
      (type $run-type (func (param "mode" u32) (param "input" $bytes) (result $bytes)))
      (func $lifted (type $run-type)
        (canon lift (core func $run)
          (memory $memory)
          (realloc $realloc)
          (post-return $post-return)))
      (export "run" (func $lifted)))
"#;

fn bytes() -> Vec<u8> {
    wat::parse_str(COMPONENT).unwrap()
}

fn world() -> WorldContract {
    WorldContract::parse_profile_4_sync_simd_candidate(WIT, EXACT_WORLD).unwrap()
}

fn limits(total_fuel: u64) -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 65_536,
        total_fuel,
        poll_quantum: total_fuel,
        resources: 0,
    }
}

fn policy<'a>(
    artifact: &ComponentArtifact,
    world: &'a WorldContract,
    total_fuel: u64,
) -> SimdAcceptanceAdmissionPolicy<'a> {
    let component = bytes();
    let plan = inspect_component_for_profile_4_candidate(&component).unwrap();
    SimdAcceptanceAdmissionPolicy {
        activation_label: SIMD_ACCEPTANCE_ACTIVATION_LABEL,
        exact_world: world,
        trust: ArtifactTrust::ImagePinned(artifact.identity()),
        limits: limits(total_fuel),
        compile_reservation_bytes: profile_4_candidate_required_compile_bytes(
            plan.embedded_modules()[0],
        )
        .unwrap(),
    }
}

fn candidate_artifact() -> ComponentArtifact {
    ComponentArtifact::copy_from(&bytes(), ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION).unwrap()
}

#[test]
fn exact_code7_candidate_is_default_off_authority_free_and_non_current() {
    let artifact = candidate_artifact();
    let world = world();
    let admitted = admit_simd_acceptance_candidate(
        artifact,
        &policy(&candidate_artifact(), &world, 10_000),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    assert_eq!(admitted.profile().stage, ProfileStage::ValidationOnly);
    assert!(!admitted.profile().execution_enabled());
    assert_eq!(admitted.world(), EXACT_WORLD);
    assert_eq!(admitted.limits().resources, 0);
    assert!(admitted.compile_reservation_bytes() > 0);
    assert!(admitted
        .validated_plan()
        .unwrap()
        .has_exact_simd_candidate_execution_binding());
    assert!(current_validation_engine_identity(admitted.profile()).is_none());
    assert!(current_component_validation_engine(admitted.profile()).is_none());

    let ordinary_artifact = candidate_artifact();
    let ordinary = AdmissionPolicy {
        command_name: "simd",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: &world,
        profile: ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION,
        trust: ArtifactTrust::ImagePinned(ordinary_artifact.identity()),
        limits: InstanceLimits {
            resources: 1,
            ..limits(10_000)
        },
        stdin: CommandStreamMode::Closed,
        stdout: CommandStreamMode::Closed,
        stderr: CommandStreamMode::Closed,
        interfaces: &[],
    };
    assert_eq!(
        admit(
            ordinary_artifact,
            &ordinary,
            &CallerAuthority { offers: &[] }
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );
}

#[test]
fn quota_cancel_fault_cold_recovery_and_revoke_are_instance_exact() {
    let artifact = candidate_artifact();
    let world = world();
    let admitted = admit_simd_acceptance_candidate(
        artifact,
        &policy(&candidate_artifact(), &world, 50),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    let mut lifecycle = admitted.activate().unwrap();
    assert_eq!(lifecycle.live_instances(), 1);

    lifecycle.start_call(0, b"abc").unwrap();
    assert_eq!(
        lifecycle.poll_call().unwrap(),
        SimdCandidatePoll::Ready(Vec::new())
    );
    assert!(lifecycle.metrics().last_consumed_fuel <= 50);

    lifecycle.start_call(0, b"cancel").unwrap();
    lifecycle.cancel().unwrap();
    assert_eq!(lifecycle.state(), SimdCandidateState::Cancelled);
    assert_eq!(lifecycle.live_instances(), 0);
    lifecycle.recover().unwrap();

    lifecycle.start_call(1, b"fault").unwrap();
    assert_eq!(
        lifecycle.poll_call().unwrap(),
        SimdCandidatePoll::Faulted(TrapCode::Validation)
    );
    lifecycle.recover().unwrap();

    lifecycle.start_call(2, b"fuel").unwrap();
    assert_eq!(
        lifecycle.poll_call().unwrap(),
        SimdCandidatePoll::Faulted(TrapCode::FuelExhausted)
    );
    lifecycle.recover().unwrap();
    lifecycle.revoke();
    lifecycle.revoke();
    assert_eq!(lifecycle.state(), SimdCandidateState::Revoked);
    assert_eq!(lifecycle.live_instances(), 0);
    assert_eq!(lifecycle.metrics().cancellations, 1);
    assert_eq!(lifecycle.metrics().faults, 2);
    assert_eq!(lifecycle.metrics().recoveries, 3);
    assert_eq!(lifecycle.metrics().revocations, 1);
    assert_eq!(lifecycle.recover(), Err(SimdCandidateError::Revoked));
}

#[test]
fn pin_reservation_limits_and_empty_authority_fail_closed() {
    let world = world();
    let artifact = candidate_artifact();
    let mut wrong_pin = policy(&artifact, &world, 100);
    wrong_pin.trust = ArtifactTrust::ImagePinned(
        ComponentArtifact::copy_from(b"adjacent", ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION)
            .unwrap()
            .identity(),
    );
    assert_eq!(
        admit_simd_acceptance_candidate(artifact, &wrong_pin, &CallerAuthority { offers: &[] })
            .err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let artifact = candidate_artifact();
    let mut exact = policy(&artifact, &world, 100);
    exact.compile_reservation_bytes -= 1;
    assert_eq!(
        admit_simd_acceptance_candidate(artifact, &exact, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::InvalidLimits)
    );

    let artifact = candidate_artifact();
    let mut wrong_label = policy(&artifact, &world, 100);
    wrong_label.activation_label = "adjacent";
    assert_eq!(
        admit_simd_acceptance_candidate(artifact, &wrong_label, &CallerAuthority { offers: &[] })
            .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let artifact = candidate_artifact();
    let offer = [AuthorityOffer {
        label: "clock0",
        kind: HostResourceKind::Clock,
        grantable: Rights::READ,
    }];
    assert_eq!(
        admit_simd_acceptance_candidate(
            artifact,
            &policy(&candidate_artifact(), &world, 100),
            &CallerAuthority { offers: &offer }
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );
}
