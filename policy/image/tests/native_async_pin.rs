#![cfg(feature = "c53-native-async-qemu-acceptance")]

use vibeos_component_admission::{
    admit, admit_native_async_acceptance_candidate, AdmissionError, AdmissionPolicy, ArtifactTrust,
    CallerAuthority, CommandStreamMode, ComponentArtifact, ComponentIdentity, InstanceLimits,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_image_policy::{
    ComponentInstanceLimits, ComponentStreamMode, NativeAsyncAcceptancePin,
    C53_NATIVE_ASYNC_QEMU_ACCEPTANCE,
};

fn admission_mode(mode: ComponentStreamMode) -> CommandStreamMode {
    match mode {
        ComponentStreamMode::Required => CommandStreamMode::Required,
        ComponentStreamMode::Optional => CommandStreamMode::Optional,
        ComponentStreamMode::Closed => CommandStreamMode::Closed,
    }
}

fn admission_limits(limits: ComponentInstanceLimits) -> InstanceLimits {
    InstanceLimits {
        memory_bytes: limits.memory_bytes,
        total_fuel: limits.total_fuel,
        poll_quantum: limits.poll_quantum,
        resources: limits.resources,
    }
}

fn policy<'a>(
    pin: NativeAsyncAcceptancePin,
    world: &'a WorldContract,
    identity: ComponentIdentity,
) -> AdmissionPolicy<'a> {
    AdmissionPolicy {
        command_name: pin.command_name(),
        entrypoint: pin.entrypoint(),
        min_args: pin.min_args(),
        max_args: pin.max_args(),
        exact_world: world,
        profile: pin.profile(),
        trust: ArtifactTrust::ImagePinned(identity),
        limits: admission_limits(pin.limits()),
        stdin: admission_mode(pin.stdin()),
        stdout: admission_mode(pin.stdout()),
        stderr: admission_mode(pin.stderr()),
        interfaces: &[],
    }
}

fn exact_world(pin: NativeAsyncAcceptancePin) -> WorldContract {
    WorldContract::parse(pin.wit_source(), pin.world()).unwrap()
}

#[test]
fn pinned_native_async_candidate_admits_only_through_the_isolated_path() {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    assert_eq!(identity.as_bytes(), &pin.expected_sha256());
    let world = exact_world(pin);
    let candidate = admit_native_async_acceptance_candidate(
        artifact,
        &policy(pin, &world, identity),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();

    assert_eq!(candidate.command_name(), "c53-native-filter");
    assert_eq!(candidate.world(), "vibe:stream/native-filter@1.0.0");
    let plan = candidate.validated_plan().unwrap();
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert_eq!(plan.runtime_instance_count(), 1);
    assert_eq!(
        plan.native_async_execution_plan().unwrap().exports().len(),
        1
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    assert_eq!(
        admit(
            artifact,
            &policy(pin, &world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );
}

#[test]
fn pinned_native_async_hash_and_independent_wit_fail_closed() {
    let pin = C53_NATIVE_ASYNC_QEMU_ACCEPTANCE;
    let pinned = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let pinned_identity = pinned.identity();
    let world = exact_world(pin);

    let mut corrupted = pin.artifact_bytes().to_vec();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    let corrupted = ComponentArtifact::copy_from(&corrupted, pin.profile()).unwrap();
    assert_eq!(
        admit_native_async_acceptance_candidate(
            corrupted,
            &policy(pin, &world, pinned_identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    let mut adjacent_world = exact_world(pin);
    adjacent_world.identity = String::from("vibe:stream/native-filter@1.0.1");
    assert_eq!(
        admit_native_async_acceptance_candidate(
            artifact,
            &policy(pin, &adjacent_world, identity),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile()).unwrap();
    let identity = artifact.identity();
    let mut wrong_contract = exact_world(pin);
    wrong_contract.exports.clear();
    assert!(matches!(
        admit_native_async_acceptance_candidate(
            artifact,
            &policy(pin, &wrong_contract, identity),
            &CallerAuthority { offers: &[] },
        ),
        Err(AdmissionError::World(_))
    ));
}
