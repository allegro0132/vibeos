#![cfg(feature = "c89-float-executable")]

use vibeos_component_admission::{
    admit, admit_float_executable, AdmissionError, AdmissionPolicy, ArtifactTrust, CallerAuthority,
    CommandStreamMode, ComponentArtifact, FloatExecutableAdmissionPolicy, InstanceLimits,
    ProfileIdentity, FLOAT_EXECUTABLE_ACTIVATION_LABEL,
};
use vibeos_component_runtime::{
    float_candidate::FloatCandidateLifecyclePoll,
    value::{CanonicalF32, CanonicalF64},
    world::WorldContract,
};

const WORLD: &str = "vibe:float/runtime@1.0.0";
const WIT: &str = r#"
package vibe:float@1.0.0;
world runtime {
  export run: func(mode: u32, left: f32, right: f64) -> f64;
}
"#;
const COMPONENT: &str =
    include_str!("../../../policy/image/artifacts/c88-float-candidate.component.wat");

fn make_artifact(profile: ProfileIdentity) -> ComponentArtifact {
    ComponentArtifact::copy_from(&wat::parse_str(COMPONENT).unwrap(), profile).unwrap()
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 2 * 65_536,
        total_fuel: 100_000,
        poll_quantum: 100,
        resources: 0,
    }
}

#[test]
fn exact_code6_admission_activates_without_authority_or_durable_command() {
    let world = WorldContract::parse_profile_3_sync_float_executable(WIT, WORLD).unwrap();
    let artifact = make_artifact(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE);
    let identity = artifact.identity();
    let admitted = admit_float_executable(
        artifact,
        &FloatExecutableAdmissionPolicy {
            activation_label: FLOAT_EXECUTABLE_ACTIVATION_LABEL,
            exact_world: &world,
            trust: ArtifactTrust::ImagePinned(identity),
            limits: limits(),
        },
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    assert_eq!(
        admitted.profile(),
        ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE
    );
    assert_eq!(admitted.world(), WORLD);
    let mut lifecycle = admitted.activate().unwrap();
    lifecycle
        .start_call(
            0,
            CanonicalF32::from_bits(0x3f80_0000),
            CanonicalF64::from_bits(0),
        )
        .unwrap();
    loop {
        match lifecycle.poll_call().unwrap() {
            FloatCandidateLifecyclePoll::Pending(_) => {}
            FloatCandidateLifecyclePoll::Ready(_) => break,
            FloatCandidateLifecyclePoll::Faulted(trap) => panic!("unexpected trap: {trap:?}"),
        }
    }

    // The ordinary command admission/durable path remains closed to code 6.
    let artifact = make_artifact(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE);
    let command_policy = AdmissionPolicy {
        command_name: "float",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: &world,
        profile: ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE,
        trust: ArtifactTrust::ImagePinned(artifact.identity()),
        limits: InstanceLimits::profile_default(2 * 65_536),
        stdin: CommandStreamMode::Closed,
        stdout: CommandStreamMode::Closed,
        stderr: CommandStreamMode::Closed,
        interfaces: &[],
    };
    assert_eq!(
        admit(artifact, &command_policy, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::BadProfile)
    );
}

#[test]
fn code5_and_authority_bearing_inputs_cannot_enter_code6_admission() {
    let world = WorldContract::parse_profile_3_sync_float_executable(WIT, WORLD).unwrap();
    let artifact = make_artifact(ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let identity = artifact.identity();
    assert_eq!(
        admit_float_executable(
            artifact,
            &FloatExecutableAdmissionPolicy {
                activation_label: FLOAT_EXECUTABLE_ACTIVATION_LABEL,
                exact_world: &world,
                trust: ArtifactTrust::ImagePinned(identity),
                limits: limits(),
            },
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );
}
