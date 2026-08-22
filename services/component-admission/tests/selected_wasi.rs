#![cfg(feature = "selected-wasi-admission")]

use vibeos_component_admission::{
    admit, admit_selected_wasi_candidate, AdmissionError, AdmissionPolicy, ArtifactTrust,
    CallerAuthority, CommandStreamMode, ComponentArtifact, InstanceLimits,
    SelectedWasiAdmissionPolicy,
};
use vibeos_component_format::{
    ProfileIdentity, ProfileStage, SelectedWasiCapability, SelectedWasiInterfaceDirection,
    SelectedWasiMappingCategory, SELECTED_WASI_COMMAND_WIT, SELECTED_WASI_COMMAND_WORLD,
    SELECTED_WASI_INTERFACE_MAPPINGS, SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
    SELECTED_WASI_SECURE_RANDOM_INTERFACE,
};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::world::{WorldContract, WorldError};
use vibeos_core::cap::Rights;

const SELECTED_WASI_COMPONENT: &str = include_str!(
    "../../../component-format/tests/corpus/component/wasi-selected-0.3.0.component.wat"
);

fn artifact(source: &str, profile: ProfileIdentity) -> ComponentArtifact {
    let bytes = wat::parse_str(source).expect("valid Component WAT fixture");
    ComponentArtifact::copy_from(&bytes, profile).expect("bounded Component artifact")
}

fn policy(
    identity: vibeos_component_admission::ComponentIdentity,
) -> SelectedWasiAdmissionPolicy<'static> {
    SelectedWasiAdmissionPolicy {
        command_name: "selected-wasi",
        trust: ArtifactTrust::ImagePinned(identity),
        limits: InstanceLimits::profile_default(1024 * 1024),
    }
}

fn admit_source(
    source: &str,
) -> Result<
    vibeos_component_admission::AdmittedSelectedWasiCandidate,
    vibeos_component_admission::AdmissionError,
> {
    let artifact = artifact(source, ProfileIdentity::PROFILE_1_ASYNC);
    let policy = policy(artifact.identity());
    admit_selected_wasi_candidate(artifact, &policy)
}

#[test]
fn selected_wasi_admission_is_exact_mapped_and_permanently_inert() {
    let artifact = artifact(SELECTED_WASI_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC);
    let identity = artifact.identity();
    let admitted = admit_selected_wasi_candidate(artifact, &policy(identity)).unwrap();

    assert_eq!(admitted.identity(), identity);
    assert_eq!(
        admitted.inspection().profile(),
        ProfileIdentity::PROFILE_1_ASYNC
    );
    assert_eq!(admitted.inspection().world(), SELECTED_WASI_COMMAND_WORLD);
    assert_eq!(
        (
            admitted.inspection().imports().len(),
            admitted.inspection().exports().len(),
        ),
        (6, 1)
    );

    let manifest = admitted.manifest();
    assert_eq!(manifest.command_name(), "selected-wasi");
    assert_eq!(manifest.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert_eq!(manifest.abi(), ProfileIdentity::PROFILE_1_ASYNC.runtime_abi);
    assert_eq!(manifest.artifact(), identity);
    assert_eq!(manifest.world(), SELECTED_WASI_COMMAND_WORLD);
    assert_eq!(
        manifest.host_mappings(),
        SELECTED_WASI_INTERFACE_MAPPINGS.as_slice()
    );
    assert_eq!(manifest.host_mappings().len(), 5);

    assert_eq!(
        manifest
            .host_mappings()
            .iter()
            .map(|mapping| (mapping.direction(), mapping.category()))
            .collect::<Vec<_>>(),
        [
            (
                SelectedWasiInterfaceDirection::Import,
                SelectedWasiMappingCategory::Capability(SelectedWasiCapability::MonotonicClock,),
            ),
            (
                SelectedWasiInterfaceDirection::Import,
                SelectedWasiMappingCategory::Capability(SelectedWasiCapability::SecureRandom),
            ),
            (
                SelectedWasiInterfaceDirection::Import,
                SelectedWasiMappingCategory::CommandStdin,
            ),
            (
                SelectedWasiInterfaceDirection::Import,
                SelectedWasiMappingCategory::CommandStdout,
            ),
            (
                SelectedWasiInterfaceDirection::Export,
                SelectedWasiMappingCategory::InvocationLifecycle,
            ),
        ]
    );

    let requirements = manifest.capability_requirements();
    assert_eq!(requirements.len(), 2);
    assert_eq!(
        requirements[0].interface(),
        SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE
    );
    assert_eq!(
        requirements[0].capability(),
        SelectedWasiCapability::MonotonicClock
    );
    assert_eq!(requirements[0].kind(), HostResourceKind::Clock);
    assert_eq!(requirements[0].rights(), Rights::READ);
    assert_eq!(
        requirements[1].interface(),
        SELECTED_WASI_SECURE_RANDOM_INTERFACE
    );
    assert_eq!(
        requirements[1].capability(),
        SelectedWasiCapability::SecureRandom
    );
    assert_eq!(requirements[1].kind(), HostResourceKind::Random);
    assert_eq!(requirements[1].rights(), Rights::READ);

    admitted.revalidate().unwrap();
    admitted.revalidate().unwrap();
    assert_eq!(admitted.identity(), identity);
}

#[test]
fn selected_wasi_identity_trust_name_and_limits_fail_closed() {
    for profile in [
        ProfileIdentity::PROFILE_1_SYNC,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
    ] {
        let artifact = artifact(SELECTED_WASI_COMPONENT, profile);
        let selected_policy = policy(artifact.identity());
        assert_eq!(
            admit_selected_wasi_candidate(artifact, &selected_policy).err(),
            Some(AdmissionError::BadProfile)
        );
    }

    for mutate in [
        |profile: &mut ProfileIdentity| profile.wasi_revision = "wasi-v0.3.1-adjacent",
        |profile: &mut ProfileIdentity| profile.runtime_abi += 1,
        |profile: &mut ProfileIdentity| profile.stage = ProfileStage::Executable,
    ] {
        let mut adjacent = ProfileIdentity::PROFILE_1_ASYNC;
        mutate(&mut adjacent);
        let artifact = artifact(SELECTED_WASI_COMPONENT, adjacent);
        let selected_policy = policy(artifact.identity());
        assert_eq!(
            admit_selected_wasi_candidate(artifact, &selected_policy).err(),
            Some(AdmissionError::BadProfile)
        );
    }

    let selected_artifact = artifact(SELECTED_WASI_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC);
    let foreign = artifact("(component)", ProfileIdentity::PROFILE_1_ASYNC).identity();
    let mut wrong_trust = policy(selected_artifact.identity());
    wrong_trust.trust = ArtifactTrust::ImagePinned(foreign);
    assert_eq!(
        admit_selected_wasi_candidate(selected_artifact, &wrong_trust).err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let bad_name_artifact = artifact(SELECTED_WASI_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC);
    let mut bad_name = policy(bad_name_artifact.identity());
    bad_name.command_name = "";
    assert_eq!(
        admit_selected_wasi_candidate(bad_name_artifact, &bad_name).err(),
        Some(AdmissionError::InvalidCommandName)
    );

    let bad_limits_artifact = artifact(SELECTED_WASI_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC);
    let mut bad_limits = policy(bad_limits_artifact.identity());
    bad_limits.limits.memory_bytes = 0;
    assert_eq!(
        admit_selected_wasi_candidate(bad_limits_artifact, &bad_limits).err(),
        Some(AdmissionError::InvalidLimits)
    );
}

#[test]
fn unselected_standard_interfaces_never_receive_a_fallback_mapping() {
    assert_eq!(AdmissionError::UnsupportedWasiInterface.code(), 19);
    let rejected = [
        "wasi:clocks/system-clock@0.3.0",
        "wasi:clocks/timezone@0.3.0",
        "wasi:random/insecure@0.3.0",
        "wasi:random/insecure-seed@0.3.0",
        "wasi:cli/environment@0.3.0",
        "wasi:cli/exit@0.3.0",
        "wasi:cli/stderr@0.3.0",
        "wasi:cli/terminal-input@0.3.0",
        "wasi:cli/terminal-output@0.3.0",
        "wasi:cli/terminal-stdin@0.3.0",
        "wasi:cli/terminal-stdout@0.3.0",
        "wasi:cli/terminal-stderr@0.3.0",
        "wasi:filesystem/types@0.3.0",
        "wasi:filesystem/preopens@0.3.0",
        "wasi:sockets/types@0.3.0",
        "wasi:sockets/ip-name-lookup@0.3.0",
        "wasi:cli/command@0.3.0",
    ];
    for identity in rejected {
        // The allowlist rejects an unknown standard identity before its member
        // shape could be interpreted as selected authority.
        let mutated =
            SELECTED_WASI_COMPONENT.replacen(SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE, identity, 1);
        assert_eq!(
            admit_source(&mutated).err(),
            Some(AdmissionError::UnsupportedWasiInterface),
            "{identity}"
        );
    }

    // wasi:cli/command expands included interfaces at the component boundary;
    // it is not itself an interface import. Exercise the forbidden set as one
    // aggregate superset as well as the identity-isolation cases above.
    let mut full_command_imports = String::new();
    for (index, identity) in rejected[..rejected.len() - 1].iter().enumerate() {
        full_command_imports.push_str(&format!(
            "  (type $full-command-interface-{index} (instance))\n  (import \"{identity}\"\n    (instance $full-command-{index} (type $full-command-interface-{index})))\n"
        ));
    }
    let full_command_component = SELECTED_WASI_COMPONENT.replacen(
        "(component\n",
        &format!("(component\n{full_command_imports}"),
        1,
    );
    assert_eq!(
        admit_source(&full_command_component).err(),
        Some(AdmissionError::UnsupportedWasiInterface)
    );
}

#[test]
fn selected_interface_versions_types_and_effects_are_exact() {
    for (selected, adjacent) in [
        (
            SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
            "wasi:clocks/monotonic-clock@0.3.1",
        ),
        (
            SELECTED_WASI_SECURE_RANDOM_INTERFACE,
            "wasi:random/random@0.2.6",
        ),
        ("wasi:cli/stdin@0.3.0", "wasi:cli/stdin@0.3.0-rc"),
        ("wasi:cli/run@0.3.0", "wasi:cli/run@0.3.1"),
    ] {
        let mutated = SELECTED_WASI_COMPONENT.replace(selected, adjacent);
        assert_eq!(
            admit_source(&mutated).err(),
            Some(AdmissionError::UnsupportedWasiInterface),
            "{adjacent}"
        );
    }

    for mutated in [
        SELECTED_WASI_COMPONENT.replace(
            "(type $wait-for (func async (param \"how-long\" $duration-in)))",
            "(type $wait-for (func (param \"how-long\" $duration-in)))",
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(func (param \"max-len\" u64) (result (list u8)))",
            "(func (param \"max-len\" u32) (result (list u8)))",
        ),
        SELECTED_WASI_COMPONENT.replacen(
            "(enum \"io\" \"illegal-byte-sequence\" \"pipe\")",
            "(enum \"io\" \"pipe\" \"illegal-byte-sequence\")",
            1,
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(type $write-via-stream\n        (func (param \"data\" $bytes) (result $completed)))",
            "(type $write-via-stream\n        (func async (param \"data\" $bytes) (result $completed)))",
        ),
    ] {
        assert!(matches!(
            admit_source(&mutated),
            Err(AdmissionError::World(WorldError::TypeMismatch))
        ));
    }

    for wrong_direction in [
        SELECTED_WASI_COMPONENT.replacen(
            SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
            "wasi:cli/run@0.3.0",
            1,
        ),
        SELECTED_WASI_COMPONENT.replace(
            "(export \"wasi:cli/run@0.3.0\" (instance $run-interface))",
            &format!(
                "(export \"{SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE}\" (instance $run-interface))"
            ),
        ),
    ] {
        assert_eq!(
            admit_source(&wrong_direction).err(),
            Some(AdmissionError::UnsupportedWasiInterface)
        );
    }

    let missing_type_dependency = SELECTED_WASI_COMPONENT.replace(
        "  (import \"wasi:clocks/types@0.3.0\"\n    (instance $clock-types (type $clock-types-interface)))\n\n",
        "",
    );
    assert_ne!(missing_type_dependency, SELECTED_WASI_COMPONENT);
    assert_eq!(
        admit_source(&missing_type_dependency).err(),
        Some(AdmissionError::InvalidPolicy)
    );
}

#[test]
fn ordinary_admission_still_cannot_convert_the_selected_wasi_candidate() {
    let world = WorldContract::parse(SELECTED_WASI_COMMAND_WIT, SELECTED_WASI_COMMAND_WORLD)
        .expect("pinned selected-WASI world");
    let artifact = artifact(SELECTED_WASI_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC);
    let identity = artifact.identity();
    let ordinary_policy = AdmissionPolicy {
        command_name: "selected-wasi",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: &world,
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        trust: ArtifactTrust::ImagePinned(identity),
        limits: InstanceLimits::profile_default(1024 * 1024),
        stdin: CommandStreamMode::Required,
        stdout: CommandStreamMode::Required,
        stderr: CommandStreamMode::Closed,
        interfaces: &[],
    };
    assert_eq!(
        admit(artifact, &ordinary_policy, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::RuntimeUnavailable)
    );
}
