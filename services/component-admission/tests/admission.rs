use vibeos_component_admission::{
    admit, AdmissionError, AdmissionPolicy, ArtifactTrust, AuthorityOffer, CallerAuthority,
    CommandStreamMode, ComponentArtifact, InstanceLimits, InterfaceCeiling, ProfileIdentity,
};
use vibeos_component_host::{HostManifestError, HostResourceKind, CLOCK_INTERFACE};
use vibeos_component_runtime::{decode::inspect_component, world::WorldContract};
use vibeos_core::cap::Rights;

const CLOCK_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-clock.component.wat");
const FOREIGN_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-pair.component.wat");
const PURE_COMPONENT: &str =
    include_str!("../../../component-format/tests/corpus/component/typed.component.wat");

fn artifact_and_exact_world(source: &str) -> (ComponentArtifact, WorldContract) {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract {
        identity: String::from("vibe:test/admitted@1.0.0"),
        imports: plan.imports,
        exports: plan.exports,
    };
    (ComponentArtifact::copy_from(&bytes).unwrap(), world)
}

fn clock_ceiling() -> InterfaceCeiling<'static> {
    InterfaceCeiling {
        label: "clock0",
        interface: CLOCK_INTERFACE,
        kind: HostResourceKind::Clock,
        rights: Rights::READ,
    }
}

fn clock_offer() -> AuthorityOffer<'static> {
    AuthorityOffer {
        label: "clock0",
        kind: HostResourceKind::Clock,
        grantable: Rights::READ,
    }
}

fn policy<'a>(
    identity: vibeos_component_admission::ComponentIdentity,
    world: &'a WorldContract,
    interfaces: &'a [InterfaceCeiling<'a>],
) -> AdmissionPolicy<'a> {
    AdmissionPolicy {
        command_name: "clock-filter",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: world,
        profile: ProfileIdentity::PROFILE_1,
        trust: ArtifactTrust::ImagePinned(identity),
        limits: InstanceLimits::profile_default(1024 * 1024),
        stdin: CommandStreamMode::Required,
        stdout: CommandStreamMode::Required,
        stderr: CommandStreamMode::Optional,
        interfaces,
    }
}

#[test]
fn pure_inspection_and_admission_create_an_inert_sealed_template() {
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let inspection = artifact.inspect().unwrap();
    assert_eq!(inspection.identity(), identity);
    assert_eq!(inspection.profile(), ProfileIdentity::PROFILE_1);
    assert_eq!(inspection.embedded_modules().len(), 1);
    assert_eq!(inspection.summary().embedded_modules, 1);
    assert_eq!(inspection.imports().len(), 1);
    drop(inspection);

    // Admission succeeds without an engine, CSpace, dispatcher, host backend,
    // or runtime instance. Calling the imported clock would be impossible here.
    let ceilings = [clock_ceiling()];
    let offers = [clock_offer()];
    let admitted = admit(
        artifact,
        &policy(identity, &world, &ceilings),
        &CallerAuthority { offers: &offers },
    )
    .unwrap();

    let manifest = admitted.command_manifest();
    assert_eq!(manifest.name(), "clock-filter");
    assert_eq!(manifest.abi(), ProfileIdentity::PROFILE_1.runtime_abi);
    assert_eq!(manifest.artifact(), identity);
    assert_eq!(manifest.world(), "vibe:test/admitted@1.0.0");
    assert_eq!(manifest.entrypoint(), "run");
    assert_eq!(manifest.min_args(), 0);
    assert_eq!(manifest.max_args(), 0);
    assert_eq!(manifest.stdin(), CommandStreamMode::Required);
    assert_eq!(manifest.stdout(), CommandStreamMode::Required);
    assert_eq!(manifest.stderr(), CommandStreamMode::Optional);
    assert_eq!(manifest.requirements().len(), 1);
    let requirement = &manifest.requirements()[0];
    assert_eq!(requirement.label(), "clock0");
    assert_eq!(requirement.interface(), CLOCK_INTERFACE);
    assert_eq!(requirement.resource(), "clock");
    assert_eq!(requirement.kind(), HostResourceKind::Clock);
    assert_eq!(requirement.rights(), Rights::READ);
    assert_eq!(admitted.grants().len(), 1);
    assert_eq!(admitted.grants()[0].requirement_index(), 0);
    assert_eq!(admitted.grants()[0].offer_index(), 0);
    assert_eq!(admitted.grants()[0].source_label(), "clock0");
    assert_eq!(admitted.grants()[0].kind(), HostResourceKind::Clock);
    assert_eq!(admitted.grants()[0].rights(), Rights::READ);

    // The admitted object owns bytes, not a self-referential plan. Each use
    // derives a fresh borrowed plan and fresh plan-local nominal resource IDs.
    let plan = admitted.validated_plan().unwrap();
    assert_eq!(plan.summary(), admitted.inspection().component());
}

#[test]
fn import_free_component_requires_no_ambient_authority() {
    let (artifact, world) = artifact_and_exact_world(PURE_COMPONENT);
    let identity = artifact.identity();
    let mut pure_policy = policy(identity, &world, &[]);
    pure_policy.entrypoint = "add";
    let admitted = admit(artifact, &pure_policy, &CallerAuthority { offers: &[] }).unwrap();
    assert!(admitted.command_manifest().requirements().is_empty());
    assert!(admitted.grants().is_empty());
    assert!(admitted.validated_plan().is_ok());
}

#[test]
fn admitted_template_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<vibeos_component_admission::AdmittedComponent>();
}

#[test]
fn exact_identity_profile_and_world_fail_closed() {
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let ceilings = [clock_ceiling()];
    let offers = [clock_offer()];
    let wrong_identity = ComponentArtifact::copy_from(b"different exact bytes")
        .unwrap()
        .identity();
    assert_eq!(
        admit(
            artifact,
            &policy(wrong_identity, &world, &ceilings),
            &CallerAuthority { offers: &offers },
        )
        .err(),
        Some(AdmissionError::UntrustedArtifact),
    );

    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let mut bad = ProfileIdentity::PROFILE_1;
    bad.component_profile += 1;
    let mut bad_policy = policy(artifact.identity(), &world, &ceilings);
    bad_policy.profile = bad;
    assert_eq!(
        admit(artifact, &bad_policy, &CallerAuthority { offers: &offers },).err(),
        Some(AdmissionError::BadProfile),
    );

    let (artifact, mut world) = artifact_and_exact_world(CLOCK_COMPONENT);
    world.exports.clear();
    assert!(matches!(
        admit(
            artifact,
            &policy(identity, &world, &ceilings),
            &CallerAuthority { offers: &offers },
        ),
        Err(AdmissionError::World(_))
    ));
}

#[test]
fn unknown_or_malformed_host_imports_never_become_requirements() {
    let (artifact, world) = artifact_and_exact_world(FOREIGN_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &[]),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::HostManifest(
            HostManifestError::UnexpectedImport
        )),
    );
}

#[test]
fn image_ceiling_and_caller_authority_intersect_exactly() {
    let offers = [clock_offer()];

    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &[]),
            &CallerAuthority { offers: &offers },
        )
        .err(),
        Some(AdmissionError::MissingImageCeiling),
    );

    let ceilings = [clock_ceiling()];
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &ceilings),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::MissingCallerAuthority),
    );

    let no_rights = [AuthorityOffer {
        grantable: Rights::NONE,
        ..clock_offer()
    }];
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &ceilings),
            &CallerAuthority { offers: &no_rights },
        )
        .err(),
        Some(AdmissionError::RightsAmplification),
    );

    let duplicate = [clock_ceiling(), clock_ceiling()];
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &duplicate),
            &CallerAuthority { offers: &offers },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy),
    );
}

#[test]
fn artifact_and_instance_bounds_are_checked_before_runtime_work() {
    let oversized = vec![0_u8; vibeos_component_format::PROFILE_1_LIMITS.max_artifact_bytes + 1];
    assert_eq!(
        ComponentArtifact::copy_from(&oversized).err(),
        Some(AdmissionError::ArtifactLimit),
    );

    let overlong_policy =
        vec![clock_ceiling(); vibeos_component_format::PROFILE_1_LIMITS.max_imports as usize + 1];
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &overlong_policy),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy),
    );

    let ceilings = [clock_ceiling()];
    let offers = [clock_offer()];
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let mut invalid = policy(identity, &world, &ceilings);
    invalid.limits.total_fuel = 0;
    assert_eq!(
        admit(artifact, &invalid, &CallerAuthority { offers: &offers },).err(),
        Some(AdmissionError::InvalidLimits),
    );

    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let mut invalid = policy(identity, &world, &ceilings);
    invalid.command_name = "not/a/command";
    assert_eq!(
        admit(artifact, &invalid, &CallerAuthority { offers: &offers },).err(),
        Some(AdmissionError::InvalidCommandName),
    );

    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let mut invalid = policy(identity, &world, &ceilings);
    invalid.entrypoint = "now";
    assert_eq!(
        admit(artifact, &invalid, &CallerAuthority { offers: &offers }).err(),
        Some(AdmissionError::InvalidEntrypoint),
    );
}

#[test]
fn command_argument_bounds_are_image_policy_and_fail_closed() {
    let (artifact, world) = artifact_and_exact_world(PURE_COMPONENT);
    let identity = artifact.identity();
    let mut bad_policy = policy(identity, &world, &[]);
    bad_policy.entrypoint = "add";
    bad_policy.min_args = 2;
    bad_policy.max_args = 1;
    assert_eq!(
        admit(artifact, &bad_policy, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::InvalidArgumentLimits),
    );

    let (artifact, world) = artifact_and_exact_world(PURE_COMPONENT);
    let mut too_many = policy(artifact.identity(), &world, &[]);
    too_many.entrypoint = "add";
    too_many.max_args = 129;
    assert_eq!(
        admit(artifact, &too_many, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::InvalidArgumentLimits),
    );
}

#[test]
fn identity_and_diagnostics_are_redacted_and_stable() {
    let (artifact, world) = artifact_and_exact_world(CLOCK_COMPONENT);
    let identity = artifact.identity();
    let debug = format!("{identity:?}");
    assert_eq!(debug, "ComponentIdentity(<redacted>)");
    let raw_prefix = identity.as_bytes()[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(!debug.contains(&raw_prefix));

    let error = admit(
        artifact,
        &policy(identity, &world, &[]),
        &CallerAuthority { offers: &[] },
    )
    .err()
    .expect("missing image ceiling must reject admission");
    let display = error.to_string();
    assert_eq!(display, "component requirement has no image-policy ceiling");
    assert!(!display.contains("clock0"));
    assert!(!display.contains(CLOCK_INTERFACE));
    assert!(!display.contains(&raw_prefix));
    assert_eq!(error.code(), 12);
}
