use vibeos_component_admission::{
    admit, AdmissionError, AdmissionPolicy, ArtifactTrust, AuthorityOffer, CallerAuthority,
    CommandStreamMode, ComponentArtifact, InstanceLimits, InterfaceCeiling, ProfileIdentity,
    STREAM_FILTER_WORLD,
};
use vibeos_component_host::{
    HostManifestError, HostResourceKind, CLOCK_INTERFACE, STREAM_INTERFACE,
};
use vibeos_component_runtime::{decode::inspect_component, world::WorldContract};
use vibeos_core::cap::Rights;

const CLOCK_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-clock.component.wat");
const FOREIGN_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-pair.component.wat");
const PURE_COMPONENT: &str =
    include_str!("../../../component-format/tests/corpus/component/typed.component.wat");
const STREAM_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-stream.component.wat");
const STREAM_WIT: &str = include_str!("../../../component-format/tests/corpus/wit/stream.wit");

fn artifact_and_exact_world(source: &str) -> (ComponentArtifact, WorldContract) {
    let bytes = wat::parse_str(source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract {
        identity: String::from("vibe:test/admitted@1.0.0"),
        imports: plan.imports,
        exports: plan.exports,
    };
    (
        ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1).unwrap(),
        world,
    )
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

fn stream_artifact_and_world() -> (ComponentArtifact, WorldContract) {
    let bytes = wat::parse_str(STREAM_COMPONENT).unwrap();
    let world = WorldContract::parse(STREAM_WIT, STREAM_FILTER_WORLD).unwrap();
    (
        ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1).unwrap(),
        world,
    )
}

fn stream_policy<'a>(
    identity: vibeos_component_admission::ComponentIdentity,
    world: &'a WorldContract,
    interfaces: &'a [InterfaceCeiling<'a>],
) -> AdmissionPolicy<'a> {
    AdmissionPolicy {
        command_name: "stream-filter",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: world,
        profile: ProfileIdentity::PROFILE_1,
        trust: ArtifactTrust::ImagePinned(identity),
        limits: InstanceLimits {
            memory_bytes: 1024 * 1024,
            total_fuel: 500_000,
            poll_quantum: 100,
            resources: 4,
        },
        stdin: CommandStreamMode::Required,
        stdout: CommandStreamMode::Required,
        stderr: CommandStreamMode::Optional,
        interfaces,
    }
}

#[test]
fn exact_stream_transport_is_not_ambient_authority() {
    let (artifact, world) = stream_artifact_and_world();
    let identity = artifact.identity();
    let admitted = admit(
        artifact,
        &stream_policy(identity, &world, &[]),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();
    let manifest = admitted.command_manifest();
    assert_eq!(manifest.world(), STREAM_FILTER_WORLD);
    assert_eq!(manifest.stdin(), CommandStreamMode::Required);
    assert_eq!(manifest.stdout(), CommandStreamMode::Required);
    assert_eq!(manifest.stderr(), CommandStreamMode::Optional);
    assert!(manifest.uses_stream_transport());
    assert!(manifest.requirements().is_empty());
    assert!(admitted.grants().is_empty());
    assert!(admitted.validated_plan().is_ok());

    let (artifact, world) = stream_artifact_and_world();
    let mut closed_stderr = stream_policy(artifact.identity(), &world, &[]);
    closed_stderr.stderr = CommandStreamMode::Closed;
    let admitted = admit(artifact, &closed_stderr, &CallerAuthority { offers: &[] }).unwrap();
    assert_eq!(
        admitted.command_manifest().stderr(),
        CommandStreamMode::Closed
    );
    assert!(admitted.validated_plan().is_ok());
}

#[test]
fn stream_transport_modes_and_authority_tables_fail_closed() {
    for (stdin, stdout) in [
        (CommandStreamMode::Optional, CommandStreamMode::Required),
        (CommandStreamMode::Closed, CommandStreamMode::Required),
        (CommandStreamMode::Required, CommandStreamMode::Optional),
        (CommandStreamMode::Required, CommandStreamMode::Closed),
    ] {
        let (artifact, world) = stream_artifact_and_world();
        let mut policy = stream_policy(artifact.identity(), &world, &[]);
        policy.stdin = stdin;
        policy.stdout = stdout;
        assert_eq!(
            admit(artifact, &policy, &CallerAuthority { offers: &[] }).err(),
            Some(AdmissionError::InvalidPolicy),
            "stdin={stdin:?} stdout={stdout:?}"
        );
    }

    for (min_args, max_args, stderr) in [
        (0, 1, CommandStreamMode::Optional),
        (1, 1, CommandStreamMode::Optional),
        (0, 0, CommandStreamMode::Required),
    ] {
        let (artifact, world) = stream_artifact_and_world();
        let mut policy = stream_policy(artifact.identity(), &world, &[]);
        policy.min_args = min_args;
        policy.max_args = max_args;
        policy.stderr = stderr;
        assert_eq!(
            admit(artifact, &policy, &CallerAuthority { offers: &[] }).err(),
            Some(AdmissionError::InvalidPolicy),
            "min_args={min_args} max_args={max_args} stderr={stderr:?}"
        );
    }

    let reader_ceiling = [InterfaceCeiling {
        label: "stdin",
        interface: STREAM_INTERFACE,
        kind: HostResourceKind::ByteStreamReader,
        rights: Rights::RECV,
    }];
    let (artifact, world) = stream_artifact_and_world();
    let policy = stream_policy(artifact.identity(), &world, &reader_ceiling);
    assert_eq!(
        admit(artifact, &policy, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let writer_offer = [AuthorityOffer {
        label: "stdout",
        kind: HostResourceKind::ByteStreamWriter,
        grantable: Rights::SEND,
    }];
    let (artifact, world) = stream_artifact_and_world();
    let policy = stream_policy(artifact.identity(), &world, &[]);
    assert_eq!(
        admit(
            artifact,
            &policy,
            &CallerAuthority {
                offers: &writer_offer,
            },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );
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
    assert_eq!(manifest.profile(), ProfileIdentity::PROFILE_1);
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
fn artifact_revision_descriptor_mismatch_wins_before_trust_and_decode() {
    let (_, world) = artifact_and_exact_world(PURE_COMPONENT);
    let mut foreign = ProfileIdentity::PROFILE_1;
    foreign.component_revision = "component-model-untrusted-adjacent";
    let artifact = ComponentArtifact::copy_from(b"not even a component", foreign).unwrap();
    let identity = artifact.identity();
    assert_eq!(
        admit(
            artifact,
            &policy(identity, &world, &[]),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );

    let mut mismatches = [ProfileIdentity::PROFILE_1; 6];
    mismatches[0].component_revision = "component-model-adjacent";
    mismatches[1].canonical_abi_revision = "canonical-abi-previous-rc";
    mismatches[2].wasm_tools_revision = "wasm-tools-v1.254.0";
    mismatches[3].wasi_revision = "wasi-v0.3.0-rc-2026-01-06";
    mismatches[4].canonical_features ^= 1 << 16;
    mismatches[5].runtime_abi = mismatches[5].runtime_abi.saturating_add(1);
    for bad_profile in mismatches {
        let (artifact, world) = artifact_and_exact_world(PURE_COMPONENT);
        let identity = artifact.identity();
        let mut bad_policy = policy(identity, &world, &[]);
        bad_policy.entrypoint = "add";
        bad_policy.profile = bad_profile;
        assert_eq!(
            admit(artifact, &bad_policy, &CallerAuthority { offers: &[] },).err(),
            Some(AdmissionError::BadProfile),
            "{bad_profile:?}"
        );
    }
}

#[test]
fn selected_async_profile_is_inspectable_but_cannot_be_admitted_before_c52() {
    assert_eq!(AdmissionError::RuntimeUnavailable.code(), 18);
    let bytes = wat::parse_str(
        r#"(component
              (type $t (func async))
              (import "source" (func $source (type $t)))
              (export "run" (func $source)))"#,
    )
    .unwrap();
    let world = WorldContract::parse(
        r#"
            package test:async-admission@1.0.0;
            world api {
                import source: async func();
                export run: async func();
            }
        "#,
        "test:async-admission/api@1.0.0",
    )
    .unwrap();
    let artifact = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    let identity = artifact.identity();
    let inspection = artifact.inspect().unwrap();
    assert_eq!(inspection.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert!(!inspection.plan().runtime_ready());
    drop(inspection);

    let mut async_policy = policy(identity, &world, &[]);
    async_policy.profile = ProfileIdentity::PROFILE_1_ASYNC;
    assert_eq!(
        admit(artifact, &async_policy, &CallerAuthority { offers: &[] },).err(),
        Some(AdmissionError::RuntimeUnavailable)
    );

    let mut adjacent = ProfileIdentity::PROFILE_1_ASYNC;
    adjacent.canonical_abi_revision = "canonical-abi-adjacent-rc";
    let artifact = ComponentArtifact::copy_from(&bytes, adjacent).unwrap();
    assert_eq!(artifact.inspect().err(), Some(AdmissionError::BadProfile));
}

#[test]
fn component_controlled_revision_custom_section_never_grants_profile_identity() {
    let mut bytes = wat::parse_str(
        r#"(component
              (type $t (func async))
              (import "source" (func $source (type $t)))
              (export "run" (func $source)))"#,
    )
    .unwrap();
    let name = b"vibe:claimed-profile";
    let claim = vibeos_component_format::ASYNC_CANONICAL_ABI_REVISION.as_bytes();
    let mut custom = Vec::new();
    push_leb(&mut custom, name.len() as u32);
    custom.extend_from_slice(name);
    custom.extend_from_slice(claim);
    bytes.push(0);
    push_leb(&mut bytes, custom.len() as u32);
    bytes.extend_from_slice(&custom);

    let artifact = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1_SYNC).unwrap();
    assert!(matches!(
        artifact.inspect(),
        Err(AdmissionError::Decode(
            vibeos_component_runtime::decode::DecodeError::Unsupported
        ))
    ));
}

fn push_leb(target: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        target.push(byte);
        if value == 0 {
            return;
        }
    }
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
    let wrong_identity =
        ComponentArtifact::copy_from(b"different exact bytes", ProfileIdentity::PROFILE_1)
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
        ComponentArtifact::copy_from(&oversized, ProfileIdentity::PROFILE_1).err(),
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
