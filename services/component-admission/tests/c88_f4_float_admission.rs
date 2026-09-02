#![cfg(feature = "c88-f4-acceptance")]

use vibeos_component_admission::{
    admit, admit_float_acceptance_candidate, AdmissionError, AdmissionPolicy,
    AdmittedFloatAcceptanceCandidate, ArtifactTrust, AuthorityOffer, CallerAuthority,
    CommandStreamMode, ComponentArtifact, FloatAcceptanceAdmissionPolicy, InstanceLimits,
    ProfileIdentity, FLOAT_ACCEPTANCE_ACTIVATION_LABEL,
};
use vibeos_component_format::{ProfileStage, PROFILE_1_LIMITS};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::{
    decode::current_component_validation_engine,
    world::{EntityShape, FunctionEffect, ValueShape, WorldContract},
};
use vibeos_core::cap::Rights;

const EXACT_WORLD: &str = "vibe:float-acceptance/lifecycle@1.0.0";

const WIT: &str = r#"
    package vibe:float-acceptance@1.0.0;
    world lifecycle {
        export run: func(mode: u32, left: f32, right: f64) -> f64;
    }
"#;

const COMPONENT: &str = r#"
    (component
      (core module $guest
        (memory (export "memory") 1 2)
        (func (export "run") (param i32 f32 f64) (result f64)
          local.get 1
          f64.promote_f32
          local.get 2
          f64.add))
      (core instance $guest-instance (instantiate $guest))
      (alias core export $guest-instance "run" (core func $run-core))
      (type $run-type
        (func
          (param "mode" u32)
          (param "left" f32)
          (param "right" f64)
          (result f64)))
      (func $run (type $run-type) (canon lift (core func $run-core)))
      (export "run" (func $run)))
"#;

fn candidate_world() -> WorldContract {
    WorldContract::parse_profile_2_sync_float_candidate(WIT, EXACT_WORLD).unwrap()
}

fn artifact_from(source: &str, profile: ProfileIdentity) -> ComponentArtifact {
    let bytes = wat::parse_str(source).unwrap();
    ComponentArtifact::copy_from(&bytes, profile).unwrap()
}

fn candidate_artifact() -> ComponentArtifact {
    artifact_from(COMPONENT, ProfileIdentity::PROFILE_2_SYNC_FLOAT)
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 2 * 65_536,
        total_fuel: 100_000,
        poll_quantum: 100,
        resources: 0,
    }
}

fn policy<'a>(
    identity: vibeos_component_admission::ComponentIdentity,
    world: &'a WorldContract,
) -> FloatAcceptanceAdmissionPolicy<'a> {
    FloatAcceptanceAdmissionPolicy {
        activation_label: FLOAT_ACCEPTANCE_ACTIVATION_LABEL,
        exact_world: world,
        trust: ArtifactTrust::ImagePinned(identity),
        limits: limits(),
    }
}

fn admit_fixture() -> AdmittedFloatAcceptanceCandidate {
    let artifact = candidate_artifact();
    let identity = artifact.identity();
    let world = candidate_world();
    admit_float_acceptance_candidate(
        artifact,
        &policy(identity, &world),
        &CallerAuthority { offers: &[] },
    )
    .unwrap()
}

#[test]
fn exact_float_candidate_is_sealed_inert_and_authority_free() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AdmittedFloatAcceptanceCandidate>();

    let artifact = candidate_artifact();
    let identity = artifact.identity();
    assert_eq!(artifact.inspect().err(), Some(AdmissionError::BadProfile));
    let world = candidate_world();
    let candidate = admit_float_acceptance_candidate(
        artifact,
        &policy(identity, &world),
        &CallerAuthority { offers: &[] },
    )
    .unwrap();

    assert_eq!(candidate.identity(), identity);
    assert_eq!(
        candidate.activation_label(),
        FLOAT_ACCEPTANCE_ACTIVATION_LABEL
    );
    assert_eq!(candidate.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert_eq!(candidate.profile().stage, ProfileStage::ValidationOnly);
    assert!(!candidate.profile().execution_enabled());
    assert_eq!(candidate.abi(), 5);
    assert_eq!(candidate.world(), EXACT_WORLD);
    assert_eq!(candidate.entrypoint(), "run");
    assert_eq!(candidate.limits(), limits());
    assert_eq!(candidate.limits().resources, 0);
    assert!(candidate.inspection().imports().is_empty());
    assert_eq!(candidate.inspection().exports().len(), 1);
    assert_eq!(candidate.inspection().embedded_modules().len(), 1);
    assert_eq!(candidate.inspection().embedded_modules()[0].imports, 0);

    let plan = candidate.validated_plan().unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    assert!(!plan.runtime_ready());
    assert!(!plan.native_async_runtime_ready());
    assert_eq!(plan.summary().resources, 0);
    assert_eq!(plan.summary().embedded_modules, 1);
    assert_eq!(plan.summary().core_instances, 1);
    assert_eq!(plan.summary().canonical_functions, 1);
    assert!(plan.imports().is_empty());
    assert_eq!(plan.host_imports().count(), 0);
    assert_eq!(plan.executable_exports().count(), 0);
    assert!(plan.native_async_execution_plan().is_none());
    assert_eq!(plan.exports().len(), 1);
    assert_eq!(plan.exports()[0].name, "run");
    let EntityShape::Function(function) = &plan.exports()[0].entity else {
        panic!("the sole candidate export must be a function");
    };
    assert_eq!(function.effect, FunctionEffect::Sync);
    assert_eq!(function.parameters.len(), 3);
    assert_eq!(function.parameters[0].name, "mode");
    assert_eq!(function.parameters[0].value, ValueShape::U32);
    assert_eq!(function.parameters[1].name, "left");
    assert_eq!(function.parameters[1].value, ValueShape::F32);
    assert_eq!(function.parameters[2].name, "right");
    assert_eq!(function.parameters[2].value, ValueShape::F64);
    assert_eq!(function.result, Some(ValueShape::F64));

    assert!(current_component_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
}

#[test]
fn ordinary_admission_still_rejects_profile_code_5() {
    let artifact = candidate_artifact();
    let identity = artifact.identity();
    let world = candidate_world();
    let ordinary = AdmissionPolicy {
        command_name: "float-candidate",
        entrypoint: "run",
        min_args: 0,
        max_args: 0,
        exact_world: &world,
        profile: ProfileIdentity::PROFILE_2_SYNC_FLOAT,
        trust: ArtifactTrust::ImagePinned(identity),
        limits: InstanceLimits {
            resources: 1,
            ..limits()
        },
        stdin: CommandStreamMode::Closed,
        stdout: CommandStreamMode::Closed,
        stderr: CommandStreamMode::Closed,
        interfaces: &[],
    };
    assert_eq!(
        admit(artifact, &ordinary, &CallerAuthority { offers: &[] }).err(),
        Some(AdmissionError::BadProfile)
    );
}

#[test]
fn exact_hash_world_profile_label_and_empty_authority_fail_closed() {
    let world = candidate_world();

    let artifact = candidate_artifact();
    let wrong_identity = ComponentArtifact::copy_from(
        b"not the pinned component",
        ProfileIdentity::PROFILE_2_SYNC_FLOAT,
    )
    .unwrap()
    .identity();
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &policy(wrong_identity, &world),
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::UntrustedArtifact)
    );

    let artifact = candidate_artifact();
    let mut wrong_world = candidate_world();
    let EntityShape::Function(function) = &mut wrong_world.exports[0].entity else {
        panic!("fixture export must be a function");
    };
    function.result = Some(ValueShape::F32);
    let candidate_policy = policy(artifact.identity(), &wrong_world);
    assert!(matches!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        ),
        Err(AdmissionError::World(_))
    ));

    let artifact = candidate_artifact();
    let mut invalid_world = candidate_world();
    invalid_world.identity.clear();
    let candidate_policy = policy(artifact.identity(), &invalid_world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let offer = [AuthorityOffer {
        label: "clock0",
        kind: HostResourceKind::Clock,
        grantable: Rights::READ,
    }];
    let artifact = candidate_artifact();
    let candidate_policy = policy(artifact.identity(), &world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &offer },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let artifact = candidate_artifact();
    let mut candidate_policy = policy(artifact.identity(), &world);
    candidate_policy.activation_label = "adjacent-float-candidate";
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let mut adjacent = ProfileIdentity::PROFILE_2_SYNC_FLOAT;
    adjacent.runtime_abi += 1;
    let artifact = artifact_from(COMPONENT, adjacent);
    let candidate_policy = policy(artifact.identity(), &world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::BadProfile)
    );
}

#[test]
fn exact_candidate_limits_are_preserved_and_every_adjacent_limit_is_rejected() {
    let candidate = admit_fixture();
    assert_eq!(candidate.limits(), limits());

    let maximum_memory = PROFILE_1_LIMITS.max_memory_pages as usize * 65_536;
    let bad_limits = [
        InstanceLimits {
            memory_bytes: 0,
            ..limits()
        },
        InstanceLimits {
            memory_bytes: maximum_memory + 1,
            ..limits()
        },
        InstanceLimits {
            total_fuel: 0,
            ..limits()
        },
        InstanceLimits {
            total_fuel: PROFILE_1_LIMITS.total_fuel + 1,
            ..limits()
        },
        InstanceLimits {
            poll_quantum: 0,
            ..limits()
        },
        InstanceLimits {
            poll_quantum: PROFILE_1_LIMITS.poll_quantum + 1,
            ..limits()
        },
        InstanceLimits {
            total_fuel: 10,
            poll_quantum: 11,
            ..limits()
        },
        InstanceLimits {
            resources: 1,
            ..limits()
        },
    ];
    let world = candidate_world();
    for limits in bad_limits {
        let artifact = candidate_artifact();
        let mut candidate_policy = policy(artifact.identity(), &world);
        candidate_policy.limits = limits;
        assert_eq!(
            admit_float_acceptance_candidate(
                artifact,
                &candidate_policy,
                &CallerAuthority { offers: &[] },
            )
            .err(),
            Some(AdmissionError::InvalidLimits),
            "adjacent limits unexpectedly admitted: {limits:?}"
        );
    }
}

#[test]
fn imported_or_nonminimal_component_topology_is_rejected() {
    const IMPORT_WIT: &str = r#"
        package vibe:float-import@1.0.0;
        world candidate {
            import source: func(value: f32) -> f64;
            export run: func(value: f32) -> f64;
        }
    "#;
    const IMPORT_COMPONENT: &str = r#"
        (component
          (type $source-type (func (param "value" f32) (result f64)))
          (import "source" (func $source (type $source-type)))
          (export "run" (func $source)))
    "#;
    let import_world = WorldContract::parse_profile_2_sync_float_candidate(
        IMPORT_WIT,
        "vibe:float-import/candidate@1.0.0",
    )
    .unwrap();
    let artifact = artifact_from(IMPORT_COMPONENT, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let candidate_policy = policy(artifact.identity(), &import_world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let extra_module = COMPONENT.replacen(
        "(core module $guest",
        "(core module $spare)\n      (core module $guest",
        1,
    );
    assert_ne!(extra_module, COMPONENT);
    let artifact = artifact_from(&extra_module, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let world = candidate_world();
    let candidate_policy = policy(artifact.identity(), &world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let extra_export = COMPONENT.replacen(
        "(export \"run\" (func $run)))",
        "(export \"run\" (func $run))\n      (export \"run-adjacent\" (func $run)))",
        1,
    );
    assert_ne!(extra_export, COMPONENT);
    let extra_world = WorldContract::parse_profile_2_sync_float_candidate(
        r#"
            package vibe:float-extra@1.0.0;
            world candidate {
                export run: func(mode: u32, left: f32, right: f64) -> f64;
                export run-adjacent: func(mode: u32, left: f32, right: f64) -> f64;
            }
        "#,
        "vibe:float-extra/candidate@1.0.0",
    )
    .unwrap();
    let artifact = artifact_from(&extra_export, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let candidate_policy = policy(artifact.identity(), &extra_world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );

    let adjacent_signature =
        COMPONENT.replacen("(param \"mode\" u32)", "(param \"selector\" u32)", 1);
    assert_ne!(adjacent_signature, COMPONENT);
    let adjacent_world = WorldContract::parse_profile_2_sync_float_candidate(
        r#"
            package vibe:float-adjacent@1.0.0;
            world candidate {
                export run: func(selector: u32, left: f32, right: f64) -> f64;
            }
        "#,
        "vibe:float-adjacent/candidate@1.0.0",
    )
    .unwrap();
    let artifact = artifact_from(&adjacent_signature, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let candidate_policy = policy(artifact.identity(), &adjacent_world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );
}

#[test]
fn component_run_must_lift_the_exact_core_run_binding() {
    const MISBOUND: &str = r#"
        (component
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
          (export "run" (func $run)))
    "#;
    let artifact = artifact_from(MISBOUND, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
    let world = candidate_world();
    let candidate_policy = policy(artifact.identity(), &world);
    assert_eq!(
        admit_float_acceptance_candidate(
            artifact,
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .err(),
        Some(AdmissionError::InvalidPolicy)
    );
}
