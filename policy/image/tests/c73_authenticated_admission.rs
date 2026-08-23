#![cfg(feature = "c73-authenticated-admission-qemu-acceptance")]

use vibeos_component_admission::{
    admit, admit_authenticated, authenticate_component_artifact, AdmissionPolicy,
    ArtifactAuthenticationError, ArtifactTrust, AuthenticatedAdmissionError, CallerAuthority,
    OperatorArtifactAdmissionPolicy,
};
use vibeos_component_format::{
    ComponentArtifactSignerPolicyKind, ComponentArtifactV1, ProfileIdentity,
};
use vibeos_component_loader::{
    project_authenticated_component_command, project_development_component_command,
    DevelopmentComponentLoadPolicy,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_image_policy::{
    C73ArtifactMutationKind, C73OperatorPolicyPin, C73RejectedEvidenceKind,
    C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE,
};

fn with_policy<R>(
    pin: C73OperatorPolicyPin,
    action: impl FnOnce(&OperatorArtifactAdmissionPolicy<'_>) -> R,
) -> R {
    let world = WorldContract::parse(pin.exact_wit_source(), pin.exact_world())
        .expect("C7.3 image WIT must independently parse");
    let signers = pin
        .signers()
        .expect("C7.3 image keys must form a canonical production signer table");
    let policy = OperatorArtifactAdmissionPolicy::new(
        pin.operator_role().expect("C7.3 operator role is non-zero"),
        pin.generation(),
        pin.profile(),
        pin.command_name(),
        pin.entrypoint(),
        pin.min_args(),
        pin.max_args(),
        pin.exact_wit_source(),
        &world,
        pin.limits(),
        pin.stdin(),
        pin.stdout(),
        pin.stderr(),
        &[],
        &signers,
    )
    .expect("C7.3 typed image policy must pass production construction");
    action(&policy)
}

#[test]
fn development_exact_byte_pin_and_two_operator_artifacts_are_distinct() {
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    assert!(!root.runtime_ready());
    assert_eq!(root.guest_calls(), 0);

    let development = root.development();
    assert!(!development.canonical_artifact_bytes().is_empty());
    let artifact = development.artifact().expect("development pin decodes");
    assert_eq!(
        ComponentArtifactV1::decode(development.canonical_artifact_bytes()).unwrap(),
        artifact
    );
    let independent_development_policy = development.signer_policy().unwrap();
    assert_eq!(
        artifact.signer_policy().kind(),
        ComponentArtifactSignerPolicyKind::DevelopmentImagePin
    );
    assert_eq!(
        independent_development_policy.kind(),
        ComponentArtifactSignerPolicyKind::DevelopmentImagePin
    );
    assert_eq!(
        independent_development_policy.policy_digest(),
        artifact.signer_policy().policy_digest()
    );
    assert_eq!(
        development.signer_policy_digest().unwrap(),
        artifact.signer_policy().policy_digest()
    );
    assert!(!artifact.runtime_ready());
    assert!(!development.runtime_ready());
    assert_eq!(development.guest_calls(), 0);

    let pin = root.policy_p1();
    let world = WorldContract::parse(pin.exact_wit_source(), pin.exact_world()).unwrap();
    let component = vibeos_component_admission::ComponentArtifact::copy_from(
        artifact.component_bytes(),
        artifact.profile(),
    )
    .unwrap();
    let policy = AdmissionPolicy {
        command_name: pin.command_name(),
        entrypoint: pin.entrypoint(),
        min_args: pin.min_args(),
        max_args: pin.max_args(),
        exact_world: &world,
        profile: pin.profile(),
        trust: ArtifactTrust::ImagePinned(component.identity()),
        limits: pin.limits(),
        stdin: pin.stdin(),
        stdout: pin.stdout(),
        stderr: pin.stderr(),
        interfaces: &[],
    };
    let development_load_policy = DevelopmentComponentLoadPolicy::new(
        development.canonical_artifact_bytes(),
        pin.exact_wit_source(),
        *development.signer_policy_digest().unwrap().as_bytes(),
        &policy,
    );
    let volatile = project_development_component_command(
        development.canonical_artifact_bytes(),
        &development_load_policy,
    )
    .expect("production loader projects the exact development image pin");
    assert!(!volatile.runtime_ready());
    assert_eq!(volatile.guest_calls(), 0);
    let admitted = admit(component, &policy, &CallerAuthority { offers: &[] })
        .expect("exact image-provenance development artifact admits");
    assert_eq!(admitted.command_manifest().name(), pin.command_name());
    assert!(admitted.grants().is_empty());

    let [operator_a, operator_b] = root.operator_p1();
    let artifact_a = operator_a.artifact().unwrap();
    let artifact_b = operator_b.artifact().unwrap();
    assert_eq!(
        artifact_a.signer_policy().kind(),
        ComponentArtifactSignerPolicyKind::OperatorRequired
    );
    assert_eq!(
        artifact_b.signer_policy().kind(),
        ComponentArtifactSignerPolicyKind::OperatorRequired
    );
    assert_ne!(artifact_a.component_bytes(), artifact_b.component_bytes());
    assert_ne!(
        artifact_a.artifact_commitment().unwrap(),
        artifact_b.artifact_commitment().unwrap()
    );
    assert!(!operator_a.runtime_ready());
    assert!(!operator_b.runtime_ready());
    assert_eq!(operator_a.guest_calls() + operator_b.guest_calls(), 0);
}

#[test]
fn production_policy_commitment_authenticates_p1_and_rotated_p2_without_replay() {
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    with_policy(root.policy_p1(), |policy_p1| {
        let commitment_p1 = policy_p1.commitment().unwrap();
        for pin in root.operator_p1() {
            let artifact = pin.artifact().unwrap();
            assert_eq!(
                artifact.signer_policy().policy_digest().as_bytes(),
                commitment_p1.as_bytes()
            );
            let evidence = pin.authentication_evidence().unwrap();
            assert!(!evidence.runtime_ready());
            let authenticated = authenticate_component_artifact(artifact, &evidence, policy_p1)
                .expect("active P1 operator signature authenticates");
            assert!(!authenticated.runtime_ready());
            assert!(!authenticated.receipt().runtime_ready());
            assert_eq!(authenticated.receipt().generation(), 1);
            let volatile = project_authenticated_component_command(authenticated, policy_p1)
                .expect("production loader projects authenticated P1 artifact");
            assert!(!volatile.runtime_ready());
            assert_eq!(volatile.guest_calls(), 0);
        }

        let [operator_a, operator_b] = root.operator_p1();
        let replay = operator_a.authentication_evidence().unwrap();
        assert_eq!(
            authenticate_component_artifact(operator_b.artifact().unwrap(), &replay, policy_p1)
                .err(),
            Some(ArtifactAuthenticationError::InvalidSignature)
        );
    });

    with_policy(root.policy_p2(), |policy_p2| {
        let rotated = root.operator_p2();
        let artifact = rotated.artifact().unwrap();
        assert_eq!(
            artifact.signer_policy().policy_digest().as_bytes(),
            policy_p2.commitment().unwrap().as_bytes()
        );
        let authenticated = authenticate_component_artifact(
            artifact,
            &rotated.authentication_evidence().unwrap(),
            policy_p2,
        )
        .expect("active P2 operator signature authenticates");
        assert_eq!(authenticated.receipt().generation(), 2);
        assert!(!authenticated.runtime_ready());
        let volatile = project_authenticated_component_command(authenticated, policy_p2)
            .expect("production loader projects authenticated P2 artifact");
        assert!(!volatile.runtime_ready());
        assert_eq!(volatile.guest_calls(), 0);

        let old = root.operator_p1()[0];
        assert_eq!(
            authenticate_component_artifact(
                old.artifact().unwrap(),
                &old.authentication_evidence().unwrap(),
                policy_p2,
            )
            .err(),
            Some(ArtifactAuthenticationError::PolicyDigestMismatch)
        );
        assert_eq!(
            authenticate_component_artifact(
                rotated.artifact().unwrap(),
                &old.authentication_evidence().unwrap(),
                policy_p2,
            )
            .err(),
            Some(ArtifactAuthenticationError::InvalidSignature)
        );
    });

    with_policy(root.policy_p1(), |p1| {
        with_policy(root.policy_p2(), |p2| {
            assert_ne!(p1.commitment().unwrap(), p2.commitment().unwrap());
            assert_eq!(p1.role(), p2.role());
            assert_eq!(p1.signers(), p2.signers());
            assert_eq!((p1.generation(), p2.generation()), (1, 2));
        });
    });
}

#[test]
fn wrong_unknown_revoked_and_hash_only_evidence_fail_closed() {
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    let artifact_pin = root.operator_p1()[0];
    with_policy(root.policy_p1(), |policy| {
        for (negative, expected) in root.rejected_evidence().into_iter().zip([
            ArtifactAuthenticationError::InvalidSignature,
            ArtifactAuthenticationError::UnknownSigner,
            ArtifactAuthenticationError::RevokedSigner,
            ArtifactAuthenticationError::InvalidSignature,
        ]) {
            assert!(!negative.runtime_ready());
            assert_eq!(negative.guest_calls(), 0);
            assert_eq!(
                authenticate_component_artifact(
                    artifact_pin.artifact().unwrap(),
                    &negative.authentication_evidence().unwrap(),
                    policy,
                )
                .err(),
                Some(expected),
                "negative signer case {:?} changed",
                negative.kind()
            );
        }
    });
    assert_eq!(
        root.rejected_evidence().map(|pin| pin.kind()),
        [
            C73RejectedEvidenceKind::WrongSignature,
            C73RejectedEvidenceKind::UnknownSigner,
            C73RejectedEvidenceKind::RevokedSigner,
            C73RejectedEvidenceKind::ContentHashOnly,
        ]
    );
}

#[test]
fn every_signed_mutation_is_rejected_at_signature_or_fresh_semantic_gate() {
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    let baseline_evidence = root.operator_p1()[0].authentication_evidence().unwrap();
    with_policy(root.policy_p1(), |policy| {
        for mutation in root.mutations() {
            assert!(!mutation.runtime_ready());
            assert_eq!(mutation.guest_calls(), 0);

            assert!(
                authenticate_component_artifact(
                    mutation.artifact().unwrap(),
                    &baseline_evidence,
                    policy,
                )
                .is_err(),
                "stale baseline signature accepted {:?}",
                mutation.kind()
            );

            let fresh = authenticate_component_artifact(
                mutation.artifact().unwrap(),
                &mutation.authentication_evidence().unwrap(),
                policy,
            );
            match mutation.kind() {
                C73ArtifactMutationKind::ArtifactManifest
                | C73ArtifactMutationKind::CoreModuleManifest
                | C73ArtifactMutationKind::AdapterManifest => {
                    let authenticated = fresh.expect(
                        "fresh signature should pass before independent semantic revalidation",
                    );
                    assert!(!authenticated.runtime_ready());
                    assert_eq!(
                        admit_authenticated(
                            authenticated,
                            policy,
                            &CallerAuthority { offers: &[] },
                        )
                        .err(),
                        Some(AuthenticatedAdmissionError::Authentication(
                            ArtifactAuthenticationError::ArtifactConfiguration,
                        )),
                        "fresh semantic mutation {:?} escaped revalidation",
                        mutation.kind()
                    );
                }
                C73ArtifactMutationKind::ExactWitSource => assert_eq!(
                    fresh.err(),
                    Some(ArtifactAuthenticationError::ArtifactConfiguration)
                ),
                C73ArtifactMutationKind::InstanceLimits => assert_eq!(
                    fresh.err(),
                    Some(ArtifactAuthenticationError::InstanceLimitsMismatch)
                ),
                C73ArtifactMutationKind::ProfileIdentity => assert_eq!(
                    fresh.err(),
                    Some(ArtifactAuthenticationError::ProfileMismatch)
                ),
            }
        }
    });
}

#[test]
fn typed_image_root_is_private_redacted_and_inert() {
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    let debug = format!("{root:?}");
    let development_debug = format!("{:?}", root.development());
    assert_eq!(root.policy_p1().profile(), ProfileIdentity::PROFILE_1_SYNC);
    assert_eq!(
        root.policy_p1().exact_wit_source(),
        root.policy_p2().exact_wit_source()
    );
    assert!(root.policy_p1().exact_wit_source().contains("world filter"));
    assert!(!root.policy_p1().runtime_ready());
    assert_eq!(root.policy_p1().guest_calls(), 0);
    assert!(debug.contains("<redacted"));
    assert!(development_debug.contains("artifact: \"<redacted>\""));
    assert!(!development_debug.contains("VIBECMP"));
    for artifact in root.operator_p1().into_iter().chain([root.operator_p2()]) {
        let artifact_debug = format!("{artifact:?}");
        assert!(artifact_debug.contains("artifact: \"<redacted>\""));
        assert!(artifact_debug.contains("authentication_evidence: \"<redacted>\""));
        assert!(!artifact_debug.contains("VIBECMP"));
        assert!(!artifact_debug.contains("VIBESIG"));
    }
    for rejected in root.rejected_evidence() {
        let rejected_debug = format!("{rejected:?}");
        assert!(rejected_debug.contains("authentication_evidence: \"<redacted>\""));
        assert!(!rejected_debug.contains("VIBESIG"));
    }
    for mutation in root.mutations() {
        let mutation_debug = format!("{mutation:?}");
        assert!(mutation_debug.contains("artifact: \"<redacted>\""));
        assert!(mutation_debug.contains("authentication_evidence: \"<redacted>\""));
        assert!(!mutation_debug.contains("VIBECMP"));
        assert!(!mutation_debug.contains("VIBESIG"));
    }
    for forbidden in [
        "VIBECMP",
        "VIBESIG",
        "public_key",
        "signature",
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "Cap {",
        "slot=",
        "0x",
        "package vibe:bytes",
    ] {
        assert!(!debug.contains(forbidden), "debug leaked `{forbidden}`");
    }
    for policy in [root.policy_p1(), root.policy_p2()] {
        let policy_debug = format!("{policy:?}");
        assert!(policy_debug.contains("operator_role: \"<redacted>\""));
        assert!(policy_debug.contains("signers: \"<redacted>\""));
        assert!(policy_debug.contains("exact_wit_source: \"<redacted>\""));
        assert!(policy_debug.contains("runtime_ready: false"));
        assert!(policy_debug.contains("guest_calls: 0"));
    }
}
