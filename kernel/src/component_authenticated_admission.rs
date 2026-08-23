//! C7.3 target gate for exact development pins and detached operator evidence.
//!
//! The acceptance task performs only canonical decoding, authentication,
//! semantic admission, and inert command projection. It never receives a raw
//! durable identity, performs a lookup, installs a command, or calls guest
//! code. A successful detached signature is consumed through the production
//! move-only wrapper before the command can be observed as unavailable.

use vibeos_component_admission::{
    authenticate_component_artifact, AdmissionPolicy, ArtifactAuthenticationError, ArtifactTrust,
    ComponentArtifact, OperatorArtifactAdmissionPolicy,
};
use vibeos_component_loader::{
    project_authenticated_component_command, project_development_component_command,
    ComponentLoadError, DevelopmentComponentLoadPolicy, VolatileComponentCommand,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_image_policy::{
    C73ArtifactMutationKind, C73AuthenticatedAdmissionPin, C73OperatorArtifactPin,
    C73OperatorPolicyPin, C73RejectedEvidenceKind, C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE,
};
use vibeos_vsh::{ComponentCommandRunner, ComponentTerminal};

fn with_operator_policy(
    pin: C73OperatorPolicyPin,
    action: impl FnOnce(&OperatorArtifactAdmissionPolicy<'_>) -> bool,
) -> bool {
    let Ok(world) = WorldContract::parse(pin.exact_wit_source(), pin.exact_world()) else {
        return false;
    };
    let Ok(signers) = pin.signers() else {
        return false;
    };
    let Ok(policy) = OperatorArtifactAdmissionPolicy::new(
        match pin.operator_role() {
            Ok(role) => role,
            Err(_) => return false,
        },
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
    ) else {
        return false;
    };
    action(&policy)
}

fn command_is_inert(command: &VolatileComponentCommand) -> bool {
    !command.runtime_ready()
        && command.guest_calls() == 0
        && ComponentCommandRunner::preflight(command, command.manifest())
            == Err(ComponentTerminal::Unavailable)
}

fn development_accepts(root: C73AuthenticatedAdmissionPin) -> bool {
    let pin = root.development();
    let policy_pin = root.policy_p1();
    let Ok(artifact) = pin.artifact() else {
        return false;
    };
    let Ok(component) =
        ComponentArtifact::copy_from(artifact.component_bytes(), artifact.profile())
    else {
        return false;
    };
    let Ok(world) = WorldContract::parse(policy_pin.exact_wit_source(), policy_pin.exact_world())
    else {
        return false;
    };
    let admission = AdmissionPolicy {
        command_name: policy_pin.command_name(),
        entrypoint: policy_pin.entrypoint(),
        min_args: policy_pin.min_args(),
        max_args: policy_pin.max_args(),
        exact_world: &world,
        profile: policy_pin.profile(),
        trust: ArtifactTrust::ImagePinned(component.identity()),
        limits: policy_pin.limits(),
        stdin: policy_pin.stdin(),
        stdout: policy_pin.stdout(),
        stderr: policy_pin.stderr(),
        interfaces: &[],
    };
    let Ok(signer_policy) = pin.signer_policy() else {
        return false;
    };
    let load = DevelopmentComponentLoadPolicy::new(
        pin.canonical_artifact_bytes(),
        policy_pin.exact_wit_source(),
        *signer_policy.policy_digest().as_bytes(),
        &admission,
    );
    let Ok(command) = project_development_component_command(pin.canonical_artifact_bytes(), &load)
    else {
        return false;
    };
    command_is_inert(&command) && !pin.runtime_ready() && pin.guest_calls() == 0
}

fn operator_accepts(
    pin: C73OperatorArtifactPin,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> bool {
    let Ok(artifact) = pin.artifact() else {
        return false;
    };
    let Ok(evidence) = pin.authentication_evidence() else {
        return false;
    };
    let Ok(authenticated) = authenticate_component_artifact(artifact, &evidence, policy) else {
        return false;
    };
    if authenticated.runtime_ready() || authenticated.receipt().runtime_ready() {
        return false;
    }
    let Ok(command) = project_authenticated_component_command(authenticated, policy) else {
        return false;
    };
    command_is_inert(&command) && !pin.runtime_ready() && pin.guest_calls() == 0
}

fn p1_acceptance_and_rejections(root: C73AuthenticatedAdmissionPin) -> bool {
    with_operator_policy(root.policy_p1(), |policy| {
        let operator_p1 = root.operator_p1();
        if !operator_p1
            .iter()
            .copied()
            .all(|pin| operator_accepts(pin, policy))
        {
            return false;
        }

        let baseline = operator_p1[0];
        for rejected in root.rejected_evidence() {
            let Ok(artifact) = baseline.artifact() else {
                return false;
            };
            let Ok(evidence) = rejected.authentication_evidence() else {
                return false;
            };
            let expected = match rejected.kind() {
                C73RejectedEvidenceKind::WrongSignature
                | C73RejectedEvidenceKind::ContentHashOnly => {
                    ArtifactAuthenticationError::InvalidSignature
                }
                C73RejectedEvidenceKind::UnknownSigner => {
                    ArtifactAuthenticationError::UnknownSigner
                }
                C73RejectedEvidenceKind::RevokedSigner => {
                    ArtifactAuthenticationError::RevokedSigner
                }
            };
            if authenticate_component_artifact(artifact, &evidence, policy).err() != Some(expected)
                || rejected.runtime_ready()
                || rejected.guest_calls() != 0
            {
                return false;
            }
        }

        let Ok(baseline_evidence) = baseline.authentication_evidence() else {
            return false;
        };
        if authenticate_component_artifact(
            match operator_p1[1].artifact() {
                Ok(artifact) => artifact,
                Err(_) => return false,
            },
            &baseline_evidence,
            policy,
        )
        .err()
            != Some(ArtifactAuthenticationError::InvalidSignature)
        {
            return false;
        }

        let mut mutation_rejections = [0_u8; 6];
        for mutation in root.mutations() {
            let index = match mutation.kind() {
                C73ArtifactMutationKind::ArtifactManifest => 0,
                C73ArtifactMutationKind::CoreModuleManifest => 1,
                C73ArtifactMutationKind::ExactWitSource => 2,
                C73ArtifactMutationKind::AdapterManifest => 3,
                C73ArtifactMutationKind::InstanceLimits => 4,
                C73ArtifactMutationKind::ProfileIdentity => 5,
            };
            let stale_rejected = match mutation.artifact() {
                Ok(artifact) => {
                    authenticate_component_artifact(artifact, &baseline_evidence, policy).is_err()
                }
                Err(_) => false,
            };
            if !stale_rejected {
                return false;
            }
            mutation_rejections[index] += 1;

            let Ok(artifact) = mutation.artifact() else {
                return false;
            };
            let Ok(evidence) = mutation.authentication_evidence() else {
                return false;
            };
            let fresh = authenticate_component_artifact(artifact, &evidence, policy);
            let fresh_rejected = match mutation.kind() {
                C73ArtifactMutationKind::ArtifactManifest => fresh.is_ok_and(|authenticated| {
                    project_authenticated_component_command(authenticated, policy).err()
                        == Some(ComponentLoadError::InterfaceManifest)
                }),
                C73ArtifactMutationKind::CoreModuleManifest => fresh.is_ok_and(|authenticated| {
                    project_authenticated_component_command(authenticated, policy).err()
                        == Some(ComponentLoadError::CoreManifest)
                }),
                C73ArtifactMutationKind::AdapterManifest => fresh.is_ok_and(|authenticated| {
                    project_authenticated_component_command(authenticated, policy).err()
                        == Some(ComponentLoadError::UnsupportedAdapterEvidence)
                }),
                C73ArtifactMutationKind::ExactWitSource => {
                    fresh.err() == Some(ArtifactAuthenticationError::ArtifactConfiguration)
                }
                C73ArtifactMutationKind::InstanceLimits => {
                    fresh.err() == Some(ArtifactAuthenticationError::InstanceLimitsMismatch)
                }
                C73ArtifactMutationKind::ProfileIdentity => {
                    fresh.err() == Some(ArtifactAuthenticationError::ProfileMismatch)
                }
            };
            if !fresh_rejected || mutation.runtime_ready() || mutation.guest_calls() != 0 {
                return false;
            }
            mutation_rejections[index] += 1;
        }
        mutation_rejections == [2; 6]
    })
}

fn p2_acceptance_and_rotation_rejections(root: C73AuthenticatedAdmissionPin) -> bool {
    with_operator_policy(root.policy_p2(), |policy| {
        if !operator_accepts(root.operator_p2(), policy) {
            return false;
        }
        let old = root.operator_p1()[0];
        let Ok(old_evidence) = old.authentication_evidence() else {
            return false;
        };
        if authenticate_component_artifact(
            match old.artifact() {
                Ok(artifact) => artifact,
                Err(_) => return false,
            },
            &old_evidence,
            policy,
        )
        .err()
            != Some(ArtifactAuthenticationError::PolicyDigestMismatch)
        {
            return false;
        }
        authenticate_component_artifact(
            match root.operator_p2().artifact() {
                Ok(artifact) => artifact,
                Err(_) => return false,
            },
            &old_evidence,
            policy,
        )
        .err()
            == Some(ArtifactAuthenticationError::InvalidSignature)
    })
}

/// Four-hart proof that both C7.3 trust roots remain exact, separate, and
/// execution-disabled after successful admission.
pub(crate) fn run_qemu_acceptance() -> bool {
    if crate::online_hart_count() != 4 || crate::online_hart_mask() & 0x0f != 0x0f {
        return false;
    }
    let root = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    !root.runtime_ready()
        && root.guest_calls() == 0
        && development_accepts(root)
        && p1_acceptance_and_rejections(root)
        && p2_acceptance_and_rotation_rejections(root)
}
