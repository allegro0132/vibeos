//! C7.5 target gate for fresh validation of one durable Component on every boot.
//!
//! Durable state is classified before this module may consult an image
//! installation candidate. A vacant boot prevalidates and appends the exact
//! operator fixture; an existing boot supplies no candidate bytes at all.
//! Both paths converge on independent physical readback and current-policy /
//! current-engine validation before the private supervisor singleton changes.

use vibeos_component_admission::OperatorArtifactAdmissionPolicy;
use vibeos_component_loader::{
    admit_operator_component_install, begin_c75_component_boot, C75ComponentBootState,
    C75RecoveredComponentInstall, DeployableComponentLoadPolicy,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_image_policy::C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
use vibeos_object_store::{AuthorityJournal, StoreError};

use crate::component_durable_publication::{
    c75_publication_ledger_is_empty, c75_publication_ledger_len, c75_publication_ledger_state,
    publish_c75_fresh_validated, C75PublicationLedgerState,
};

const STORE_READY_ATTEMPTS: usize = 120_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C75BootOutcome {
    Installed,
    Existing,
}

async fn recover_boot_proved_storage_v2(
    journal: &AuthorityJournal,
) -> Option<vibeos_object_store::StorageV2RecoveredAuthorityHead> {
    for _ in 0..STORE_READY_ATTEMPTS {
        match journal.recover_storage_v2_only().await {
            Ok(recovered) => return Some(recovered),
            Err(StoreError::Busy | StoreError::BackendAuthority | StoreError::Unformatted) => {
                crate::exec::sleep_ms(1).await;
            }
            Err(_) => return None,
        }
    }
    None
}

fn no_component_runtime_publication(baseline_component_count: usize) -> bool {
    c75_publication_ledger_is_empty()
        && c75_publication_ledger_state() == C75PublicationLedgerState::NoRootNoCommand
        && crate::world::world().c75_component_count() == baseline_component_count
}

pub(crate) async fn run_qemu_acceptance(
    journal: Option<AuthorityJournal>,
    baseline_component_count: usize,
) -> Option<C75BootOutcome> {
    if crate::online_hart_count() != 4
        || !no_component_runtime_publication(baseline_component_count)
    {
        return None;
    }
    let journal = journal?;
    let head = recover_boot_proved_storage_v2(&journal).await?;
    if !no_component_runtime_publication(baseline_component_count) {
        return None;
    }

    // This is the decisive ordering boundary: no policy fixture, artifact pin,
    // or evidence bytes have been consulted before durable state is classified.
    let state = begin_c75_component_boot(head).await.ok()?;
    if !no_component_runtime_publication(baseline_component_count) {
        return None;
    }

    // The current operator policy is boot configuration, not durable identity.
    // It is needed on both branches; only the Vacant arm below may inspect the
    // image artifact/evidence installation candidate.
    let policy_pin = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE.policy_p1();
    if policy_pin.runtime_ready() || policy_pin.guest_calls() != 0 {
        return None;
    }
    let world_contract =
        WorldContract::parse(policy_pin.exact_wit_source(), policy_pin.exact_world()).ok()?;
    let signers = policy_pin.signers().ok()?;
    let operator_policy = OperatorArtifactAdmissionPolicy::new(
        policy_pin.operator_role().ok()?,
        policy_pin.generation(),
        policy_pin.profile(),
        policy_pin.command_name(),
        policy_pin.entrypoint(),
        policy_pin.min_args(),
        policy_pin.max_args(),
        policy_pin.exact_wit_source(),
        &world_contract,
        policy_pin.limits(),
        policy_pin.stdin(),
        policy_pin.stdout(),
        policy_pin.stderr(),
        &[],
        &signers,
    )
    .ok()?;
    let load_policy = DeployableComponentLoadPolicy::new(&operator_policy);

    let (outcome, pending) = match state {
        C75ComponentBootState::Vacant(vacant) => {
            let artifact_pin = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE.operator_p1()[0];
            if artifact_pin.runtime_ready() || artifact_pin.guest_calls() != 0 {
                return None;
            }
            let artifact_bytes = artifact_pin
                .artifact()
                .and_then(|artifact| artifact.encode())
                .ok()?;
            let evidence_bytes = artifact_pin.authentication_evidence().ok()?.encode();
            let candidate =
                admit_operator_component_install(&artifact_bytes, &evidence_bytes, &load_policy)
                    .ok()?;
            if !no_component_runtime_publication(baseline_component_count) {
                return None;
            }
            let pending = vacant.install_operator(candidate).await.ok()?;
            (C75BootOutcome::Installed, pending)
        }
        C75ComponentBootState::Existing(pending) => {
            // This branch deliberately has no reference to operator_p1(), an
            // artifact pin, authentication evidence, or candidate constructor.
            (C75BootOutcome::Existing, pending)
        }
    };
    if !no_component_runtime_publication(baseline_component_count) {
        return None;
    }

    let recovered = pending.recover_payload().await.ok()?;
    if !no_component_runtime_publication(baseline_component_count) {
        return None;
    }
    let C75RecoveredComponentInstall::Operator(recovered) = recovered else {
        // Trust mode is selected by the durable layout; operator publication
        // can never fall back to development admission.
        return None;
    };
    let fresh = recovered.revalidate_on_boot(&load_policy).ok()?;
    let roots = fresh.root_presence();
    // Persistent/program roots are optional, independently owned partitions
    // in the fixed complete union. This publication requires exactly the
    // Component partition; the physical payload proof already bound the
    // optional-partition presence bits to the recovered media.
    if !roots.component() || !no_component_runtime_publication(baseline_component_count) {
        return None;
    }

    // Projection remains private and inert. It allocates no Component CSpace,
    // resource table, Task, executor instance, memory, fuel, or pending call.
    let publication = fresh.seal_inert_publication().ok()?;
    if !no_component_runtime_publication(baseline_component_count) {
        return None;
    }
    publish_c75_fresh_validated(publication).ok()?;
    if c75_publication_ledger_len() != 1
        || c75_publication_ledger_state()
            != C75PublicationLedgerState::ExactRootOneFreshValidatedInertCommand
        || crate::world::world().c75_component_count() != baseline_component_count
    {
        return None;
    }
    Some(outcome)
}
