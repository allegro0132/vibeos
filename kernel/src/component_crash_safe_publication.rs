//! C7.4 target gate for one crash-safe operator Component publication.
//!
//! The task obtains the already-provisioned store service through init's
//! explicit boot authority, waits for the native policy-v2 Storage V2 probe,
//! and then consumes the production linear installer. The only local
//! publication is a move into the private supervisor singleton; this module
//! cannot retrieve that command, install it in VSH, or execute guest code.

use vibeos_component_admission::OperatorArtifactAdmissionPolicy;
use vibeos_component_loader::{
    admit_operator_component_install, begin_c75_component_boot, C75ComponentBootState,
    C75RecoveredComponentInstall, DeployableComponentLoadPolicy,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_image_policy::C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
use vibeos_object_store::{AuthorityJournal, StoreError};

use crate::component_durable_publication::{
    c74_publication_ledger_is_empty, c74_publication_ledger_len, c74_publication_ledger_state,
    recover_and_publish_operator, C74PublicationLedgerState, C74_INERT_SINGLETON_MARKER,
};

const STORE_READY_ATTEMPTS: usize = 120_000;

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

pub(crate) async fn run_qemu_acceptance(journal: Option<AuthorityJournal>) -> bool {
    if crate::online_hart_count() != 4
        || !c74_publication_ledger_is_empty()
        || c74_publication_ledger_state() != C74PublicationLedgerState::NoRootNoCommand
        || C74_INERT_SINGLETON_MARKER
            != "c74 root=exact command=volatile-singleton runtime_ready=false guest_calls=0"
    {
        return false;
    }
    let Some(journal) = journal else {
        return false;
    };

    let fixture = C73_AUTHENTICATED_ADMISSION_QEMU_ACCEPTANCE;
    let policy_pin = fixture.policy_p1();
    if policy_pin.runtime_ready() || policy_pin.guest_calls() != 0 {
        return false;
    }
    let Ok(world_contract) =
        WorldContract::parse(policy_pin.exact_wit_source(), policy_pin.exact_world())
    else {
        return false;
    };
    let Ok(signers) = policy_pin.signers() else {
        return false;
    };
    let Ok(operator_policy) = OperatorArtifactAdmissionPolicy::new(
        match policy_pin.operator_role() {
            Ok(role) => role,
            Err(_) => return false,
        },
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
    ) else {
        return false;
    };
    let install_policy = DeployableComponentLoadPolicy::new(&operator_policy);

    if !c74_publication_ledger_is_empty()
        || c74_publication_ledger_state() != C74PublicationLedgerState::NoRootNoCommand
    {
        return false;
    }
    let Some(head) = recover_boot_proved_storage_v2(&journal).await else {
        return false;
    };
    if !c74_publication_ledger_is_empty() {
        return false;
    }
    let Ok(state) = begin_c75_component_boot(head).await else {
        return false;
    };
    if !c74_publication_ledger_is_empty() {
        return false;
    }
    let pending = match state {
        C75ComponentBootState::Vacant(vacant) => {
            let artifact_pin = fixture.operator_p1()[0];
            if artifact_pin.runtime_ready() || artifact_pin.guest_calls() != 0 {
                return false;
            }
            let Ok(artifact_bytes) = artifact_pin
                .artifact()
                .and_then(|artifact| artifact.encode())
            else {
                return false;
            };
            let Ok(evidence) = artifact_pin.authentication_evidence() else {
                return false;
            };
            let evidence_bytes = evidence.encode();
            let Ok(candidate) =
                admit_operator_component_install(&artifact_bytes, &evidence_bytes, &install_policy)
            else {
                return false;
            };
            let Ok(pending) = vacant.install_operator(candidate).await else {
                return false;
            };
            pending
        }
        C75ComponentBootState::Existing(pending) => pending,
    };
    if !c74_publication_ledger_is_empty()
        || c74_publication_ledger_state() != C74PublicationLedgerState::NoRootNoCommand
    {
        return false;
    }
    let Ok(recovered) = pending.recover_payload().await else {
        return false;
    };
    let C75RecoveredComponentInstall::Operator(recovered) = recovered else {
        return false;
    };
    let Ok(fresh) = recovered.revalidate_on_boot(&install_policy) else {
        return false;
    };
    let roots = fresh.root_presence();
    if !roots.component() {
        return false;
    }
    let Ok(()) = recover_and_publish_operator(fresh) else {
        return false;
    };
    c74_publication_ledger_len() == 1
        && c74_publication_ledger_state() == C74PublicationLedgerState::ExactRootOneInertCommand
}
