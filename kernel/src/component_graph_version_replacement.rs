//! C7.6 three-boot durable graph-version replacement orchestrator.
//!
//! Durable state is classified before either image candidate can be read.
//! G0 remains the sole visible version while a complete G1 is appended,
//! physically read back, and freshly revalidated.  The only visibility
//! transition then makes the graph unavailable while the exact C6.6
//! supervisor consumes PolicyCancel, retires the old target, and installs
//! fresh incident routes.  Any error after G0 publication is a sticky
//! fail-stop; there is no transition which can reopen G0 or expose a mixed
//! graph.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use vibeos_component_admission::{
    CallerAuthority, CommandStreamMode, ComponentGraphNodeReplacementPolicy,
    ComponentGraphReplacementEdgeAction, ComponentGraphReplacementEdgePolicy,
    ComponentGraphReplacementNodeAction, OperatorArtifactAdmissionPolicy,
    OperatorComponentGraphAdmissionPolicy, OperatorComponentGraphNodeAdmissionPolicy,
};
use vibeos_component_loader::{
    begin_c76_graph_boot, C76FreshReplaceableGraph, C76GraphBootState, C76RecoveredDurableGraph,
};
use vibeos_component_runtime::{
    graph::{
        ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
        ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
        ComponentGraphPublishedExportSpec,
    },
    world::WorldContract,
};
use vibeos_image_policy::{
    C76GraphOperatorPolicyPin, C76GraphRetirementAction, ComponentGraphReplacementEdgePin,
    ComponentGraphReplacementPinAction, C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE,
    C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE, C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE,
};
use vibeos_object_store::C76AuthorityJournal;

use crate::component_graph_principals::{
    stage_c76_current_graph, start_c76_durable_replacement, C76ReplacementReceipt, C76StagedCurrent,
};
use crate::sync::SpinLock;

const VISIBILITY_EMPTY: u8 = 0;
const VISIBILITY_G0: u8 = 1;
const VISIBILITY_TRANSITIONING: u8 = 2;
const VISIBILITY_G1: u8 = 3;
const VISIBILITY_FAILED: u8 = 4;

static VISIBILITY: AtomicU8 = AtomicU8::new(VISIBILITY_EMPTY);
static CURRENT: SpinLock<Option<C76StagedCurrent>> = SpinLock::new(None);
static FAIL_STOP_ARMED: AtomicBool = AtomicBool::new(false);
static VISIBILITY_LINEARIZATIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum C76BootOutcome {
    InstalledG0,
    ReplacedG1,
    ExistingG1,
}

async fn recover_boot_proved_storage_v3(journal: C76AuthorityJournal) -> Option<C76GraphBootState> {
    begin_c76_graph_boot(journal).await.ok()
}

fn world_baseline_is(baseline_component_count: usize) -> bool {
    crate::world::world().c76_component_count() == baseline_component_count
}

fn registry_is(occupied: usize) -> bool {
    let state = crate::component_instances::registry().occupancy_stats();
    state.occupied == occupied && state.header_mismatches == 0
}

fn visibility_is(state: u8) -> bool {
    VISIBILITY.load(Ordering::Acquire) == state
}

fn staged_current_is_exact(staged: &C76StagedCurrent) -> bool {
    staged.current_nodes() == 3
        && staged.current_routes() == 2
        && staged.candidate_lifecycle_objects() == 0
        && !staged.runtime_ready()
}

fn visible_g0_is_exact(baseline_component_count: usize) -> bool {
    visibility_is(VISIBILITY_G0)
        && VISIBILITY_LINEARIZATIONS.load(Ordering::Acquire) == 0
        && world_baseline_is(baseline_component_count)
        && registry_is(3)
        && CURRENT.lock().as_ref().is_some_and(staged_current_is_exact)
}

fn publish_current(
    staged: C76StagedCurrent,
    version: u8,
    baseline_component_count: usize,
) -> Result<(), ()> {
    if !matches!(version, VISIBILITY_G0 | VISIBILITY_G1)
        || !staged_current_is_exact(&staged)
        || !world_baseline_is(baseline_component_count)
        || !registry_is(3)
    {
        return Err(());
    }
    let mut slot = CURRENT.lock();
    if slot.is_some() || !visibility_is(VISIBILITY_EMPTY) {
        return Err(());
    }
    *slot = Some(staged);
    if VISIBILITY
        .compare_exchange(
            VISIBILITY_EMPTY,
            version,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        let _ = slot.take();
        return Err(());
    }
    Ok(())
}

/// Arm the one-way failure boundary before the first G1 candidate byte is
/// consulted. Visibility deliberately remains G0 until the durable pair has
/// passed independent physical readback and full fresh validation.
fn arm_fail_stop(baseline_component_count: usize) -> Result<(), ()> {
    if !visible_g0_is_exact(baseline_component_count)
        || FAIL_STOP_ARMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        || !visibility_is(VISIBILITY_G0)
    {
        return Err(());
    }
    Ok(())
}

/// Sole G0 -> Transitioning linearization, immediately before Stage B can
/// allocate its first candidate lifecycle object.
fn begin_transition(baseline_component_count: usize) -> Result<C76StagedCurrent, ()> {
    if !FAIL_STOP_ARMED.load(Ordering::Acquire) || !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }
    let mut slot = CURRENT.lock();
    VISIBILITY
        .compare_exchange(
            VISIBILITY_G0,
            VISIBILITY_TRANSITIONING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| ())?;
    slot.take().ok_or(())
}

fn replacement_receipt_is_exact(receipt: &C76ReplacementReceipt) -> bool {
    receipt.candidate_hidden_before_policy_cancel()
        && receipt.old_terminal_before_new_visible()
        && receipt.siblings_stable() == 2
        && receipt.candidate_identity_is_fresh()
        && receipt.fresh_resources_are_distinct()
        && receipt.old_routes_retired() == 2
        && receipt.fresh_routes() == 2
        && receipt.stale_replacement_tokens() == 2
        && receipt.late_wake_stale() == 1
        && receipt.policy_cancelled_after_old_terminal()
        && receipt.no_active_poll_at_cutover()
        && !receipt.graph_version_published()
        && !receipt.runtime_ready()
        && receipt.guest_calls() == 0
        && receipt.terminal_receipts() == 4
        && receipt.reports_are_runtime_unavailable()
}

fn publish_g1(receipt: C76ReplacementReceipt, baseline_component_count: usize) -> Result<(), ()> {
    if !replacement_receipt_is_exact(&receipt)
        || !FAIL_STOP_ARMED.load(Ordering::Acquire)
        || !world_baseline_is(baseline_component_count)
        || !registry_is(0)
        || VISIBILITY_LINEARIZATIONS.load(Ordering::Acquire) != 0
        || CURRENT.lock().is_some()
    {
        return Err(());
    }
    VISIBILITY
        .compare_exchange(
            VISIBILITY_TRANSITIONING,
            VISIBILITY_G1,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| ())?;
    VISIBILITY_LINEARIZATIONS.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

fn fail_stop() {
    VISIBILITY.store(VISIBILITY_FAILED, Ordering::Release);
    let _ = CURRENT.lock().take();
}

fn edge(pin: ComponentGraphReplacementEdgePin) -> Option<ComponentGraphEdgeSpec> {
    if pin.action() != ComponentGraphReplacementPinAction::RecreateFresh {
        return None;
    }
    Some(ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(pin.source_node()),
            ComponentGraphEntityIndex::new(pin.source_export()),
        ),
        ComponentGraphImportEndpoint::new(
            ComponentGraphNodeId::new(pin.target_node()),
            ComponentGraphEntityIndex::new(pin.target_import()),
        ),
    ))
}

fn policy_pin_is_exact(pin: C76GraphOperatorPolicyPin) -> bool {
    let (stdin, stdout, stderr) = pin.node_streams();
    pin.node_count() == 3
        && pin.all_nodes_are_roots()
        && pin.resource_edge_count() == 0
        && pin.external_import_count() == 0
        && pin.node_interface_ceiling_count() == 0
        && pin.replacement_node() == 1
        && pin.max_replacements() == 1
        && pin.retirement_action() == C76GraphRetirementAction::PolicyCancel
        && stdin == CommandStreamMode::Closed
        && stdout == CommandStreamMode::Closed
        && stderr == CommandStreamMode::Closed
        && !pin.profile().execution_enabled()
        && !pin.runtime_ready()
        && pin.guest_calls() == 0
}

async fn replace_g0(
    current: C76FreshReplaceableGraph,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
    baseline_component_count: usize,
) -> Result<C76BootOutcome, ()> {
    let (current_proof, successor_gate) = current.take_current_supervisor();
    let staged = stage_c76_current_graph(current_proof).map_err(|_| ())?;
    publish_current(staged, VISIBILITY_G0, baseline_component_count)?;
    if !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }

    // Every later error is converted by the outer driver into FAILED. G0 is
    // still the sole visible graph while the durable successor is proved.
    arm_fail_stop(baseline_component_count)?;
    let pin = C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE;
    if pin.ordinal() != 1
        || pin.attachment_counts() != (3, 3, 1)
        || pin.runtime_ready()
        || pin.guest_calls() != 0
    {
        return Err(());
    }
    if !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }
    let pending = successor_gate
        .admit_and_replace(
            pin.canonical_descriptor_bytes(),
            pin.canonical_artifact_bytes(),
            pin.canonical_artifact_evidence_bytes(),
            pin.canonical_graph_evidence_bytes(),
            policy,
            caller,
        )
        .await
        .map_err(|_| ())?;
    if !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }
    let recovered = pending.recover_graph().await.map_err(|_| ())?;
    let C76RecoveredDurableGraph::G1(recovered) = recovered else {
        return Err(());
    };
    if !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }
    let fresh_pair = recovered
        .revalidate_on_boot(policy, caller)
        .map_err(|_| ())?;
    if !visible_g0_is_exact(baseline_component_count) {
        return Err(());
    }
    let replacement = fresh_pair.into_supervisor_replacement();

    // This CAS is adjacent to Stage B. No candidate domain, registry slot,
    // resource table, task, or route can exist before it.
    let staged = begin_transition(baseline_component_count)?;
    let run = start_c76_durable_replacement(staged, replacement).map_err(|_| ())?;
    let receipt = run.wait().await.map_err(|_| ())?;
    publish_g1(receipt, baseline_component_count)?;
    if !visibility_is(VISIBILITY_G1)
        || VISIBILITY_LINEARIZATIONS.load(Ordering::Acquire) != 1
        || !FAIL_STOP_ARMED.load(Ordering::Acquire)
        || CURRENT.lock().is_some()
        || !world_baseline_is(baseline_component_count)
        || !registry_is(0)
    {
        return Err(());
    }
    Ok(C76BootOutcome::ReplacedG1)
}

async fn run_inner(
    journal: Option<C76AuthorityJournal>,
    baseline_component_count: usize,
) -> Option<C76BootOutcome> {
    if crate::online_hart_count() != 4
        || crate::online_hart_mask() & 0x0f != 0x0f
        || !visibility_is(VISIBILITY_EMPTY)
        || CURRENT.lock().is_some()
        || FAIL_STOP_ARMED.load(Ordering::Acquire)
        || VISIBILITY_LINEARIZATIONS.load(Ordering::Acquire) != 0
        || !world_baseline_is(baseline_component_count)
        || !registry_is(0)
    {
        return None;
    }
    let journal = journal?;
    let durable = recover_boot_proved_storage_v3(journal).await?;
    if !world_baseline_is(baseline_component_count) || !registry_is(0) {
        return None;
    }

    // Decisive ordering boundary: no policy fixture and no G0/G1 candidate
    // bytes were consulted before the V3 durable namespace was classified.
    if !world_baseline_is(baseline_component_count) || !registry_is(0) {
        return None;
    }

    // The current policy is a disjoint image constant.  Neither G0 nor G1
    // candidate bytes are named while the existing physical history is still
    // unknown.
    let pin = C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;
    if !policy_pin_is_exact(pin) {
        return None;
    }
    let worlds = pin.node_worlds();
    let world0 = WorldContract::parse(pin.exact_wit_source(), worlds[0]).ok()?;
    let world1 = WorldContract::parse(pin.exact_wit_source(), worlds[1]).ok()?;
    let world2 = WorldContract::parse(pin.exact_wit_source(), worlds[2]).ok()?;
    let leaf_signers = pin.leaf_signers().ok()?;
    let graph_signers = pin.graph_signers().ok()?;
    if leaf_signers != graph_signers {
        return None;
    }
    let role = pin.operator_role().ok()?;
    let (min_args, max_args) = pin.node_argument_limits();
    let (stdin, stdout, stderr) = pin.node_streams();
    let leaf0 = OperatorArtifactAdmissionPolicy::new(
        role,
        pin.generation(),
        pin.profile(),
        pin.node_command_name(),
        pin.node_entrypoint(),
        min_args,
        max_args,
        pin.exact_wit_source(),
        &world0,
        pin.node_limits(),
        stdin,
        stdout,
        stderr,
        &[],
        &leaf_signers,
    )
    .ok()?;
    let leaf1 = OperatorArtifactAdmissionPolicy::new(
        role,
        pin.generation(),
        pin.profile(),
        pin.node_command_name(),
        pin.node_entrypoint(),
        min_args,
        max_args,
        pin.exact_wit_source(),
        &world1,
        pin.node_limits(),
        stdin,
        stdout,
        stderr,
        &[],
        &leaf_signers,
    )
    .ok()?;
    let leaf2 = OperatorArtifactAdmissionPolicy::new(
        role,
        pin.generation(),
        pin.profile(),
        pin.node_command_name(),
        pin.node_entrypoint(),
        min_args,
        max_args,
        pin.exact_wit_source(),
        &world2,
        pin.node_limits(),
        stdin,
        stdout,
        stderr,
        &[],
        &leaf_signers,
    )
    .ok()?;
    let labels = pin.node_labels();
    let nodes = [
        OperatorComponentGraphNodeAdmissionPolicy {
            label: labels[0],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf0,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: labels[1],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf1,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: labels[2],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf2,
        },
    ];
    let edge_pins = pin.graph_edges();
    let edges = [edge(edge_pins[0])?, edge(edge_pins[1])?];
    let incident_pins = pin.incident_edges();
    let incidents = [
        ComponentGraphReplacementEdgePolicy {
            edge: edge(incident_pins[0])?,
            action: ComponentGraphReplacementEdgeAction::RecreateFresh,
        },
        ComponentGraphReplacementEdgePolicy {
            edge: edge(incident_pins[1])?,
            action: ComponentGraphReplacementEdgeAction::RecreateFresh,
        },
    ];
    let (published_node, published_export) = pin.published_export();
    let published = [ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(published_node),
            ComponentGraphEntityIndex::new(published_export),
        ),
    )];
    let policy = OperatorComponentGraphAdmissionPolicy::new(
        role,
        pin.generation(),
        pin.graph_name(),
        pin.profile(),
        &nodes,
        &edges,
        &[],
        &[],
        &published,
        ComponentGraphNodeReplacementPolicy {
            target: ComponentGraphNodeId::new(pin.replacement_node()),
            max_replacements: pin.max_replacements(),
            node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
            incident_edges: &incidents,
        },
        &graph_signers,
    )
    .ok()?;
    let caller = CallerAuthority { offers: &[] };

    match durable {
        C76GraphBootState::Vacant(vacant) => {
            // Only the classified Vacant branch may read G0 image bytes.
            let version = C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE;
            if version.ordinal() != 0
                || version.attachment_counts() != (3, 3, 1)
                || version.runtime_ready()
                || version.guest_calls() != 0
            {
                return None;
            }
            if !visibility_is(VISIBILITY_EMPTY)
                || !world_baseline_is(baseline_component_count)
                || !registry_is(0)
            {
                return None;
            }
            let pending = vacant
                .admit_and_install_initial(
                    version.canonical_descriptor_bytes(),
                    version.canonical_artifact_bytes(),
                    version.canonical_artifact_evidence_bytes(),
                    version.canonical_graph_evidence_bytes(),
                    &policy,
                    &caller,
                )
                .await
                .ok()?;
            let recovered = pending.recover_graph().await.ok()?;
            let C76RecoveredDurableGraph::G0(recovered) = recovered else {
                return None;
            };
            let fresh = recovered
                .revalidate_current_on_boot(&policy, &caller)
                .ok()?;
            let (proof, _successor_gate) = fresh.take_current_supervisor();
            let staged = stage_c76_current_graph(proof).ok()?;
            publish_current(staged, VISIBILITY_G0, baseline_component_count).ok()?;
            if !visible_g0_is_exact(baseline_component_count)
                || FAIL_STOP_ARMED.load(Ordering::Acquire)
            {
                return None;
            }
            Some(C76BootOutcome::InstalledG0)
        }
        C76GraphBootState::Existing(pending) => {
            // Physical classification completes before this match can decide
            // whether the G1 image candidate is needed.
            let recovered = pending.recover_graph().await.ok()?;
            match recovered {
                C76RecoveredDurableGraph::G0(recovered) => {
                    let current = recovered
                        .revalidate_current_on_boot(&policy, &caller)
                        .ok()?;
                    replace_g0(current, &policy, &caller, baseline_component_count)
                        .await
                        .ok()
                }
                C76RecoveredDurableGraph::G1(recovered) => {
                    // This branch has no G0/G1 candidate accessor and the
                    // physically final graph exposes no durable write method.
                    let fresh_pair = recovered.revalidate_on_boot(&policy, &caller).ok()?;
                    let proof = fresh_pair.into_successor_supervisor_graph().ok()?;
                    let staged = stage_c76_current_graph(proof).ok()?;
                    publish_current(staged, VISIBILITY_G1, baseline_component_count).ok()?;
                    if !visibility_is(VISIBILITY_G1)
                        || FAIL_STOP_ARMED.load(Ordering::Acquire)
                        || VISIBILITY_LINEARIZATIONS.load(Ordering::Acquire) != 0
                        || !world_baseline_is(baseline_component_count)
                        || !registry_is(3)
                        || !CURRENT.lock().as_ref().is_some_and(staged_current_is_exact)
                    {
                        return None;
                    }
                    Some(C76BootOutcome::ExistingG1)
                }
            }
        }
    }
}

pub(crate) async fn run_qemu_acceptance(
    journal: Option<C76AuthorityJournal>,
    baseline_component_count: usize,
) -> Option<C76BootOutcome> {
    let outcome = run_inner(journal, baseline_component_count).await;
    if outcome.is_none() {
        fail_stop();
    }
    outcome
}
