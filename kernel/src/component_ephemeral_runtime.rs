//! C7.7 cold-boot reconstruction of one exact durable Component graph.
//!
//! The storage/loader gate accepts only a complete, graph-only physical G1
//! namespace and exposes no image candidate or write transition. Current
//! signer, policy, WIT, Component, Core, and engine validation all finish
//! while the component registry is still empty. Only then may the kernel
//! allocate a fresh validation-only lifecycle and wait at one real sealed
//! host-stream pending-call cut. The retained cut is boot-local and contains
//! no executable guest state.

use vibeos_component_admission::{
    CallerAuthority, CommandStreamMode, ComponentGraphNodeReplacementPolicy,
    ComponentGraphReplacementEdgeAction, ComponentGraphReplacementEdgePolicy,
    ComponentGraphReplacementNodeAction, OperatorArtifactAdmissionPolicy,
    OperatorComponentGraphAdmissionPolicy, OperatorComponentGraphNodeAdmissionPolicy,
};
use vibeos_component_loader::begin_c77_ephemeral_boot;
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
    ComponentGraphReplacementPinAction, C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE,
};
use vibeos_object_store::C76AuthorityJournal;

use crate::component_graph_principals::{
    stage_c77_ephemeral_graph, C77EphemeralBootReceipt, C77StagedEphemeralGraph,
};
use crate::sync::SpinLock;

const C77_NODE_COUNT: usize = 3;
const C77_LIVE_RESOURCE_COUNT: usize = 4;

/// Hold the exact parked lifecycle until QEMU removes power. No operation can
/// obtain it by name, and no diagnostic surface can inspect its identities.
static CURRENT: SpinLock<Option<C77StagedEphemeralGraph>> = SpinLock::new(None);

fn world_baseline_is(baseline_component_count: usize) -> bool {
    crate::world::world().c77_component_count() == baseline_component_count
}

fn registry_is(occupied: usize) -> bool {
    let state = crate::component_instances::registry().occupancy_stats();
    state.occupied == occupied && state.header_mismatches == 0
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
    pin.node_count() == C77_NODE_COUNT as u16
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

fn receipt_is_exact(receipt: &C77EphemeralBootReceipt, expected_memory_bytes: u64) -> bool {
    receipt.fresh_tasks() == C77_NODE_COUNT
        && receipt.fresh_arenas() == C77_NODE_COUNT
        && receipt.fresh_cspaces() == C77_NODE_COUNT
        && receipt.fresh_memories() == C77_NODE_COUNT
        && receipt.fresh_resource_tables() == C77_NODE_COUNT
        && receipt.fresh_fuel_accounts() == C77_NODE_COUNT
        && receipt.fresh_pending_ledgers() == C77_NODE_COUNT
        && receipt.active_pending_calls() == 1
        && receipt.memory_bytes() == expected_memory_bytes
        && receipt.live_resources() == C77_LIVE_RESOURCE_COUNT
        && receipt.fuel_consumed() == 0
        && !receipt.runtime_ready()
        && receipt.guest_calls() == 0
}

pub(crate) async fn run_qemu_acceptance(
    journal: Option<C76AuthorityJournal>,
    baseline_component_count: usize,
) -> bool {
    if crate::online_hart_count() != 4
        || crate::online_hart_mask() & 0x0f != 0x0f
        || CURRENT.lock().is_some()
        || !world_baseline_is(baseline_component_count)
        || !registry_is(0)
    {
        return false;
    }
    let Some(journal) = journal else {
        return false;
    };

    // The first consuming gate rejects Vacant, G0, optional root partitions,
    // tombstoned foreign history, and every non-exact namespace before policy
    // configuration or a runtime constructor is consulted.
    let pending = match begin_c77_ephemeral_boot(journal).await {
        Ok(pending) => pending,
        Err(_) => return false,
    };
    if !world_baseline_is(baseline_component_count) || !registry_is(0) {
        return false;
    }
    // A second physical readback repeats the graph-only namespace proof and
    // exact descriptor binding. This branch has no append/candidate method.
    let recovered = match pending.recover_graph().await {
        Ok(recovered) => recovered,
        Err(_) => return false,
    };
    if !world_baseline_is(baseline_component_count) || !registry_is(0) {
        return false;
    }

    // Current boot policy is independent configuration. It is deliberately
    // read only after exact physical G1 recovery; no artifact bytes are read
    // from the image in C7.7.
    let pin = C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;
    if !policy_pin_is_exact(pin) {
        return false;
    }
    let worlds = pin.node_worlds();
    let Ok(world0) = WorldContract::parse(pin.exact_wit_source(), worlds[0]) else {
        return false;
    };
    let Ok(world1) = WorldContract::parse(pin.exact_wit_source(), worlds[1]) else {
        return false;
    };
    let Ok(world2) = WorldContract::parse(pin.exact_wit_source(), worlds[2]) else {
        return false;
    };
    let Ok(leaf_signers) = pin.leaf_signers() else {
        return false;
    };
    let Ok(graph_signers) = pin.graph_signers() else {
        return false;
    };
    if leaf_signers != graph_signers {
        return false;
    }
    let Ok(role) = pin.operator_role() else {
        return false;
    };
    let (min_args, max_args) = pin.node_argument_limits();
    let (stdin, stdout, stderr) = pin.node_streams();
    let Ok(leaf0) = OperatorArtifactAdmissionPolicy::new(
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
    ) else {
        return false;
    };
    let Ok(leaf1) = OperatorArtifactAdmissionPolicy::new(
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
    ) else {
        return false;
    };
    let Ok(leaf2) = OperatorArtifactAdmissionPolicy::new(
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
    ) else {
        return false;
    };
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
    let Some(edge0) = edge(edge_pins[0]) else {
        return false;
    };
    let Some(edge1) = edge(edge_pins[1]) else {
        return false;
    };
    let edges = [edge0, edge1];
    let incident_pins = pin.incident_edges();
    let Some(incident0) = edge(incident_pins[0]) else {
        return false;
    };
    let Some(incident1) = edge(incident_pins[1]) else {
        return false;
    };
    let incidents = [
        ComponentGraphReplacementEdgePolicy {
            edge: incident0,
            action: ComponentGraphReplacementEdgeAction::RecreateFresh,
        },
        ComponentGraphReplacementEdgePolicy {
            edge: incident1,
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
    let Ok(policy) = OperatorComponentGraphAdmissionPolicy::new(
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
    ) else {
        return false;
    };
    let caller = CallerAuthority { offers: &[] };
    let proof = match recovered.revalidate_current_on_boot(&policy, &caller) {
        Ok(proof) => proof,
        Err(_) => return false,
    };
    if !world_baseline_is(baseline_component_count) || !registry_is(0) {
        return false;
    }

    // This is the first runtime allocation boundary. The staged graph owns
    // real boot-local Tasks, arenas, CSpaces, memory/fuel/resource state and
    // per-instance pending ledgers, but its guest profile remains disabled.
    let staged = match stage_c77_ephemeral_graph(proof) {
        Ok(staged) => staged,
        Err(_) => return false,
    };
    if !world_baseline_is(baseline_component_count) || !registry_is(C77_NODE_COUNT) {
        return false;
    }
    let receipt = match staged.observe().await {
        Ok(receipt) => receipt,
        Err(_) => return false,
    };
    let Some(expected_memory_bytes) = u64::try_from(pin.node_limits().memory_bytes)
        .ok()
        .and_then(|bytes| bytes.checked_mul(C77_NODE_COUNT as u64))
    else {
        return false;
    };
    if !receipt_is_exact(&receipt, expected_memory_bytes)
        || !world_baseline_is(baseline_component_count)
        || !registry_is(C77_NODE_COUNT)
    {
        return false;
    }
    let mut current = CURRENT.lock();
    if current.is_some() {
        return false;
    }
    *current = Some(staged);
    current.is_some() && world_baseline_is(baseline_component_count) && registry_is(C77_NODE_COUNT)
}
