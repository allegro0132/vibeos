use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use vibeos_component_admission::{
    admit_authenticated_component_graph_replacement, admit_authenticated_component_graph_version,
    admit_component_graph, authenticate_component_graph_version, canonical_entity_shape_text_v1,
    ArtifactAuthenticationError, ArtifactTrust, AuthenticatedAdmissionError, CallerAuthority,
    CommandStreamMode, ComponentArtifact, ComponentGraphAdmissionPolicy,
    ComponentGraphAuthenticationError, ComponentGraphCyclePolicy,
    ComponentGraphNodeAdmissionPolicy, ComponentGraphNodeReplacementPolicy,
    ComponentGraphReplacementEdgeAction, ComponentGraphReplacementEdgePolicy,
    ComponentGraphReplacementNodeAction, InstanceLimits, OperatorArtifactAdmissionPolicy,
    OperatorComponentGraphAdmissionPolicy, OperatorComponentGraphNodeAdmissionPolicy,
    OperatorRoleIdentity, OperatorSignerStatus, OperatorSignerV1,
    COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN,
};
use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceCommitment, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ComponentArtifactWitPackageV1,
    ComponentGraphNodeBudget, ComponentGraphVersionAsyncEdgeV1,
    ComponentGraphVersionAuthenticationEvidenceV1, ComponentGraphVersionBundleV1,
    ComponentGraphVersionCommitment, ComponentGraphVersionComponentIdentity,
    ComponentGraphVersionEdgeV1, ComponentGraphVersionEndpointV1,
    ComponentGraphVersionIncidentEdgeActionV1, ComponentGraphVersionIncidentEdgeV1,
    ComponentGraphVersionNodeNestingV1, ComponentGraphVersionNodeV1,
    ComponentGraphVersionPolicyDigest, ComponentGraphVersionPublishedExportV1,
    ComponentGraphVersionReplacementV1, ComponentGraphVersionRetirementActionV1,
    ComponentGraphVersionV1, ComponentGraphVersionWorldContractCommitment, ProfileIdentity,
};
use vibeos_component_runtime::{
    decode::inspect_component_for_profile,
    graph::{
        ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
        ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
        ComponentGraphPublishedExportSpec,
    },
    world::{EntityShape, TypeShape, WorldContract},
};

const WIT: &str = include_str!("../../../policy/image/artifacts/c65-async-chain.wit");
const SOURCE: &str = include_str!("../../../policy/image/artifacts/c65-async-source.component.wat");
const RELAY: &str = include_str!("../../../policy/image/artifacts/c65-async-relay.component.wat");
const RELAY_V2: &str =
    include_str!("../../../policy/image/artifacts/c66-async-relay-v2.component.wat");
const SINK: &str = include_str!("../../../policy/image/artifacts/c65-async-sink.component.wat");

const WORLDS: [&str; 3] = [
    "test:c65-chain/source@1.0.0",
    "test:c65-chain/relay@1.0.0",
    "test:c65-chain/sink@1.0.0",
];
const LABELS: [&str; 3] = ["source", "relay", "sink"];
const SEED: [u8; 32] = [0x76; 32];

fn node(index: u16) -> ComponentGraphNodeId {
    ComponentGraphNodeId::new(index)
}

fn entity(index: u16) -> ComponentGraphEntityIndex {
    ComponentGraphEntityIndex::new(index)
}

fn edge(source: u16, export: u16, target: u16, import: u16) -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(node(source), entity(export)),
        ComponentGraphImportEndpoint::new(node(target), entity(import)),
    )
}

fn graph_edges() -> [ComponentGraphEdgeSpec; 2] {
    [edge(0, 0, 1, 0), edge(1, 0, 2, 0)]
}

fn published() -> [ComponentGraphPublishedExportSpec; 1] {
    [ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(node(2), entity(0)),
    )]
}

fn incidents() -> [ComponentGraphReplacementEdgePolicy; 2] {
    graph_edges().map(|edge| ComponentGraphReplacementEdgePolicy {
        edge,
        action: ComponentGraphReplacementEdgeAction::RecreateFresh,
    })
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 2_000,
        poll_quantum: 100,
        resources: 5,
    }
}

fn format_limits() -> ComponentArtifactInstanceLimitsV1 {
    let limits = limits();
    ComponentArtifactInstanceLimitsV1::new(
        limits.memory_bytes as u64,
        limits.total_fuel,
        limits.poll_quantum,
        u64::from(limits.resources),
    )
    .unwrap()
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn signer_policy() -> OperatorSignerV1 {
    OperatorSignerV1::new(
        signer().verifying_key().to_bytes(),
        OperatorSignerStatus::Active,
    )
    .unwrap()
}

fn role() -> OperatorRoleIdentity {
    OperatorRoleIdentity::from_bytes(Sha256::digest(b"vibeos.c76.test.graph-role\0").into())
        .unwrap()
}

fn leaf_policy<'a>(
    world: &'a WorldContract,
    signers: &'a [OperatorSignerV1],
) -> OperatorArtifactAdmissionPolicy<'a> {
    OperatorArtifactAdmissionPolicy::new(
        role(),
        9,
        ProfileIdentity::PROFILE_1_ASYNC,
        "c76-node",
        "run",
        0,
        0,
        WIT,
        world,
        limits(),
        CommandStreamMode::Closed,
        CommandStreamMode::Closed,
        CommandStreamMode::Closed,
        &[],
        signers,
    )
    .unwrap()
}

fn entity_kind(entity: &EntityShape) -> ComponentArtifactEntityKind {
    match entity {
        EntityShape::Function(_) => ComponentArtifactEntityKind::Function,
        EntityShape::Interface(_) => ComponentArtifactEntityKind::Interface,
        EntityShape::Type(TypeShape::Resource | TypeShape::Value(_)) => {
            ComponentArtifactEntityKind::Type
        }
    }
}

fn artifact(
    wat: &str,
    world: &WorldContract,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> ComponentArtifactV1 {
    let bytes = wat::parse_str(wat).unwrap();
    artifact_bytes_with_manifest(&bytes, world, policy, false)
}

fn artifact_bytes(
    bytes: &[u8],
    world: &WorldContract,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> ComponentArtifactV1 {
    artifact_bytes_with_manifest(bytes, world, policy, false)
}

fn artifact_bytes_with_manifest(
    bytes: &[u8],
    world: &WorldContract,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
    omit_interfaces: bool,
) -> ComponentArtifactV1 {
    let plan = inspect_component_for_profile(bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    let mut interfaces = Vec::new();
    for (direction, entities) in [
        (ComponentArtifactInterfaceDirection::Import, plan.imports()),
        (ComponentArtifactInterfaceDirection::Export, plan.exports()),
    ] {
        for entity in entities {
            interfaces.push(
                ComponentArtifactInterfaceV1::new(
                    direction,
                    entity_kind(&entity.entity),
                    &entity.name,
                    &canonical_entity_shape_text_v1(&entity.entity).unwrap(),
                )
                .unwrap(),
            );
        }
    }
    if omit_interfaces {
        interfaces.clear();
    }
    let modules = plan
        .embedded_modules()
        .iter()
        .map(|bytes| ComponentArtifactCoreModuleV1::from_bytes(bytes).unwrap())
        .collect();
    let manifest = ComponentArtifactManifestV1::new(
        &world.identity,
        vec![ComponentArtifactWitPackageV1::new("test:c65-chain", "1.0.0", WIT).unwrap()],
        interfaces,
        modules,
        vec![],
    )
    .unwrap();
    ComponentArtifactV1::new(
        bytes,
        ProfileIdentity::PROFILE_1_ASYNC,
        format_limits(),
        ComponentArtifactSignerPolicyV1::operator_required(
            *policy.commitment().unwrap().as_bytes(),
        )
        .unwrap(),
        manifest,
    )
    .unwrap()
}

fn leaf_evidence(
    artifact: &ComponentArtifactV1,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> ComponentArtifactAuthenticationEvidenceV1 {
    let key = signer();
    let public = key.verifying_key().to_bytes();
    ComponentArtifactAuthenticationEvidenceV1::new(
        public,
        key.sign(&policy.signature_transcript(artifact, public).unwrap())
            .to_bytes(),
    )
    .unwrap()
}

fn image_admit(
    artifacts: &[ComponentArtifactV1],
    worlds: &[WorldContract; 3],
) -> vibeos_component_admission::AdmittedComponentGraph {
    let components: Vec<_> = artifacts
        .iter()
        .map(|artifact| {
            ComponentArtifact::copy_from(
                artifact.component_bytes(),
                ProfileIdentity::PROFILE_1_ASYNC,
            )
            .unwrap()
        })
        .collect();
    let nodes = [
        ComponentGraphNodeAdmissionPolicy {
            label: LABELS[0],
            nesting: ComponentGraphNesting::Root,
            exact_world: &worlds[0],
            trust: ArtifactTrust::ImagePinned(components[0].identity()),
            limits: limits(),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: LABELS[1],
            nesting: ComponentGraphNesting::Root,
            exact_world: &worlds[1],
            trust: ArtifactTrust::ImagePinned(components[1].identity()),
            limits: limits(),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: LABELS[2],
            nesting: ComponentGraphNesting::Root,
            exact_world: &worlds[2],
            trust: ArtifactTrust::ImagePinned(components[2].identity()),
            limits: limits(),
            interfaces: &[],
        },
    ];
    let edges = graph_edges();
    let published = published();
    admit_component_graph(
        components,
        &ComponentGraphAdmissionPolicy {
            name: "c76-chain",
            profile: ProfileIdentity::PROFILE_1_ASYNC,
            nodes: &nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        },
        &CallerAuthority { offers: &[] },
    )
    .unwrap()
}

fn format_edge(edge: ComponentGraphEdgeSpec) -> ComponentGraphVersionEdgeV1 {
    ComponentGraphVersionEdgeV1::new(
        ComponentGraphVersionEndpointV1::new(
            edge.source().node().index(),
            edge.source().export().index(),
        ),
        ComponentGraphVersionEndpointV1::new(
            edge.target().node().index(),
            edge.target().import().index(),
        ),
    )
}

#[derive(Clone, Copy)]
enum DescriptorMutation {
    None,
    NodeWorldContract { node: usize },
    NodeCoreInstancesBudget { node: usize },
    AsyncFunctions { edge: usize },
}

fn bundle(
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    artifacts: Vec<ComponentArtifactV1>,
    leaf_evidence: Vec<ComponentArtifactAuthenticationEvidenceV1>,
    admitted: &vibeos_component_admission::AdmittedComponentGraph,
    graph_policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> ComponentGraphVersionBundleV1 {
    bundle_with_mutation(
        ordinal,
        predecessor,
        artifacts,
        leaf_evidence,
        admitted,
        graph_policy,
        DescriptorMutation::None,
    )
}

fn bundle_with_mutation(
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    artifacts: Vec<ComponentArtifactV1>,
    leaf_evidence: Vec<ComponentArtifactAuthenticationEvidenceV1>,
    admitted: &vibeos_component_admission::AdmittedComponentGraph,
    graph_policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    mutation: DescriptorMutation,
) -> ComponentGraphVersionBundleV1 {
    let mut nodes = Vec::new();
    for (index, ((artifact, evidence), admitted_node)) in artifacts
        .iter()
        .zip(&leaf_evidence)
        .zip(admitted.manifest().nodes())
        .enumerate()
    {
        let world_contract_commitment = match mutation {
            DescriptorMutation::NodeWorldContract { node } if node == index => {
                ComponentGraphVersionWorldContractCommitment::from_bytes([0xa5; 32]).unwrap()
            }
            _ => ComponentGraphVersionWorldContractCommitment::from_bytes(
                admitted_node.world_contract_commitment(),
            )
            .unwrap(),
        };
        let mut budget: ComponentGraphNodeBudget = admitted_node.budget();
        if matches!(
            mutation,
            DescriptorMutation::NodeCoreInstancesBudget { node } if node == index
        ) {
            budget.core_instances += 1;
        }
        nodes.push(
            ComponentGraphVersionNodeV1::new(
                index as u16,
                LABELS[index],
                WORLDS[index],
                ComponentGraphVersionNodeNestingV1::Root,
                artifact.encode().unwrap().len() as u64,
                artifact.artifact_commitment().unwrap(),
                ComponentArtifactAuthenticationEvidenceCommitment::from_evidence(evidence).unwrap(),
                artifact.signer_policy().policy_digest(),
                ComponentGraphVersionComponentIdentity::from_component_bytes(
                    artifact.component_bytes(),
                )
                .unwrap(),
                world_contract_commitment,
                artifact.instance_limits(),
                budget,
            )
            .unwrap(),
        );
    }
    let edges: Vec<_> = admitted
        .manifest()
        .edges()
        .iter()
        .copied()
        .map(format_edge)
        .collect();
    let async_edges = admitted
        .manifest()
        .async_edges()
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let async_functions = if matches!(
                mutation,
                DescriptorMutation::AsyncFunctions { edge } if edge == index
            ) {
                edge.async_functions() + 1
            } else {
                edge.async_functions()
            };
            ComponentGraphVersionAsyncEdgeV1::new(
                format_edge(edge.edge()),
                async_functions,
                edge.streams(),
                edge.futures(),
            )
            .unwrap()
        })
        .collect();
    let incidents = graph_policy
        .replacement()
        .incident_edges
        .iter()
        .map(|incident| {
            ComponentGraphVersionIncidentEdgeV1::new(
                format_edge(incident.edge),
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )
        })
        .collect();
    let mut account = admitted.manifest().account();
    if matches!(mutation, DescriptorMutation::NodeCoreInstancesBudget { .. }) {
        account.core_instances += 1;
    }
    let descriptor = ComponentGraphVersionV1::new(
        "c76-chain",
        ProfileIdentity::PROFILE_1_ASYNC,
        ordinal,
        predecessor,
        ComponentGraphVersionPolicyDigest::from_bytes(
            *graph_policy.commitment().unwrap().as_bytes(),
        )
        .unwrap(),
        account,
        nodes,
        edges,
        async_edges,
        vec![],
        vec![ComponentGraphVersionPublishedExportV1::new(
            ComponentGraphVersionEndpointV1::new(2, 0),
        )],
        ComponentGraphVersionReplacementV1::new(
            1,
            1,
            ComponentGraphVersionRetirementActionV1::PolicyCancel,
            incidents,
        )
        .unwrap(),
    )
    .unwrap();
    let key = signer();
    let public = key.verifying_key().to_bytes();
    let transcript = graph_policy
        .signature_transcript(&descriptor, public)
        .unwrap();
    assert_eq!(transcript.len(), COMPONENT_GRAPH_SIGNATURE_TRANSCRIPT_LEN);
    let graph_evidence = ComponentGraphVersionAuthenticationEvidenceV1::new(
        public,
        key.sign(&transcript).to_bytes(),
    )
    .unwrap();
    ComponentGraphVersionBundleV1::new(descriptor, artifacts, leaf_evidence, graph_evidence)
        .unwrap()
}

fn with_graph_policy<R>(
    test: impl FnOnce(&[WorldContract; 3], &OperatorComponentGraphAdmissionPolicy<'_>) -> R,
) -> R {
    let worlds = WORLDS.map(|world| WorldContract::parse(WIT, world).unwrap());
    let signers = [signer_policy()];
    let leaf0 = leaf_policy(&worlds[0], &signers);
    let leaf1 = leaf_policy(&worlds[1], &signers);
    let leaf2 = leaf_policy(&worlds[2], &signers);
    let graph_nodes = [
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[0],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf0,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[1],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf1,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[2],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf2,
        },
    ];
    let edges = graph_edges();
    let published = published();
    let incidents = incidents();
    let policy = OperatorComponentGraphAdmissionPolicy::new(
        role(),
        4,
        "c76-chain",
        ProfileIdentity::PROFILE_1_ASYNC,
        &graph_nodes,
        &edges,
        &[],
        &[],
        &published,
        ComponentGraphNodeReplacementPolicy {
            target: node(1),
            max_replacements: 1,
            node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
            incident_edges: &incidents,
        },
        &signers,
    )
    .unwrap();
    test(&worlds, &policy)
}

fn artifacts_for(
    wats: [&str; 3],
    worlds: &[WorldContract; 3],
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Vec<ComponentArtifactV1> {
    wats.into_iter()
        .enumerate()
        .map(|(index, wat)| artifact(wat, &worlds[index], policy.nodes()[index].artifact))
        .collect()
}

fn evidence_for(
    artifacts: &[ComponentArtifactV1],
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> Vec<ComponentArtifactAuthenticationEvidenceV1> {
    artifacts
        .iter()
        .enumerate()
        .map(|(index, artifact)| leaf_evidence(artifact, policy.nodes()[index].artifact))
        .collect()
}

fn fresh(
    bundle: ComponentGraphVersionBundleV1,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> vibeos_component_admission::FreshAuthenticatedComponentGraphVersion {
    admit_authenticated_component_graph_version(
        authenticate_component_graph_version(bundle, policy).unwrap(),
        policy,
        &CallerAuthority { offers: &[] },
    )
    .unwrap()
}

#[test]
fn complete_graph_and_leaf_authentication_admits_exact_g0_g1_replacement() {
    let worlds = WORLDS.map(|world| WorldContract::parse(WIT, world).unwrap());
    let signers = [signer_policy()];
    let leaf0 = leaf_policy(&worlds[0], &signers);
    let leaf1 = leaf_policy(&worlds[1], &signers);
    let leaf2 = leaf_policy(&worlds[2], &signers);
    let graph_nodes = [
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[0],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf0,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[1],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf1,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[2],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf2,
        },
    ];
    let edges = graph_edges();
    let published = published();
    let incidents = incidents();
    let replacement = ComponentGraphNodeReplacementPolicy {
        target: node(1),
        max_replacements: 1,
        node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
        incident_edges: &incidents,
    };
    let policy = OperatorComponentGraphAdmissionPolicy::new(
        role(),
        4,
        "c76-chain",
        ProfileIdentity::PROFILE_1_ASYNC,
        &graph_nodes,
        &edges,
        &[],
        &[],
        &published,
        replacement,
        &signers,
    )
    .unwrap();

    let current_artifacts = vec![
        artifact(SOURCE, &worlds[0], &leaf0),
        artifact(RELAY, &worlds[1], &leaf1),
        artifact(SINK, &worlds[2], &leaf2),
    ];
    let current_evidence = vec![
        leaf_evidence(&current_artifacts[0], &leaf0),
        leaf_evidence(&current_artifacts[1], &leaf1),
        leaf_evidence(&current_artifacts[2], &leaf2),
    ];
    let current_admitted = image_admit(&current_artifacts, &worlds);
    let current_bundle = bundle(
        0,
        None,
        current_artifacts,
        current_evidence,
        &current_admitted,
        &policy,
    );
    let current_commitment = current_bundle.descriptor().version_commitment().unwrap();
    let authenticated = authenticate_component_graph_version(current_bundle, &policy).unwrap();
    assert!(!authenticated.runtime_ready());
    assert_eq!(authenticated.receipt().ordinal(), 0);
    let current = admit_authenticated_component_graph_version(
        authenticated,
        &policy,
        &CallerAuthority { offers: &[] },
    )
    .unwrap();

    let successor_artifacts = vec![
        artifact(SOURCE, &worlds[0], &leaf0),
        artifact(RELAY_V2, &worlds[1], &leaf1),
        artifact(SINK, &worlds[2], &leaf2),
    ];
    let successor_evidence = vec![
        leaf_evidence(&successor_artifacts[0], &leaf0),
        leaf_evidence(&successor_artifacts[1], &leaf1),
        leaf_evidence(&successor_artifacts[2], &leaf2),
    ];
    let successor_admitted = image_admit(&successor_artifacts, &worlds);
    let successor_bundle = bundle(
        1,
        Some(current_commitment),
        successor_artifacts,
        successor_evidence,
        &successor_admitted,
        &policy,
    );
    let successor = admit_authenticated_component_graph_version(
        authenticate_component_graph_version(successor_bundle, &policy).unwrap(),
        &policy,
        &CallerAuthority { offers: &[] },
    )
    .unwrap();

    let replacement =
        admit_authenticated_component_graph_replacement(current, successor, &policy).unwrap();
    assert!(!replacement.runtime_ready());
    assert_eq!(replacement.current_receipt().ordinal(), 0);
    assert_eq!(replacement.successor_receipt().ordinal(), 1);
    assert_eq!(
        replacement.admitted_replacement().manifest().node_action(),
        ComponentGraphReplacementNodeAction::PolicyCancel
    );
    assert!(replacement
        .admitted_replacement()
        .manifest()
        .incident_edges()
        .iter()
        .all(|edge| edge.action == ComponentGraphReplacementEdgeAction::RecreateFresh));
}

#[test]
fn graph_leaf_signatures_and_fresh_semantic_facts_fail_closed() {
    with_graph_policy(|worlds, policy| {
        let artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
        let evidence = evidence_for(&artifacts, policy);
        let admitted = image_admit(&artifacts, worlds);
        let valid = bundle(0, None, artifacts, evidence, &admitted, policy);
        let (descriptor, artifacts, evidence, graph_evidence) = valid.into_parts();
        let public = graph_evidence.public_key().to_bytes();
        let mut signature = *graph_evidence.signature().as_bytes();
        signature[0] ^= 0x80;
        let bad_graph_evidence =
            ComponentGraphVersionAuthenticationEvidenceV1::new(public, signature).unwrap();
        let bad_graph =
            ComponentGraphVersionBundleV1::new(descriptor, artifacts, evidence, bad_graph_evidence)
                .unwrap();
        assert!(matches!(
            authenticate_component_graph_version(bad_graph, policy),
            Err(ComponentGraphAuthenticationError::InvalidSignature)
        ));

        for corrupt_node in 0..3 {
            let artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
            let mut evidence = evidence_for(&artifacts, policy);
            let public = evidence[corrupt_node].public_key().to_bytes();
            let mut signature = *evidence[corrupt_node].signature().as_bytes();
            signature[0] ^= 1 << corrupt_node;
            evidence[corrupt_node] =
                ComponentArtifactAuthenticationEvidenceV1::new(public, signature).unwrap();
            let admitted = image_admit(&artifacts, worlds);
            let signed_graph = bundle(0, None, artifacts, evidence, &admitted, policy);
            assert!(matches!(
                authenticate_component_graph_version(signed_graph, policy),
                Err(ComponentGraphAuthenticationError::LeafAuthentication {
                    node: failed_node,
                    error: ArtifactAuthenticationError::InvalidSignature,
                }) if failed_node == node(corrupt_node as u16)
            ));
        }

        let mut artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
        artifacts[0] = artifact_bytes_with_manifest(
            artifacts[0].component_bytes(),
            &worlds[0],
            policy.nodes()[0].artifact,
            true,
        );
        let evidence = evidence_for(&artifacts, policy);
        let admitted = image_admit(&artifacts, worlds);
        let signed_graph = bundle(0, None, artifacts, evidence, &admitted, policy);
        let authenticated = authenticate_component_graph_version(signed_graph, policy).unwrap();
        assert!(matches!(
            admit_authenticated_component_graph_version(
                authenticated,
                policy,
                &CallerAuthority { offers: &[] },
            ),
            Err(ComponentGraphAuthenticationError::LeafFreshAdmission {
                node: failed_node,
                error: AuthenticatedAdmissionError::Authentication(
                    ArtifactAuthenticationError::ArtifactConfiguration,
                ),
            }) if failed_node == node(0)
        ));

        for mutation in [
            DescriptorMutation::NodeWorldContract { node: 0 },
            DescriptorMutation::NodeCoreInstancesBudget { node: 1 },
            DescriptorMutation::AsyncFunctions { edge: 1 },
        ] {
            let artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
            let evidence = evidence_for(&artifacts, policy);
            let admitted = image_admit(&artifacts, worlds);
            let signed_graph =
                bundle_with_mutation(0, None, artifacts, evidence, &admitted, policy, mutation);
            let authenticated = authenticate_component_graph_version(signed_graph, policy).unwrap();
            assert!(matches!(
                admit_authenticated_component_graph_version(
                    authenticated,
                    policy,
                    &CallerAuthority { offers: &[] },
                ),
                Err(ComponentGraphAuthenticationError::DescriptorAdmissionMismatch)
            ));
        }
    });
}

#[test]
fn replacement_rejects_wrong_predecessor_and_changed_stable_sibling() {
    with_graph_policy(|worlds, policy| {
        let current_artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
        let current_evidence = evidence_for(&current_artifacts, policy);
        let current_admitted = image_admit(&current_artifacts, worlds);
        let current = fresh(
            bundle(
                0,
                None,
                current_artifacts,
                current_evidence,
                &current_admitted,
                policy,
            ),
            policy,
        );
        let successor_artifacts = artifacts_for([SOURCE, RELAY_V2, SINK], worlds, policy);
        let successor_evidence = evidence_for(&successor_artifacts, policy);
        let successor_admitted = image_admit(&successor_artifacts, worlds);
        let wrong_predecessor = ComponentGraphVersionCommitment::from_bytes([0x33; 32]).unwrap();
        let successor = fresh(
            bundle(
                1,
                Some(wrong_predecessor),
                successor_artifacts,
                successor_evidence,
                &successor_admitted,
                policy,
            ),
            policy,
        );
        assert!(matches!(
            admit_authenticated_component_graph_replacement(current, successor, policy),
            Err(ComponentGraphAuthenticationError::VersionRelation)
        ));

        let current_artifacts = artifacts_for([SOURCE, RELAY, SINK], worlds, policy);
        let current_evidence = evidence_for(&current_artifacts, policy);
        let current_admitted = image_admit(&current_artifacts, worlds);
        let current_bundle = bundle(
            0,
            None,
            current_artifacts,
            current_evidence,
            &current_admitted,
            policy,
        );
        let current_commitment = current_bundle.descriptor().version_commitment().unwrap();
        let current = fresh(current_bundle, policy);

        let mut source_bytes = wat::parse_str(SOURCE).unwrap();
        source_bytes.extend_from_slice(&[0, 4, 3, b'c', b'7', b'6']);
        let successor_artifacts = vec![
            artifact_bytes(&source_bytes, &worlds[0], policy.nodes()[0].artifact),
            artifact(RELAY_V2, &worlds[1], policy.nodes()[1].artifact),
            artifact(SINK, &worlds[2], policy.nodes()[2].artifact),
        ];
        let successor_evidence = evidence_for(&successor_artifacts, policy);
        let successor_admitted = image_admit(&successor_artifacts, worlds);
        let successor = fresh(
            bundle(
                1,
                Some(current_commitment),
                successor_artifacts,
                successor_evidence,
                &successor_admitted,
                policy,
            ),
            policy,
        );
        assert!(matches!(
            admit_authenticated_component_graph_replacement(current, successor, policy),
            Err(ComponentGraphAuthenticationError::VersionRelation)
        ));
    });
}

#[test]
fn graph_policy_rejects_wrong_fixed_c76_shape() {
    let worlds = WORLDS.map(|world| WorldContract::parse(WIT, world).unwrap());
    let signers = [signer_policy()];
    let leaf0 = leaf_policy(&worlds[0], &signers);
    let leaf1 = leaf_policy(&worlds[1], &signers);
    let leaf2 = leaf_policy(&worlds[2], &signers);
    let nodes = [
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[0],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf0,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[1],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf1,
        },
        OperatorComponentGraphNodeAdmissionPolicy {
            label: LABELS[2],
            nesting: ComponentGraphNesting::Root,
            artifact: &leaf2,
        },
    ];
    let edges = graph_edges();
    let incidents = incidents();
    assert!(matches!(
        OperatorComponentGraphAdmissionPolicy::new(
            role(),
            4,
            "c76-chain",
            ProfileIdentity::PROFILE_1_ASYNC,
            &nodes,
            &edges[..1],
            &[],
            &[],
            &published(),
            ComponentGraphNodeReplacementPolicy {
                target: node(1),
                max_replacements: 1,
                node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
                incident_edges: &incidents,
            },
            &signers,
        ),
        Err(ComponentGraphAuthenticationError::InvalidPolicy)
    ));
    assert!(matches!(
        OperatorComponentGraphAdmissionPolicy::new(
            role(),
            4,
            "c76-chain",
            ProfileIdentity::PROFILE_1_SYNC,
            &nodes,
            &edges,
            &[],
            &[],
            &published(),
            ComponentGraphNodeReplacementPolicy {
                target: node(1),
                max_replacements: 1,
                node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
                incident_edges: &incidents,
            },
            &signers,
        ),
        Err(ComponentGraphAuthenticationError::InvalidPolicy)
    ));
}
