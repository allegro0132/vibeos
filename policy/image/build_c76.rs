use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use vibeos_component_admission::{
    admit_authenticated_component_graph_replacement, admit_authenticated_component_graph_version,
    admit_component_graph, authenticate_component_graph_version, canonical_entity_shape_text_v1,
    ArtifactTrust, CallerAuthority, CommandStreamMode, ComponentArtifact,
    ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy,
    ComponentGraphNodeReplacementPolicy, ComponentGraphReplacementEdgeAction,
    ComponentGraphReplacementEdgePolicy, ComponentGraphReplacementNodeAction, InstanceLimits,
    OperatorArtifactAdmissionPolicy, OperatorComponentGraphAdmissionPolicy,
    OperatorComponentGraphNodeAdmissionPolicy, OperatorRoleIdentity, OperatorSignerStatus,
    OperatorSignerV1,
};
use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceCommitment, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactInstanceLimitsV1,
    ComponentArtifactInterfaceDirection, ComponentArtifactInterfaceV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ComponentArtifactWitPackageV1,
    ComponentGraphVersionAsyncEdgeV1, ComponentGraphVersionAuthenticationEvidenceV1,
    ComponentGraphVersionBundleV1, ComponentGraphVersionCommitment,
    ComponentGraphVersionComponentIdentity, ComponentGraphVersionEdgeV1,
    ComponentGraphVersionEndpointV1, ComponentGraphVersionIncidentEdgeActionV1,
    ComponentGraphVersionIncidentEdgeV1, ComponentGraphVersionNodeNestingV1,
    ComponentGraphVersionNodeV1, ComponentGraphVersionPolicyDigest,
    ComponentGraphVersionPublishedExportV1, ComponentGraphVersionReplacementV1,
    ComponentGraphVersionRetirementActionV1, ComponentGraphVersionV1,
    ComponentGraphVersionWorldContractCommitment, ProfileIdentity,
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

const VECTOR_MAGIC: &str = "VIBEOS-C76-GRAPH-VERSION-REPLACEMENT-V1";
const VECTOR_SOURCE: &str = include_str!("artifacts/c76-graph-version-replacement.vectors");
const WIT: &str = include_str!("artifacts/c65-async-chain.wit");
const SOURCE: &str = include_str!("artifacts/c65-async-source.component.wat");
const RELAY_G0: &str = include_str!("artifacts/c65-async-relay.component.wat");
const RELAY_G1: &str = include_str!("artifacts/c66-async-relay-v2.component.wat");
const SINK: &str = include_str!("artifacts/c65-async-sink.component.wat");

const POLICY_GENERATION: u64 = 1;
const GRAPH_NAME: &str = "c76-chain";
// Hand-reviewed trust root. The public vector is evidence under this key; it
// is never allowed to select or replace the policy key itself.
const ACTIVE_PUBLIC_KEY: [u8; 32] = [
    0x1d, 0xfa, 0xeb, 0x2e, 0x9d, 0x9f, 0xf3, 0xd5, 0xc4, 0xeb, 0x7f, 0x81, 0xa1, 0x19, 0x7d, 0xd0,
    0x9f, 0x8a, 0x30, 0x1a, 0x5a, 0x31, 0xb6, 0xed, 0x15, 0x92, 0x1e, 0x93, 0x95, 0x74, 0x15, 0x4f,
];
const LABELS: [&str; 3] = ["source", "relay", "sink"];
const WORLDS: [&str; 3] = [
    "test:c65-chain/source@1.0.0",
    "test:c65-chain/relay@1.0.0",
    "test:c65-chain/sink@1.0.0",
];
const VECTOR_FILE_NAMES: [&str; 17] = [
    "active_public_key",
    "g0_descriptor",
    "g0_artifact_0",
    "g0_artifact_1",
    "g0_artifact_2",
    "g0_evidence_0",
    "g0_evidence_1",
    "g0_evidence_2",
    "g0_graph_evidence",
    "g1_descriptor",
    "g1_artifact_0",
    "g1_artifact_1",
    "g1_artifact_2",
    "g1_evidence_0",
    "g1_evidence_1",
    "g1_evidence_2",
    "g1_graph_evidence",
];
const EXPECTED_VECTOR_NAMES: [&str; 17] = [
    "active_public_key",
    "g0_artifact_0",
    "g0_artifact_1",
    "g0_artifact_2",
    "g0_descriptor",
    "g0_evidence_0",
    "g0_evidence_1",
    "g0_evidence_2",
    "g0_graph_evidence",
    "g1_artifact_0",
    "g1_artifact_1",
    "g1_artifact_2",
    "g1_descriptor",
    "g1_evidence_0",
    "g1_evidence_1",
    "g1_evidence_2",
    "g1_graph_evidence",
];

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

fn published_exports() -> [ComponentGraphPublishedExportSpec; 1] {
    [ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(node(2), entity(0)),
    )]
}

fn incident_edges() -> [ComponentGraphReplacementEdgePolicy; 2] {
    graph_edges().map(|edge| ComponentGraphReplacementEdgePolicy {
        edge,
        action: ComponentGraphReplacementEdgeAction::RecreateFresh,
    })
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 1_000,
        poll_quantum: 100,
        resources: 8,
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
    .expect("C7.6 instance limits are canonical")
}

fn operator_role() -> OperatorRoleIdentity {
    OperatorRoleIdentity::from_bytes(
        Sha256::digest(b"vibeos.c76.acceptance.operator-role.v1\0").into(),
    )
    .expect("C7.6 operator role is nonzero")
}

fn with_policy<R>(
    public_key: [u8; 32],
    action: impl FnOnce(&[WorldContract; 3], &OperatorComponentGraphAdmissionPolicy<'_>) -> R,
) -> R {
    let worlds = WORLDS.map(|world| {
        WorldContract::parse(WIT, world).expect("pinned C7.6 WIT and world must parse")
    });
    let signers = [
        OperatorSignerV1::new(public_key, OperatorSignerStatus::Active)
            .expect("C7.6 public key must be a canonical strong Ed25519 point"),
    ];
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
    let published = published_exports();
    let incidents = incident_edges();
    let policy = OperatorComponentGraphAdmissionPolicy::new(
        operator_role(),
        POLICY_GENERATION,
        GRAPH_NAME,
        ProfileIdentity::PROFILE_1_ASYNC,
        &nodes,
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
    .expect("fixed C7.6 operator graph policy must remain valid");
    action(&worlds, &policy)
}

fn leaf_policy<'a>(
    world: &'a WorldContract,
    signers: &'a [OperatorSignerV1],
) -> OperatorArtifactAdmissionPolicy<'a> {
    OperatorArtifactAdmissionPolicy::new(
        operator_role(),
        POLICY_GENERATION,
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
    .expect("fixed C7.6 leaf policy must remain valid")
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
    component: &[u8],
    world: &WorldContract,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> ComponentArtifactV1 {
    let plan = inspect_component_for_profile(component, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("pinned C7.6 Component must pass the current validation engine");
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
                    &canonical_entity_shape_text_v1(&entity.entity)
                        .expect("C7.6 entity shape must be canonical"),
                )
                .expect("C7.6 interface manifest entry must be bounded"),
            );
        }
    }
    let core_modules = plan
        .embedded_modules()
        .iter()
        .map(|bytes| {
            ComponentArtifactCoreModuleV1::from_bytes(bytes)
                .expect("C7.6 embedded Core module must be bounded")
        })
        .collect();
    let manifest = ComponentArtifactManifestV1::new(
        &world.identity,
        vec![
            ComponentArtifactWitPackageV1::new("test:c65-chain", "1.0.0", WIT)
                .expect("C7.6 WIT package must be canonical"),
        ],
        interfaces,
        core_modules,
        vec![],
    )
    .expect("C7.6 artifact manifest must be canonical");
    ComponentArtifactV1::new(
        component,
        ProfileIdentity::PROFILE_1_ASYNC,
        format_limits(),
        ComponentArtifactSignerPolicyV1::operator_required(
            *policy
                .commitment()
                .expect("C7.6 leaf policy commitment must exist")
                .as_bytes(),
        )
        .expect("C7.6 operator signer policy digest must be nonzero"),
        manifest,
    )
    .expect("C7.6 canonical artifact must build")
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
            .expect("C7.6 Component must pass a fresh current-engine copy")
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
    let published = published_exports();
    admit_component_graph(
        components,
        &ComponentGraphAdmissionPolicy {
            name: GRAPH_NAME,
            profile: ProfileIdentity::PROFILE_1_ASYNC,
            nodes: &nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        },
        &CallerAuthority { offers: &[] },
    )
    .expect("fixed C7.6 graph must pass current atomic admission")
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

fn descriptor(
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    artifacts: &[ComponentArtifactV1],
    evidence: &[ComponentArtifactAuthenticationEvidenceV1],
    admitted: &vibeos_component_admission::AdmittedComponentGraph,
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
) -> ComponentGraphVersionV1 {
    let nodes = artifacts
        .iter()
        .zip(evidence)
        .zip(admitted.manifest().nodes())
        .enumerate()
        .map(|(index, ((artifact, evidence), admitted_node))| {
            ComponentGraphVersionNodeV1::new(
                index as u16,
                LABELS[index],
                WORLDS[index],
                ComponentGraphVersionNodeNestingV1::Root,
                artifact
                    .encode()
                    .expect("C7.6 artifact must re-encode")
                    .len() as u64,
                artifact
                    .artifact_commitment()
                    .expect("C7.6 artifact commitment must exist"),
                ComponentArtifactAuthenticationEvidenceCommitment::from_evidence(evidence)
                    .expect("C7.6 leaf evidence commitment must exist"),
                artifact.signer_policy().policy_digest(),
                ComponentGraphVersionComponentIdentity::from_component_bytes(
                    artifact.component_bytes(),
                )
                .expect("C7.6 component identity must be nonzero"),
                ComponentGraphVersionWorldContractCommitment::from_bytes(
                    admitted_node.world_contract_commitment(),
                )
                .expect("C7.6 world commitment must be nonzero"),
                artifact.instance_limits(),
                admitted_node.budget(),
            )
            .expect("C7.6 descriptor node must be canonical")
        })
        .collect();
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
        .map(|edge| {
            ComponentGraphVersionAsyncEdgeV1::new(
                format_edge(edge.edge()),
                edge.async_functions(),
                edge.streams(),
                edge.futures(),
            )
            .expect("C7.6 async-edge account must be canonical")
        })
        .collect();
    let incidents = policy
        .replacement()
        .incident_edges
        .iter()
        .map(|incident| {
            assert_eq!(
                incident.action,
                ComponentGraphReplacementEdgeAction::RecreateFresh
            );
            ComponentGraphVersionIncidentEdgeV1::new(
                format_edge(incident.edge),
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )
        })
        .collect();
    ComponentGraphVersionV1::new(
        GRAPH_NAME,
        ProfileIdentity::PROFILE_1_ASYNC,
        ordinal,
        predecessor,
        ComponentGraphVersionPolicyDigest::from_bytes(
            *policy
                .commitment()
                .expect("C7.6 graph policy commitment must exist")
                .as_bytes(),
        )
        .expect("C7.6 graph policy digest must be nonzero"),
        admitted.manifest().account(),
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
        .expect("C7.6 replacement policy must be canonical"),
    )
    .expect("C7.6 descriptor must be canonical")
}

fn decode_hex(name: &str, encoded: &str) -> Vec<u8> {
    assert!(
        !encoded.is_empty() && encoded.len().is_multiple_of(2),
        "C7.6 vector `{name}` has an empty or odd-length payload"
    );
    assert!(
        encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "C7.6 vector `{name}` is not canonical lowercase hex"
    );
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                core::str::from_utf8(pair).expect("C7.6 hex must be ASCII"),
                16,
            )
            .expect("C7.6 hex pair must be valid")
        })
        .collect()
}

fn vectors() -> BTreeMap<&'static str, Vec<u8>> {
    let mut lines = VECTOR_SOURCE.lines();
    assert_eq!(
        lines.next(),
        Some(VECTOR_MAGIC),
        "C7.6 vector magic changed"
    );
    let mut vectors = BTreeMap::new();
    let mut observed_names = Vec::new();
    for line in lines {
        assert!(!line.is_empty(), "C7.6 vector contains an empty line");
        let (name, encoded) = line
            .split_once('=')
            .expect("C7.6 vector line must be one assignment");
        assert!(!encoded.contains('='), "C7.6 vector has two assignments");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "C7.6 vector name is outside the closed schema"
        );
        assert!(
            vectors.insert(name, decode_hex(name, encoded)).is_none(),
            "duplicate C7.6 vector `{name}`"
        );
        observed_names.push(name);
    }
    assert_eq!(
        observed_names, VECTOR_FILE_NAMES,
        "C7.6 vector field order is not the exact public ABI"
    );
    assert_eq!(
        vectors.keys().copied().collect::<Vec<_>>(),
        EXPECTED_VECTOR_NAMES,
        "C7.6 vector schema is not exact"
    );
    vectors
}

fn decode_leaf_evidence(bytes: &[u8]) -> ComponentArtifactAuthenticationEvidenceV1 {
    ComponentArtifactAuthenticationEvidenceV1::decode(bytes)
        .expect("checked C7.6 leaf evidence must decode canonically")
}

fn decode_graph_evidence(bytes: &[u8]) -> ComponentGraphVersionAuthenticationEvidenceV1 {
    ComponentGraphVersionAuthenticationEvidenceV1::decode(bytes)
        .expect("checked C7.6 graph evidence must decode canonically")
}

fn strict_graph_signature_verifies(
    policy: &OperatorComponentGraphAdmissionPolicy<'_>,
    descriptor: &ComponentGraphVersionV1,
    evidence: &ComponentGraphVersionAuthenticationEvidenceV1,
) -> bool {
    let public_key = evidence.public_key().to_bytes();
    let transcript = policy
        .signature_transcript(descriptor, public_key)
        .expect("checked C7.6 graph transcript must reproduce");
    let key = VerifyingKey::from_bytes(&public_key)
        .expect("checked C7.6 public key must decode as Ed25519");
    let signature = Signature::from_bytes(evidence.signature().as_bytes());
    key.verify_strict(&transcript, &signature).is_ok()
}

pub fn write_fixture(output: &Path) {
    let vectors = vectors();
    let vector = |name: &str| {
        vectors
            .get(name)
            .unwrap_or_else(|| panic!("missing checked C7.6 vector `{name}`"))
    };
    let vector_public_key: [u8; 32] = vector("active_public_key")
        .as_slice()
        .try_into()
        .expect("C7.6 active public key must be 32 bytes");
    assert_eq!(
        vector_public_key, ACTIVE_PUBLIC_KEY,
        "C7.6 vector cannot select the hand-reviewed active signer"
    );
    let public_key = ACTIVE_PUBLIC_KEY;

    with_policy(public_key, |worlds, policy| {
        let component_source =
            wat::parse_str(SOURCE).expect("pinned C7.6 source Component WAT must parse");
        let component_relay_g0 =
            wat::parse_str(RELAY_G0).expect("pinned C7.6 G0 relay Component WAT must parse");
        let component_relay_g1 =
            wat::parse_str(RELAY_G1).expect("pinned C7.6 G1 relay Component WAT must parse");
        let component_sink =
            wat::parse_str(SINK).expect("pinned C7.6 sink Component WAT must parse");
        assert_ne!(component_relay_g0, component_relay_g1);

        let source = artifact(&component_source, &worlds[0], policy.nodes()[0].artifact);
        let relay_g0 = artifact(&component_relay_g0, &worlds[1], policy.nodes()[1].artifact);
        let relay_g1 = artifact(&component_relay_g1, &worlds[1], policy.nodes()[1].artifact);
        let sink = artifact(&component_sink, &worlds[2], policy.nodes()[2].artifact);
        let artifact_bytes = [
            source.encode().expect("C7.6 source CMP1 must encode"),
            relay_g0.encode().expect("C7.6 G0 relay CMP1 must encode"),
            relay_g1.encode().expect("C7.6 G1 relay CMP1 must encode"),
            sink.encode().expect("C7.6 sink CMP1 must encode"),
        ];
        for (name, generated) in [
            ("g0_artifact_0", &artifact_bytes[0]),
            ("g0_artifact_1", &artifact_bytes[1]),
            ("g0_artifact_2", &artifact_bytes[3]),
            ("g1_artifact_0", &artifact_bytes[0]),
            ("g1_artifact_1", &artifact_bytes[2]),
            ("g1_artifact_2", &artifact_bytes[3]),
        ] {
            assert_eq!(
                generated,
                vector(name),
                "C7.6 unsigned canonical artifact `{name}` changed"
            );
        }

        let g0_evidence_array = [
            decode_leaf_evidence(vector("g0_evidence_0")),
            decode_leaf_evidence(vector("g0_evidence_1")),
            decode_leaf_evidence(vector("g0_evidence_2")),
        ];
        let g1_evidence_array = [
            decode_leaf_evidence(vector("g1_evidence_0")),
            decode_leaf_evidence(vector("g1_evidence_1")),
            decode_leaf_evidence(vector("g1_evidence_2")),
        ];
        assert_eq!(vector("g0_artifact_0"), vector("g1_artifact_0"));
        assert_eq!(vector("g0_artifact_2"), vector("g1_artifact_2"));
        assert_eq!(vector("g0_evidence_0"), vector("g1_evidence_0"));
        assert_eq!(vector("g0_evidence_2"), vector("g1_evidence_2"));
        assert_ne!(vector("g0_artifact_1"), vector("g1_artifact_1"));
        let g0_artifacts = vec![source, relay_g0, sink];
        let g0_evidence = g0_evidence_array.to_vec();
        let g0_admitted = image_admit(&g0_artifacts, worlds);
        let g0_descriptor = descriptor(0, None, &g0_artifacts, &g0_evidence, &g0_admitted, policy);
        let g0_descriptor_bytes = g0_descriptor
            .encode()
            .expect("C7.6 G0 descriptor must encode");
        assert_eq!(
            g0_descriptor_bytes,
            *vector("g0_descriptor"),
            "C7.6 unsigned canonical G0 descriptor changed"
        );
        let g0_commitment = g0_descriptor
            .version_commitment()
            .expect("C7.6 G0 commitment must exist");
        let g0_graph_evidence = decode_graph_evidence(vector("g0_graph_evidence"));
        assert!(strict_graph_signature_verifies(
            policy,
            &g0_descriptor,
            &g0_graph_evidence
        ));
        let g0_bundle = ComponentGraphVersionBundleV1::new(
            g0_descriptor,
            g0_artifacts,
            g0_evidence,
            g0_graph_evidence,
        )
        .expect("C7.6 G0 bundle must bind exactly 3 CMP1 + 3 CME1 + CGE1");
        let g0 = admit_authenticated_component_graph_version(
            authenticate_component_graph_version(g0_bundle, policy)
                .expect("C7.6 G0 complete operator authentication must pass"),
            policy,
            &CallerAuthority { offers: &[] },
        )
        .expect("C7.6 G0 must pass all current semantic engines");
        assert!(!g0.runtime_ready());

        let g1_artifacts = vec![
            ComponentArtifactV1::decode(&artifact_bytes[0])
                .expect("checked C7.6 source artifact must decode"),
            relay_g1,
            ComponentArtifactV1::decode(&artifact_bytes[3])
                .expect("checked C7.6 sink artifact must decode"),
        ];
        let g1_evidence = g1_evidence_array.to_vec();
        let g1_admitted = image_admit(&g1_artifacts, worlds);
        let g1_descriptor = descriptor(
            1,
            Some(g0_commitment),
            &g1_artifacts,
            &g1_evidence,
            &g1_admitted,
            policy,
        );
        let g1_descriptor_bytes = g1_descriptor
            .encode()
            .expect("C7.6 G1 descriptor must encode");
        assert_eq!(
            g1_descriptor_bytes,
            *vector("g1_descriptor"),
            "C7.6 unsigned canonical G1 descriptor changed"
        );
        let g1_graph_evidence = decode_graph_evidence(vector("g1_graph_evidence"));
        assert!(strict_graph_signature_verifies(
            policy,
            &g1_descriptor,
            &g1_graph_evidence
        ));
        let g1_bundle = ComponentGraphVersionBundleV1::new(
            g1_descriptor,
            g1_artifacts,
            g1_evidence,
            g1_graph_evidence,
        )
        .expect("C7.6 G1 bundle must bind exactly 3 CMP1 + 3 CME1 + CGE1");
        let g1 = admit_authenticated_component_graph_version(
            authenticate_component_graph_version(g1_bundle, policy)
                .expect("C7.6 G1 complete operator authentication must pass"),
            policy,
            &CallerAuthority { offers: &[] },
        )
        .expect("C7.6 G1 must pass all current semantic engines");
        assert!(!g1.runtime_ready());
        let replacement = admit_authenticated_component_graph_replacement(g0, g1, policy)
            .expect("C7.6 must admit only the exact G0 -> G1 replacement");
        assert!(!replacement.runtime_ready());
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

        for version in ["g0", "g1"] {
            for index in 0..3 {
                fs::write(
                    output.join(format!("c76-{version}-artifact-{index}.artifact")),
                    vector(&format!("{version}_artifact_{index}")),
                )
                .expect("write checked C7.6 version-local artifact");
                fs::write(
                    output.join(format!("c76-{version}-evidence-{index}.evidence")),
                    vector(&format!("{version}_evidence_{index}")),
                )
                .expect("write checked C7.6 version-local leaf evidence");
            }
        }
        for (name, descriptor, graph_evidence) in [
            (
                "g0",
                g0_descriptor_bytes.as_slice(),
                vector("g0_graph_evidence").as_slice(),
            ),
            (
                "g1",
                g1_descriptor_bytes.as_slice(),
                vector("g1_graph_evidence").as_slice(),
            ),
        ] {
            fs::write(output.join(format!("c76-{name}.descriptor")), descriptor)
                .expect("write checked C7.6 graph descriptor");
            fs::write(
                output.join(format!("c76-{name}-graph.evidence")),
                graph_evidence,
            )
            .expect("write checked C7.6 graph evidence");
        }
        fs::write(
            output.join("c76-operator-role.rs"),
            format!("{:?}", *operator_role().as_bytes()),
        )
        .expect("write checked C7.6 operator role");
    });
}
