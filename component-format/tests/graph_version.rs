use vibeos_component_format::{
    ComponentArtifactAuthenticationEvidenceCommitment, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactInstanceLimitsV1, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyV1, ComponentArtifactV1, ComponentArtifactWitPackageV1,
    ComponentGraphAccount, ComponentGraphNodeBudget, ComponentGraphVersionAsyncEdgeV1,
    ComponentGraphVersionAuthenticationEvidenceV1, ComponentGraphVersionBundleV1,
    ComponentGraphVersionCommitment, ComponentGraphVersionComponentIdentity,
    ComponentGraphVersionEdgeV1, ComponentGraphVersionEndpointV1, ComponentGraphVersionError,
    ComponentGraphVersionIncidentEdgeActionV1, ComponentGraphVersionIncidentEdgeV1,
    ComponentGraphVersionNodeNestingV1, ComponentGraphVersionNodeV1,
    ComponentGraphVersionPolicyDigest, ComponentGraphVersionPublishedExportV1,
    ComponentGraphVersionReplacementV1, ComponentGraphVersionRetirementActionV1,
    ComponentGraphVersionV1, ComponentGraphVersionWorldContractCommitment, ProfileIdentity,
    C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT, C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT,
    C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS, C76_COMPONENT_GRAPH_VERSION_NODE_COUNT,
    C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT, C76_COMPONENT_GRAPH_VERSION_TARGET,
    COMPONENT_GRAPH_VERSION_FORMAT_VERSION, COMPONENT_GRAPH_VERSION_HASH_SHA256,
    COMPONENT_GRAPH_VERSION_HEADER_LEN, COMPONENT_GRAPH_VERSION_MAGIC,
    COMPONENT_GRAPH_VERSION_MANIFEST_VERSION, COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW,
    COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION, MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES,
};

const GRAPH_POLICY: [u8; 32] = [0x76; 32];
const WIT: &str = "package test:c76@1.0.0; world graph { export run: func(); }";

const FLAGS_OFFSET: usize = 12;
const OBJECT_KIND_OFFSET: usize = 16;
const HASH_ALGORITHM_OFFSET: usize = 20;
const MANIFEST_VERSION_OFFSET: usize = 22;
const SIGNER_POLICY_VERSION_OFFSET: usize = 24;
const PROFILE_CODE_OFFSET: usize = 26;
const PROFILE_STAGE_OFFSET: usize = 28;
const CYCLE_POLICY_OFFSET: usize = 30;
const ARTIFACT_ABI_OFFSET: usize = 32;
const COMPONENT_PROFILE_OFFSET: usize = 34;
const CORE_PROFILE_OFFSET: usize = 36;
const RUNTIME_ABI_OFFSET: usize = 38;
const CANONICAL_FEATURES_OFFSET: usize = 40;
const ORDINAL_OFFSET: usize = 48;
const TOTAL_LEN_OFFSET: usize = 56;
const BODY_LEN_OFFSET: usize = 64;
const NODE_COUNT_OFFSET: usize = 72;
const EDGE_COUNT_OFFSET: usize = 74;
const ASYNC_EDGE_COUNT_OFFSET: usize = 76;
const EXTERNAL_IMPORT_COUNT_OFFSET: usize = 78;
const PUBLISHED_EXPORT_COUNT_OFFSET: usize = 80;
const RESOURCE_EDGE_COUNT_OFFSET: usize = 82;
const GRANT_COUNT_OFFSET: usize = 84;
const INCIDENT_EDGE_COUNT_OFFSET: usize = 86;
const REPLACEMENT_TARGET_OFFSET: usize = 88;
const MAX_REPLACEMENTS_OFFSET: usize = 90;
const RETIREMENT_ACTION_OFFSET: usize = 92;
const HEADER_RESERVED0_OFFSET: usize = 94;
const PREDECESSOR_COMMITMENT_OFFSET: usize = 96;
const POLICY_DIGEST_OFFSET: usize = 128;
const MANIFEST_HASH_OFFSET: usize = 160;
const VERSION_COMMITMENT_OFFSET: usize = 192;
const HEADER_RESERVED1_OFFSET: usize = 224;

struct Fixture {
    descriptor: ComponentGraphVersionV1,
    artifacts: Vec<ComponentArtifactV1>,
    artifact_evidence: Vec<ComponentArtifactAuthenticationEvidenceV1>,
    graph_evidence: ComponentGraphVersionAuthenticationEvidenceV1,
}

fn endpoint(node: u16, entity: u16) -> ComponentGraphVersionEndpointV1 {
    ComponentGraphVersionEndpointV1::new(node, entity)
}

fn edges() -> Vec<ComponentGraphVersionEdgeV1> {
    vec![
        ComponentGraphVersionEdgeV1::new(endpoint(0, 0), endpoint(1, 0)),
        ComponentGraphVersionEdgeV1::new(endpoint(1, 1), endpoint(2, 0)),
    ]
}

fn async_edges(edges: &[ComponentGraphVersionEdgeV1]) -> Vec<ComponentGraphVersionAsyncEdgeV1> {
    edges
        .iter()
        .copied()
        .map(|edge| ComponentGraphVersionAsyncEdgeV1::new(edge, 1, 1, 1).unwrap())
        .collect()
}

fn limits() -> ComponentArtifactInstanceLimitsV1 {
    ComponentArtifactInstanceLimitsV1::new(65_536, 1_000, 100, 4).unwrap()
}

fn artifact(index: u8, target_seed: u8) -> ComponentArtifactV1 {
    let world = format!("test:c76/node-{index}@1.0.0");
    let manifest = ComponentArtifactManifestV1::new(
        &world,
        vec![ComponentArtifactWitPackageV1::new("test:c76", "1.0.0", WIT).unwrap()],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    let seed = if index == 1 { target_seed } else { index };
    let component = [0, b'a', b's', b'm', 0x0d, 0, 1, 0, index, seed];
    ComponentArtifactV1::new(
        &component,
        ProfileIdentity::PROFILE_1_ASYNC,
        limits(),
        ComponentArtifactSignerPolicyV1::operator_required([0xa0 + index; 32]).unwrap(),
        manifest,
    )
    .unwrap()
}

fn artifact_evidence(index: u8) -> ComponentArtifactAuthenticationEvidenceV1 {
    ComponentArtifactAuthenticationEvidenceV1::new([0x20 + index; 32], [0x80 + index; 64]).unwrap()
}

fn attachments(
    target_seed: u8,
) -> (
    Vec<ComponentArtifactV1>,
    Vec<ComponentArtifactAuthenticationEvidenceV1>,
    Vec<ComponentGraphVersionNodeV1>,
    ComponentGraphAccount,
) {
    let artifacts: Vec<_> = (0..3).map(|index| artifact(index, target_seed)).collect();
    let evidence: Vec<_> = (0..3).map(artifact_evidence).collect();
    let mut nodes = Vec::new();
    let mut account = ComponentGraphAccount::default();
    for (index, (artifact, evidence)) in artifacts.iter().zip(&evidence).enumerate() {
        let budget = ComponentGraphNodeBudget {
            component_bytes: artifact.component_bytes().len() as u64,
            core_instances: 0,
            adapters: artifact.manifest().adapters().len() as u64,
            resource_types: 0,
            resource_slots: limits().resources(),
            memory_bytes: limits().memory_bytes(),
            total_fuel: limits().total_fuel(),
            poll_quantum: limits().poll_quantum(),
        };
        account.charge_node(budget).unwrap();
        account.observe_nesting(1).unwrap();
        nodes.push(
            ComponentGraphVersionNodeV1::new(
                index as u16,
                &format!("node-{index}"),
                artifact.manifest().world(),
                ComponentGraphVersionNodeNestingV1::Root,
                artifact.encode().unwrap().len() as u64,
                artifact.artifact_commitment().unwrap(),
                ComponentArtifactAuthenticationEvidenceCommitment::from_evidence(evidence).unwrap(),
                artifact.signer_policy().policy_digest(),
                ComponentGraphVersionComponentIdentity::from_component_bytes(
                    artifact.component_bytes(),
                )
                .unwrap(),
                ComponentGraphVersionWorldContractCommitment::from_bytes([0xd0 + index as u8; 32])
                    .unwrap(),
                artifact.instance_limits(),
                budget,
            )
            .unwrap(),
        );
    }
    account.charge_edges(2).unwrap();
    account.charge_published_exports(1).unwrap();
    (artifacts, evidence, nodes, account)
}

fn descriptor(
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    target_seed: u8,
    reverse_inputs: bool,
    omit_second_async: bool,
) -> (
    ComponentGraphVersionV1,
    Vec<ComponentArtifactV1>,
    Vec<ComponentArtifactAuthenticationEvidenceV1>,
) {
    let (artifacts, evidence, mut nodes, account) = attachments(target_seed);
    let mut graph_edges = edges();
    let mut graph_async_edges = async_edges(&graph_edges);
    let mut incidents: Vec<_> = graph_edges
        .iter()
        .copied()
        .map(|edge| {
            ComponentGraphVersionIncidentEdgeV1::new(
                edge,
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )
        })
        .collect();
    if omit_second_async {
        graph_async_edges.pop();
    }
    if reverse_inputs {
        nodes.reverse();
        graph_edges.reverse();
        graph_async_edges.reverse();
        incidents.reverse();
    }
    let replacement = ComponentGraphVersionReplacementV1::new(
        1,
        1,
        ComponentGraphVersionRetirementActionV1::PolicyCancel,
        incidents,
    )
    .unwrap();
    let descriptor = ComponentGraphVersionV1::new(
        "c76-graph",
        ProfileIdentity::PROFILE_1_ASYNC,
        ordinal,
        predecessor,
        ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
        account,
        nodes,
        graph_edges,
        graph_async_edges,
        vec![],
        vec![ComponentGraphVersionPublishedExportV1::new(endpoint(2, 1))],
        replacement,
    )
    .unwrap();
    (descriptor, artifacts, evidence)
}

fn fixture(
    ordinal: u64,
    predecessor: Option<ComponentGraphVersionCommitment>,
    target_seed: u8,
) -> Fixture {
    let (descriptor, artifacts, artifact_evidence) =
        descriptor(ordinal, predecessor, target_seed, false, false);
    Fixture {
        descriptor,
        artifacts,
        artifact_evidence,
        graph_evidence: ComponentGraphVersionAuthenticationEvidenceV1::new([0x37; 32], [0xc7; 64])
            .unwrap(),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn cgv1_header_body_roundtrip_commitment_and_shape_are_exact() {
    let fixture = fixture(0, None, 1);
    let encoded = fixture.descriptor.encode().unwrap();
    assert!(encoded.len() <= MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES);
    assert_eq!(&encoded[..8], &COMPONENT_GRAPH_VERSION_MAGIC);
    assert_eq!(
        read_u16(&encoded, 8),
        COMPONENT_GRAPH_VERSION_FORMAT_VERSION
    );
    assert_eq!(
        read_u16(&encoded, 10) as usize,
        COMPONENT_GRAPH_VERSION_HEADER_LEN
    );
    assert_eq!(read_u32(&encoded, FLAGS_OFFSET), 0);
    assert_eq!(
        read_u32(&encoded, OBJECT_KIND_OFFSET),
        COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW
    );
    assert_eq!(
        read_u16(&encoded, HASH_ALGORITHM_OFFSET),
        COMPONENT_GRAPH_VERSION_HASH_SHA256
    );
    assert_eq!(
        read_u16(&encoded, MANIFEST_VERSION_OFFSET),
        COMPONENT_GRAPH_VERSION_MANIFEST_VERSION
    );
    assert_eq!(
        read_u16(&encoded, SIGNER_POLICY_VERSION_OFFSET),
        COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION
    );
    assert_ne!(read_u16(&encoded, PROFILE_CODE_OFFSET), 0);
    assert_ne!(read_u16(&encoded, PROFILE_STAGE_OFFSET), 0);
    assert_eq!(read_u16(&encoded, CYCLE_POLICY_OFFSET), 1);
    assert_eq!(
        read_u16(&encoded, ARTIFACT_ABI_OFFSET),
        fixture.descriptor.profile().artifact_abi
    );
    assert_eq!(
        read_u16(&encoded, COMPONENT_PROFILE_OFFSET),
        fixture.descriptor.profile().component_profile
    );
    assert_eq!(
        read_u16(&encoded, CORE_PROFILE_OFFSET),
        fixture.descriptor.profile().core_profile
    );
    assert_eq!(
        read_u16(&encoded, RUNTIME_ABI_OFFSET),
        fixture.descriptor.profile().runtime_abi
    );
    assert_eq!(
        read_u64(&encoded, CANONICAL_FEATURES_OFFSET),
        fixture.descriptor.profile().canonical_features
    );
    assert_eq!(read_u64(&encoded, ORDINAL_OFFSET), 0);
    assert_eq!(read_u64(&encoded, TOTAL_LEN_OFFSET) as usize, encoded.len());
    assert_eq!(
        read_u64(&encoded, BODY_LEN_OFFSET) as usize,
        encoded.len() - COMPONENT_GRAPH_VERSION_HEADER_LEN
    );
    assert_eq!(
        read_u16(&encoded, NODE_COUNT_OFFSET) as usize,
        C76_COMPONENT_GRAPH_VERSION_NODE_COUNT
    );
    assert_eq!(
        read_u16(&encoded, EDGE_COUNT_OFFSET) as usize,
        C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT
    );
    assert_eq!(
        read_u16(&encoded, ASYNC_EDGE_COUNT_OFFSET) as usize,
        C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT
    );
    assert_eq!(read_u16(&encoded, EXTERNAL_IMPORT_COUNT_OFFSET), 0);
    assert_eq!(
        read_u16(&encoded, PUBLISHED_EXPORT_COUNT_OFFSET) as usize,
        C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT
    );
    assert_eq!(read_u16(&encoded, RESOURCE_EDGE_COUNT_OFFSET), 0);
    assert_eq!(read_u16(&encoded, GRANT_COUNT_OFFSET), 0);
    assert_eq!(
        read_u16(&encoded, INCIDENT_EDGE_COUNT_OFFSET) as usize,
        C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT
    );
    assert_eq!(
        read_u16(&encoded, REPLACEMENT_TARGET_OFFSET),
        C76_COMPONENT_GRAPH_VERSION_TARGET
    );
    assert_eq!(
        read_u16(&encoded, MAX_REPLACEMENTS_OFFSET),
        C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS
    );
    assert_eq!(read_u16(&encoded, RETIREMENT_ACTION_OFFSET), 1);
    assert_eq!(read_u16(&encoded, HEADER_RESERVED0_OFFSET), 0);
    assert!(
        encoded[PREDECESSOR_COMMITMENT_OFFSET..PREDECESSOR_COMMITMENT_OFFSET + 32]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        &encoded[POLICY_DIGEST_OFFSET..POLICY_DIGEST_OFFSET + 32],
        &GRAPH_POLICY
    );
    assert!(encoded[MANIFEST_HASH_OFFSET..MANIFEST_HASH_OFFSET + 32]
        .iter()
        .any(|byte| *byte != 0));
    assert_eq!(
        &encoded[VERSION_COMMITMENT_OFFSET..VERSION_COMMITMENT_OFFSET + 32],
        fixture.descriptor.version_commitment().unwrap().as_bytes()
    );
    assert!(
        encoded[HEADER_RESERVED1_OFFSET..COMPONENT_GRAPH_VERSION_HEADER_LEN]
            .iter()
            .all(|byte| *byte == 0)
    );

    let decoded = ComponentGraphVersionV1::decode(&encoded).unwrap();
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(
        decoded.version_commitment().unwrap(),
        fixture.descriptor.version_commitment().unwrap()
    );
    assert_eq!(decoded.name(), "c76-graph");
    assert_eq!(decoded.ordinal(), 0);
    assert_eq!(decoded.predecessor(), None);
    assert_eq!(decoded.nodes().len(), 3);
    assert_eq!(decoded.edges().len(), 2);
    assert_eq!(decoded.async_edges().len(), 2);
    assert_eq!(decoded.external_imports().len(), 0);
    assert_eq!(decoded.published_exports().len(), 1);
    assert_eq!(decoded.replacement().target(), 1);
    assert_eq!(decoded.replacement().max_replacements(), 1);
    assert_eq!(
        decoded.replacement().retirement_action(),
        ComponentGraphVersionRetirementActionV1::PolicyCancel
    );
    assert_eq!(decoded.replacement().incident_edges().len(), 2);
    decoded.validate_c76_shape().unwrap();
    assert!(!decoded.runtime_ready());
}

#[test]
fn caller_order_is_canonicalized_for_every_ordered_graph_set() {
    let (canonical, _, _) = descriptor(0, None, 1, false, false);
    let (reversed, _, _) = descriptor(0, None, 1, true, false);
    assert_eq!(canonical.encode().unwrap(), reversed.encode().unwrap());
    assert_eq!(
        canonical.version_commitment().unwrap(),
        reversed.version_commitment().unwrap()
    );
    assert_eq!(reversed.nodes()[0].ordinal(), 0);
    assert_eq!(reversed.edges()[0].source().node(), 0);
    assert_eq!(
        reversed.replacement().incident_edges()[0].edge(),
        reversed.edges()[0]
    );
}

#[test]
fn complete_logical_bundle_binds_all_six_node_attachments_and_detached_graph_evidence() {
    let fixture = fixture(0, None, 1);
    let expected_commitment = fixture.descriptor.version_commitment().unwrap();
    let bundle = ComponentGraphVersionBundleV1::new(
        fixture.descriptor,
        fixture.artifacts,
        fixture.artifact_evidence,
        fixture.graph_evidence,
    )
    .unwrap();
    assert_eq!(bundle.artifacts().len(), 3);
    assert_eq!(bundle.artifact_evidence().len(), 3);
    assert_eq!(
        bundle.descriptor().version_commitment().unwrap(),
        expected_commitment
    );
    assert_eq!(bundle.graph_version(), bundle.descriptor());
    assert_eq!(bundle.graph_evidence().encode().len(), 112);
    assert!(!bundle.runtime_ready());

    let (descriptor, artifacts, evidence, graph_evidence) = bundle.into_parts();
    assert_eq!(
        descriptor.version_commitment().unwrap(),
        expected_commitment
    );
    assert_eq!(artifacts.len(), 3);
    assert_eq!(evidence.len(), 3);
    assert_eq!(graph_evidence.encode().len(), 112);
}

#[test]
fn bundle_rejects_missing_reordered_or_mismatched_attachments() {
    let mut missing = fixture(0, None, 1);
    missing.artifacts.pop();
    assert!(matches!(
        ComponentGraphVersionBundleV1::new(
            missing.descriptor,
            missing.artifacts,
            missing.artifact_evidence,
            missing.graph_evidence,
        ),
        Err(ComponentGraphVersionError::AttachmentCount)
    ));

    let mut reordered_artifacts = fixture(0, None, 1);
    reordered_artifacts.artifacts.swap(0, 1);
    assert!(matches!(
        ComponentGraphVersionBundleV1::new(
            reordered_artifacts.descriptor,
            reordered_artifacts.artifacts,
            reordered_artifacts.artifact_evidence,
            reordered_artifacts.graph_evidence,
        ),
        Err(ComponentGraphVersionError::AttachmentMismatch)
    ));

    let mut reordered_evidence = fixture(0, None, 1);
    reordered_evidence.artifact_evidence.swap(1, 2);
    assert!(matches!(
        ComponentGraphVersionBundleV1::new(
            reordered_evidence.descriptor,
            reordered_evidence.artifacts,
            reordered_evidence.artifact_evidence,
            reordered_evidence.graph_evidence,
        ),
        Err(ComponentGraphVersionError::AttachmentMismatch)
    ));
}

#[test]
fn successor_commits_predecessor_and_changes_only_the_replaced_node_attachment() {
    let current = fixture(0, None, 1);
    let current_commitment = current.descriptor.version_commitment().unwrap();
    let successor = fixture(1, Some(current_commitment), 9);
    assert_eq!(successor.descriptor.ordinal(), 1);
    assert_eq!(successor.descriptor.predecessor(), Some(current_commitment));
    assert_ne!(
        successor.descriptor.version_commitment().unwrap(),
        current_commitment
    );
    assert_eq!(
        current.descriptor.nodes()[0].artifact_commitment(),
        successor.descriptor.nodes()[0].artifact_commitment()
    );
    assert_ne!(
        current.descriptor.nodes()[1].artifact_commitment(),
        successor.descriptor.nodes()[1].artifact_commitment()
    );
    assert_eq!(
        current.descriptor.nodes()[2].artifact_commitment(),
        successor.descriptor.nodes()[2].artifact_commitment()
    );
    ComponentGraphVersionBundleV1::new(
        successor.descriptor,
        successor.artifacts,
        successor.artifact_evidence,
        successor.graph_evidence,
    )
    .unwrap();
}

#[test]
fn three_root_node_current_and_candidate_accounts_match_runtime_nesting() {
    let current = fixture(0, None, 1);
    let current_commitment = current.descriptor.version_commitment().unwrap();
    let candidate = fixture(1, Some(current_commitment), 9);

    for descriptor in [&current.descriptor, &candidate.descriptor] {
        let account = descriptor.account();
        assert_eq!(account.nodes, 3);
        assert_eq!(account.edges, 2);
        assert_eq!(account.maximum_nesting, 1);
        assert_eq!(account.external_imports, 0);
        assert_eq!(account.published_exports, 1);
        assert_eq!(
            ComponentGraphVersionV1::decode(&descriptor.encode().unwrap())
                .unwrap()
                .account(),
            account
        );
    }
    assert_eq!(current.descriptor.account(), candidate.descriptor.account());
}

#[test]
fn validation_only_artifact_profiles_do_not_enter_the_durable_graph_codec() {
    let incident_edge = edges()[0];
    let replacement = || {
        ComponentGraphVersionReplacementV1::new(
            1,
            1,
            ComponentGraphVersionRetirementActionV1::PolicyCancel,
            vec![ComponentGraphVersionIncidentEdgeV1::new(
                incident_edge,
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )],
        )
        .unwrap()
    };
    assert_eq!(
        ComponentGraphVersionV1::new(
            "preview1-wrapped-must-not-enter-cgv1",
            ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            ComponentGraphAccount::default(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            replacement(),
        ),
        Err(ComponentGraphVersionError::Profile)
    );

    assert_eq!(
        ComponentGraphVersionV1::new(
            "reference-code10-volatile-must-not-enter-cgv1",
            ProfileIdentity::PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            ComponentGraphAccount::default(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            replacement(),
        ),
        Err(ComponentGraphVersionError::Profile)
    );

    assert_eq!(
        ComponentGraphVersionV1::new(
            "reference-code9-must-not-enter-cgv1",
            ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            ComponentGraphAccount::default(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            replacement(),
        ),
        Err(ComponentGraphVersionError::Profile)
    );

    assert_eq!(
        ComponentGraphVersionV1::new(
            "sync-float-code5-must-not-enter-cgv1",
            ProfileIdentity::PROFILE_2_SYNC_FLOAT,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            ComponentGraphAccount::default(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            replacement(),
        ),
        Err(ComponentGraphVersionError::Profile)
    );

    for code in [4_u16, 5_u16] {
        let mut encoded = fixture(0, None, 1).descriptor.encode().unwrap();
        encoded[PROFILE_CODE_OFFSET..PROFILE_CODE_OFFSET + 2].copy_from_slice(&code.to_le_bytes());
        assert_eq!(
            ComponentGraphVersionV1::decode(&encoded),
            Err(ComponentGraphVersionError::Profile),
            "accepted artifact-only profile code {code}"
        );
    }
}

#[test]
fn fixed_shape_gate_is_separate_from_bounded_general_codec() {
    let (general, _, _) = descriptor(0, None, 1, false, true);
    assert_eq!(general.async_edges().len(), 1);
    assert_eq!(
        general.validate_c76_shape(),
        Err(ComponentGraphVersionError::C76Shape)
    );
    assert_eq!(
        ComponentGraphVersionV1::decode(&general.encode().unwrap()).unwrap(),
        general
    );
}

#[test]
fn every_encoded_byte_mutation_prefix_and_trailing_byte_fails_closed() {
    let encoded = fixture(0, None, 1).descriptor.encode().unwrap();
    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 1;
        assert!(
            ComponentGraphVersionV1::decode(&mutated).is_err(),
            "mutation at byte {index} was accepted"
        );
    }
    for length in 0..encoded.len() {
        assert!(ComponentGraphVersionV1::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(ComponentGraphVersionV1::decode(&trailing).is_err());
}

#[test]
fn header_reserved_resource_grant_and_relation_mutations_are_rejected() {
    let encoded = fixture(0, None, 1).descriptor.encode().unwrap();
    for offset in [42, HEADER_RESERVED0_OFFSET, HEADER_RESERVED1_OFFSET] {
        let mut mutated = encoded.clone();
        mutated[offset] = 1;
        assert!(ComponentGraphVersionV1::decode(&mutated).is_err());
    }
    for offset in [RESOURCE_EDGE_COUNT_OFFSET, GRANT_COUNT_OFFSET] {
        let mut mutated = encoded.clone();
        mutated[offset..offset + 2].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            ComponentGraphVersionV1::decode(&mutated),
            Err(ComponentGraphVersionError::Reserved)
        );
    }
    let mut predecessor_on_zero = encoded.clone();
    predecessor_on_zero[PREDECESSOR_COMMITMENT_OFFSET] = 1;
    assert!(ComponentGraphVersionV1::decode(&predecessor_on_zero).is_err());
}

#[test]
fn constructor_rejects_ambiguous_relations_cycles_incidents_and_target_surface() {
    let (artifacts, evidence, nodes, account) = attachments(1);
    drop((artifacts, evidence));
    let graph_edges = vec![
        ComponentGraphVersionEdgeV1::new(endpoint(0, 0), endpoint(1, 0)),
        ComponentGraphVersionEdgeV1::new(endpoint(1, 1), endpoint(0, 1)),
    ];
    let incidents = graph_edges
        .iter()
        .copied()
        .map(|edge| {
            ComponentGraphVersionIncidentEdgeV1::new(
                edge,
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )
        })
        .collect();
    let replacement = ComponentGraphVersionReplacementV1::new(
        1,
        1,
        ComponentGraphVersionRetirementActionV1::PolicyCancel,
        incidents,
    )
    .unwrap();
    assert_eq!(
        ComponentGraphVersionV1::new(
            "cycle",
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            account,
            nodes,
            graph_edges.clone(),
            async_edges(&graph_edges),
            vec![],
            vec![ComponentGraphVersionPublishedExportV1::new(endpoint(2, 1))],
            replacement,
        ),
        Err(ComponentGraphVersionError::GraphCycle)
    );

    let (_, _, nodes, account) = attachments(1);
    let graph_edges = edges();
    let replacement = ComponentGraphVersionReplacementV1::new(
        1,
        1,
        ComponentGraphVersionRetirementActionV1::PolicyCancel,
        vec![ComponentGraphVersionIncidentEdgeV1::new(
            graph_edges[0],
            ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
        )],
    )
    .unwrap();
    assert_eq!(
        ComponentGraphVersionV1::new(
            "missing-incident",
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            account,
            nodes,
            graph_edges.clone(),
            async_edges(&graph_edges),
            vec![],
            vec![ComponentGraphVersionPublishedExportV1::new(endpoint(2, 1))],
            replacement,
        ),
        Err(ComponentGraphVersionError::IncidentEdges)
    );

    let (_, _, nodes, account) = attachments(1);
    let graph_edges = edges();
    let incidents = graph_edges
        .iter()
        .copied()
        .map(|edge| {
            ComponentGraphVersionIncidentEdgeV1::new(
                edge,
                ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
            )
        })
        .collect();
    let replacement = ComponentGraphVersionReplacementV1::new(
        1,
        1,
        ComponentGraphVersionRetirementActionV1::PolicyCancel,
        incidents,
    )
    .unwrap();
    assert_eq!(
        ComponentGraphVersionV1::new(
            "published-target",
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
            0,
            None,
            ComponentGraphVersionPolicyDigest::from_bytes(GRAPH_POLICY).unwrap(),
            account,
            nodes,
            graph_edges.clone(),
            async_edges(&graph_edges),
            vec![],
            vec![ComponentGraphVersionPublishedExportV1::new(endpoint(1, 1))],
            replacement,
        ),
        Err(ComponentGraphVersionError::ReplacementSurface)
    );

    assert!(ComponentGraphVersionReplacementV1::new(
        1,
        0,
        ComponentGraphVersionRetirementActionV1::PolicyCancel,
        vec![ComponentGraphVersionIncidentEdgeV1::new(
            edges()[0],
            ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh,
        )],
    )
    .is_err());
}

#[test]
fn graph_debug_redacts_commitments_and_exposes_no_durable_or_execution_authority() {
    let fixture = fixture(0, None, 1);
    let descriptor_debug = format!("{:?}", fixture.descriptor);
    assert!(descriptor_debug.contains("runtime_ready: false"));
    assert!(descriptor_debug.contains("<redacted>"));
    for forbidden in [
        "ObjectId",
        "SpaceId",
        "DerivationId",
        "raw durable",
        "capability",
        "runtime_ready: true",
    ] {
        assert!(!descriptor_debug.contains(forbidden), "leaked {forbidden}");
    }
    let bundle = ComponentGraphVersionBundleV1::new(
        fixture.descriptor,
        fixture.artifacts,
        fixture.artifact_evidence,
        fixture.graph_evidence,
    )
    .unwrap();
    let bundle_debug = format!("{bundle:?}");
    assert!(bundle_debug.contains("artifact_count: 3"));
    assert!(bundle_debug.contains("artifact_evidence_count: 3"));
    assert!(bundle_debug.contains("runtime_ready: false"));
}

#[test]
fn public_constants_freeze_cgv1_and_c76_contracts() {
    assert_eq!(COMPONENT_GRAPH_VERSION_MAGIC, *b"VIBECGV\0");
    assert_eq!(COMPONENT_GRAPH_VERSION_FORMAT_VERSION, 1);
    assert_eq!(COMPONENT_GRAPH_VERSION_MANIFEST_VERSION, 1);
    assert_eq!(COMPONENT_GRAPH_VERSION_SIGNER_POLICY_VERSION, 1);
    assert_eq!(COMPONENT_GRAPH_VERSION_HASH_SHA256, 1);
    assert_eq!(COMPONENT_GRAPH_VERSION_OBJECT_KIND_RAW, 0x4347_5631);
    assert_eq!(COMPONENT_GRAPH_VERSION_HEADER_LEN, 256);
    assert_eq!(MAX_COMPONENT_GRAPH_VERSION_ENCODED_BYTES, 65_536);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_NODE_COUNT, 3);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_EDGE_COUNT, 2);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_PUBLISHED_EXPORT_COUNT, 1);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_TARGET, 1);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_MAX_REPLACEMENTS, 1);
    assert_eq!(C76_COMPONENT_GRAPH_VERSION_INCIDENT_EDGE_COUNT, 2);
}
