#![cfg(feature = "c76-graph-version-replacement-qemu-acceptance")]

use vibeos_component_admission::CommandStreamMode;
use vibeos_component_format::{
    ComponentGraphVersionIncidentEdgeActionV1, ComponentGraphVersionRetirementActionV1,
    ProfileIdentity,
};
use vibeos_image_policy::{
    C76GraphRetirementAction, ComponentGraphReplacementPinAction,
    C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE, C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE,
    C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE,
};

#[test]
fn pin_is_two_complete_operator_only_bundles_with_one_exact_replacement() {
    let policy = C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;
    assert_eq!(policy.generation(), 1);
    assert_eq!(policy.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert!(!policy.profile().execution_enabled());
    assert_eq!(policy.graph_name(), "c76-chain");
    assert_eq!(policy.node_command_name(), "c76-node");
    assert_eq!(policy.node_entrypoint(), "run");
    assert_eq!(policy.node_argument_limits(), (0, 0));
    assert_eq!(policy.node_interface_ceiling_count(), 0);
    assert_eq!(policy.node_count(), 3);
    assert!(policy.all_nodes_are_roots());
    assert_eq!(policy.node_labels(), ["source", "relay", "sink"]);
    assert_eq!(
        policy.node_worlds(),
        [
            "test:c65-chain/source@1.0.0",
            "test:c65-chain/relay@1.0.0",
            "test:c65-chain/sink@1.0.0",
        ]
    );
    assert_eq!(policy.replacement_node(), 1);
    assert_eq!(
        policy.retirement_action(),
        C76GraphRetirementAction::PolicyCancel
    );
    assert_eq!(policy.max_replacements(), 1);
    assert_eq!(policy.node_limits().memory_bytes, 64 * 1024);
    assert_eq!(policy.node_limits().total_fuel, 1_000);
    assert_eq!(policy.node_limits().poll_quantum, 100);
    assert_eq!(policy.node_limits().resources, 8);
    assert_eq!(
        policy.node_streams(),
        (
            CommandStreamMode::Closed,
            CommandStreamMode::Closed,
            CommandStreamMode::Closed,
        )
    );
    assert_eq!(policy.resource_edge_count(), 0);
    assert_eq!(policy.external_import_count(), 0);
    assert!(!policy.runtime_ready());
    assert_eq!(policy.guest_calls(), 0);
    assert_eq!(
        policy.leaf_signers().unwrap(),
        policy.graph_signers().unwrap()
    );
    assert_eq!(
        *policy.active_signer().unwrap().public_key(),
        policy.active_public_key_bytes()
    );

    let edges = policy.graph_edges();
    assert_eq!(
        edges.map(|edge| (
            edge.source_node(),
            edge.source_export(),
            edge.target_node(),
            edge.target_import(),
            edge.action(),
        )),
        [
            (
                0,
                0,
                1,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh
            ),
            (
                1,
                0,
                2,
                0,
                ComponentGraphReplacementPinAction::RecreateFresh
            ),
        ]
    );
    assert_eq!(policy.incident_edges(), edges);
    assert_eq!(policy.published_export(), (2, 0));

    let g0 = C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE;
    let g1 = C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE;
    assert_eq!(g0.ordinal(), 0);
    assert_eq!(g1.ordinal(), 1);
    assert_eq!(g0.attachment_counts(), (3, 3, 1));
    assert_eq!(g1.attachment_counts(), (3, 3, 1));
    assert!(!g0.runtime_ready());
    assert!(!g1.runtime_ready());
    assert_eq!(g0.guest_calls(), 0);
    assert_eq!(g1.guest_calls(), 0);

    let g0_artifact_bytes = g0.canonical_artifact_bytes();
    let g1_artifact_bytes = g1.canonical_artifact_bytes();
    let g0_evidence_bytes = g0.canonical_artifact_evidence_bytes();
    let g1_evidence_bytes = g1.canonical_artifact_evidence_bytes();
    assert_eq!(g0_artifact_bytes[0], g1_artifact_bytes[0]);
    assert_ne!(g0_artifact_bytes[1], g1_artifact_bytes[1]);
    assert_eq!(g0_artifact_bytes[2], g1_artifact_bytes[2]);
    assert_eq!(g0_evidence_bytes[0], g1_evidence_bytes[0]);
    assert_ne!(g0_evidence_bytes[1], g1_evidence_bytes[1]);
    assert_eq!(g0_evidence_bytes[2], g1_evidence_bytes[2]);

    let g0_descriptor = g0.descriptor().unwrap();
    let g1_descriptor = g1.descriptor().unwrap();
    g0_descriptor.validate_c76_shape().unwrap();
    g1_descriptor.validate_c76_shape().unwrap();
    assert_eq!(g0_descriptor.ordinal(), 0);
    assert!(g0_descriptor.predecessor().is_none());
    assert_eq!(g1_descriptor.ordinal(), 1);
    assert_eq!(
        g1_descriptor.predecessor(),
        Some(g0_descriptor.version_commitment().unwrap())
    );
    for descriptor in [&g0_descriptor, &g1_descriptor] {
        assert!(!descriptor.runtime_ready());
        assert_eq!(descriptor.nodes().len(), 3);
        assert_eq!(descriptor.edges().len(), 2);
        assert_eq!(descriptor.async_edges().len(), 2);
        assert!(descriptor.external_imports().is_empty());
        assert_eq!(descriptor.published_exports().len(), 1);
        assert_eq!(
            descriptor.replacement().retirement_action(),
            ComponentGraphVersionRetirementActionV1::PolicyCancel
        );
        assert!(descriptor
            .replacement()
            .incident_edges()
            .iter()
            .all(|edge| edge.action() == ComponentGraphVersionIncidentEdgeActionV1::RecreateFresh));
    }

    for (version, descriptor) in [(g0, &g0_descriptor), (g1, &g1_descriptor)] {
        assert_eq!(
            descriptor.encode().unwrap(),
            version.canonical_descriptor_bytes()
        );
        let artifacts = version.artifacts().unwrap();
        let evidence = version.artifact_evidence().unwrap();
        let graph_evidence = version.graph_evidence().unwrap();
        assert!(artifacts.iter().all(|artifact| !artifact.runtime_ready()));
        assert!(evidence.iter().all(|item| !item.runtime_ready()));
        assert!(!graph_evidence.runtime_ready());
        assert!(evidence
            .iter()
            .all(|item| item.public_key().to_bytes() == policy.active_public_key_bytes()));
        assert_eq!(
            graph_evidence.public_key().to_bytes(),
            policy.active_public_key_bytes()
        );
    }
}

#[test]
fn debug_output_redacts_all_canonical_and_signer_bytes() {
    let rendered = format!(
        "{:?} {:?} {:?}",
        C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE,
        C76_G0_GRAPH_VERSION_QEMU_ACCEPTANCE,
        C76_G1_GRAPH_VERSION_QEMU_ACCEPTANCE,
    );
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("1dfaeb2e"));
    assert!(!rendered.contains("VIBECGV"));
    assert!(!rendered.contains("VIBECMP"));
}
