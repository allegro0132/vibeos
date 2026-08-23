use std::sync::Arc;

use vibeos_component_admission::{
    admit_component_graph, admit_component_graph_replacement,
    admit_component_graph_with_resource_policy, ArtifactTrust, CallerAuthority, ComponentArtifact,
    ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy,
    ComponentGraphNodeReplacementPolicy, ComponentGraphReplacementEdgeAction,
    ComponentGraphReplacementEdgePolicy, ComponentGraphResourceEdgePolicy,
    ComponentGraphResourceMode, InstanceLimits, ProfileIdentity,
};
use vibeos_component_command::{
    ComponentGraphNodePrincipalTemplate, ComponentGraphNodeReplacementTemplate,
    ComponentGraphNodeReportError, ComponentGraphNodeTerminal, ComponentGraphPrincipalIsolation,
    ComponentGraphPrincipalTemplate,
};
use vibeos_component_runtime::{
    graph::{
        ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
        ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
        ComponentGraphPublishedExportSpec,
    },
    world::WorldContract,
};

const EMPTY_WORLD_WIT: &str = r#"
    package test:c63@1.0.0;

    world empty {}
"#;

const EMPTY_WORLD: &str = "test:c63/empty@1.0.0";

const RESOURCE_WIT: &str = r#"
    package test:c64-command@1.0.0;

    interface pipe {
        resource handle;
        send: func(value: borrow<handle>);
    }

    world producer {
        export pipe;
    }

    world consumer {
        import pipe;
    }
"#;

const RESOURCE_PRODUCER_WORLD: &str = "test:c64-command/producer@1.0.0";
const RESOURCE_CONSUMER_WORLD: &str = "test:c64-command/consumer@1.0.0";

const RESOURCE_PRODUCER_WAT: &str = r#"
    (component
      (type $handle (resource (rep i32)))
      (type $borrow-handle (borrow $handle))
      (type $send-type (func (param "value" $borrow-handle)))
      (core module $module
        (func (export "send") (param i32)))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send" (core func $send-core))
      (func $send (type $send-type) (canon lift (core func $send-core)))
      (instance $pipe
        (export "handle" (type $handle))
        (export "send" (func $send)))
      (export "test:c64-command/pipe@1.0.0" (instance $pipe)))
"#;

const RESOURCE_CONSUMER_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (export "handle" (type $handle (sub resource)))
          (type $borrow-handle (borrow $handle))
          (type $send-type (func (param "value" $borrow-handle)))
          (export "send" (func (type $send-type)))))
      (import "test:c64-command/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const ASYNC_CHAIN_WIT: &str = include_str!("../../../policy/image/artifacts/c65-async-chain.wit");
const ASYNC_SOURCE_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-source.component.wat");
const ASYNC_RELAY_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-relay.component.wat");
const ASYNC_RELAY_V2_WAT: &str =
    include_str!("../../../policy/image/artifacts/c66-async-relay-v2.component.wat");
const ASYNC_SINK_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-sink.component.wat");
const ASYNC_SOURCE_WORLD: &str = "test:c65-chain/source@1.0.0";
const ASYNC_RELAY_WORLD: &str = "test:c65-chain/relay@1.0.0";
const ASYNC_SINK_WORLD: &str = "test:c65-chain/sink@1.0.0";

fn graph_node(index: u16) -> ComponentGraphNodeId {
    ComponentGraphNodeId::new(index)
}

fn graph_entity(index: u16) -> ComponentGraphEntityIndex {
    ComponentGraphEntityIndex::new(index)
}

fn resource_edge() -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(graph_node(0), graph_entity(0)),
        ComponentGraphImportEndpoint::new(graph_node(1), graph_entity(0)),
    )
}

fn async_edge() -> ComponentGraphEdgeSpec {
    resource_edge()
}

fn second_async_edge() -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(graph_node(1), graph_entity(0)),
        ComponentGraphImportEndpoint::new(graph_node(2), graph_entity(0)),
    )
}

fn recreate(edge: ComponentGraphEdgeSpec) -> ComponentGraphReplacementEdgePolicy {
    ComponentGraphReplacementEdgePolicy {
        edge,
        action: ComponentGraphReplacementEdgeAction::RecreateFresh,
    }
}

fn limits(
    memory_bytes: usize,
    total_fuel: u64,
    poll_quantum: u64,
    resources: u16,
) -> InstanceLimits {
    InstanceLimits {
        memory_bytes,
        total_fuel,
        poll_quantum,
        resources,
    }
}

fn admitted_graph() -> vibeos_component_admission::AdmittedComponentGraph {
    let bytes = wat::parse_str("(component)").expect("empty Component must encode");
    let root = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("root artifact must fit");
    let child = ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("child artifact must fit");
    let exact_world =
        WorldContract::parse(EMPTY_WORLD_WIT, EMPTY_WORLD).expect("trusted empty world must parse");
    let nodes = [
        ComponentGraphNodeAdmissionPolicy {
            label: "root-principal",
            nesting: ComponentGraphNesting::Root,
            exact_world: &exact_world,
            trust: ArtifactTrust::ImagePinned(root.identity()),
            limits: limits(64 * 1024, 1_000, 100, 3),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: "child-principal",
            nesting: ComponentGraphNesting::Nested {
                parent: ComponentGraphNodeId::new(0),
            },
            exact_world: &exact_world,
            trust: ArtifactTrust::ImagePinned(child.identity()),
            limits: limits(128 * 1024, 2_000, 200, 5),
            interfaces: &[],
        },
    ];
    let policy = ComponentGraphAdmissionPolicy {
        name: "validation-only-principals",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        nodes: &nodes,
        edges: &[],
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(vec![root, child], &policy, &CallerAuthority { offers: &[] })
        .expect("empty validation-only graph must admit")
}

fn admitted_resource_graph() -> vibeos_component_admission::AdmittedComponentGraph {
    let producer_bytes = wat::parse_str(RESOURCE_PRODUCER_WAT).expect("producer must encode");
    let consumer_bytes = wat::parse_str(RESOURCE_CONSUMER_WAT).expect("consumer must encode");
    let producer = ComponentArtifact::copy_from(&producer_bytes, ProfileIdentity::PROFILE_1)
        .expect("producer artifact must fit");
    let consumer = ComponentArtifact::copy_from(&consumer_bytes, ProfileIdentity::PROFILE_1)
        .expect("consumer artifact must fit");
    let producer_world = WorldContract::parse(RESOURCE_WIT, RESOURCE_PRODUCER_WORLD)
        .expect("producer world must parse");
    let consumer_world = WorldContract::parse(RESOURCE_WIT, RESOURCE_CONSUMER_WORLD)
        .expect("consumer world must parse");
    let nodes = [
        ComponentGraphNodeAdmissionPolicy {
            label: "resource-producer",
            nesting: ComponentGraphNesting::Root,
            exact_world: &producer_world,
            trust: ArtifactTrust::ImagePinned(producer.identity()),
            limits: limits(64 * 1024, 1_000, 100, 3),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: "resource-consumer",
            nesting: ComponentGraphNesting::Root,
            exact_world: &consumer_world,
            trust: ArtifactTrust::ImagePinned(consumer.identity()),
            limits: limits(64 * 1024, 2_000, 100, 5),
            interfaces: &[],
        },
    ];
    let edges = [resource_edge()];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-route-report",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    let resource_policy = [ComponentGraphResourceEdgePolicy {
        edge: resource_edge(),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    admit_component_graph_with_resource_policy(
        vec![producer, consumer],
        &policy,
        &resource_policy,
        &CallerAuthority { offers: &[] },
    )
    .expect("exact resource graph must admit")
}

fn admitted_async_graph_with_relay(
    relay_wat: &str,
) -> vibeos_component_admission::AdmittedComponentGraph {
    let source_bytes = wat::parse_str(ASYNC_SOURCE_WAT).expect("source must encode");
    let relay_bytes = wat::parse_str(relay_wat).expect("relay must encode");
    let sink_bytes = wat::parse_str(ASYNC_SINK_WAT).expect("sink must encode");
    let empty_bytes = wat::parse_str("(component)").expect("empty component must encode");
    let source = ComponentArtifact::copy_from(&source_bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("source artifact must fit");
    let relay = ComponentArtifact::copy_from(&relay_bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("relay artifact must fit");
    let sink = ComponentArtifact::copy_from(&sink_bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("sink artifact must fit");
    let observer = ComponentArtifact::copy_from(&empty_bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("observer artifact must fit");
    let source_world =
        WorldContract::parse(ASYNC_CHAIN_WIT, ASYNC_SOURCE_WORLD).expect("source world must parse");
    let relay_world =
        WorldContract::parse(ASYNC_CHAIN_WIT, ASYNC_RELAY_WORLD).expect("relay world must parse");
    let sink_world =
        WorldContract::parse(ASYNC_CHAIN_WIT, ASYNC_SINK_WORLD).expect("sink world must parse");
    let empty_world =
        WorldContract::parse(EMPTY_WORLD_WIT, EMPTY_WORLD).expect("empty world must parse");
    let nodes = [
        ComponentGraphNodeAdmissionPolicy {
            label: "async-source",
            nesting: ComponentGraphNesting::Root,
            exact_world: &source_world,
            trust: ArtifactTrust::ImagePinned(source.identity()),
            limits: limits(64 * 1024, 1_000, 100, 3),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: "async-relay",
            nesting: ComponentGraphNesting::Root,
            exact_world: &relay_world,
            trust: ArtifactTrust::ImagePinned(relay.identity()),
            limits: limits(64 * 1024, 2_000, 100, 5),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: "async-sink",
            nesting: ComponentGraphNesting::Root,
            exact_world: &sink_world,
            trust: ArtifactTrust::ImagePinned(sink.identity()),
            limits: limits(64 * 1024, 1_500, 75, 4),
            interfaces: &[],
        },
        ComponentGraphNodeAdmissionPolicy {
            label: "unrouted-observer",
            nesting: ComponentGraphNesting::Root,
            exact_world: &empty_world,
            trust: ArtifactTrust::ImagePinned(observer.identity()),
            limits: limits(64 * 1024, 500, 50, 2),
            interfaces: &[],
        },
    ];
    let edges = [async_edge(), second_async_edge()];
    let published_exports = [ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(graph_node(2), graph_entity(0)),
    )];
    let policy = ComponentGraphAdmissionPolicy {
        name: "async-route-report",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(
        vec![source, relay, sink, observer],
        &policy,
        &CallerAuthority { offers: &[] },
    )
    .expect("exact async graph must admit")
}

fn admitted_async_graph() -> vibeos_component_admission::AdmittedComponentGraph {
    admitted_async_graph_with_relay(ASYNC_RELAY_WAT)
}

fn admitted_async_replacement() -> vibeos_component_admission::AdmittedComponentGraphReplacement {
    let current = Arc::new(admitted_async_graph_with_relay(ASYNC_RELAY_WAT));
    let candidate = Arc::new(admitted_async_graph_with_relay(ASYNC_RELAY_V2_WAT));
    let incident_edges = [recreate(second_async_edge()), recreate(async_edge())];
    admit_component_graph_replacement(
        current,
        candidate,
        &ComponentGraphNodeReplacementPolicy {
            target: graph_node(1),
            max_replacements: 1,
            incident_edges: &incident_edges,
        },
    )
    .expect("exact async relay replacement must admit")
}

#[test]
fn exact_principal_projection_is_owned_inert_send_sync_and_revalidates() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<ComponentGraphPrincipalTemplate>();
    assert_send_sync::<ComponentGraphNodePrincipalTemplate>();

    let admitted = Arc::new(admitted_graph());
    let account = admitted.manifest().account();
    let expected = admitted
        .manifest()
        .nodes()
        .iter()
        .map(|node| {
            (
                node.id(),
                node.label().to_owned(),
                node.artifact(),
                node.profile(),
                node.world().to_owned(),
                node.nesting(),
                node.limits(),
                node.budget(),
            )
        })
        .collect::<Vec<_>>();
    let template = ComponentGraphPrincipalTemplate::new(Arc::clone(&admitted))
        .expect("construction must revalidate the graph");

    assert!(!template.runtime_ready());
    assert_eq!(template.profile(), ProfileIdentity::PROFILE_1_ASYNC);
    assert_eq!(template.account(), account);
    assert_eq!(template.manifest(), admitted.manifest());
    assert!(core::ptr::eq(template.admitted_graph(), admitted.as_ref()));
    assert!(template.grants().is_empty());
    assert!(template.async_edges().is_empty());
    assert_eq!(template.principals().len(), expected.len());
    for (principal, expected) in template.principals().iter().zip(&expected) {
        assert_eq!(principal.id(), expected.0);
        assert_eq!(principal.label(), expected.1);
        assert_eq!(principal.artifact(), expected.2);
        assert_eq!(principal.profile(), expected.3);
        assert_eq!(principal.world(), expected.4);
        assert_eq!(principal.nesting(), expected.5);
        assert_eq!(principal.limits(), expected.6);
        assert_eq!(principal.budget(), expected.7);
        assert_eq!(principal.memory_bytes(), expected.7.memory_bytes);
        assert_eq!(principal.fuel_limit(), expected.7.total_fuel);
        assert_eq!(principal.poll_quantum(), expected.7.poll_quantum);
        assert_eq!(principal.resource_slot_limit(), expected.7.resource_slots);
        assert_eq!(
            principal.isolation(),
            ComponentGraphPrincipalIsolation::FreshPerNode
        );
        assert!(core::ptr::eq(
            template.principal(principal.id()).unwrap(),
            principal
        ));
    }

    template.revalidate().expect("first complete revalidation");
    template.revalidate().expect("second complete revalidation");
}

#[test]
fn runtime_unavailable_reports_are_zero_bounded_and_semantic() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_graph()))
        .expect("template must build");
    for principal in template.principals() {
        let report = template
            .runtime_unavailable_report(principal.id())
            .expect("known node must report unavailable");
        assert_eq!(report.node(), principal.id());
        assert_eq!(
            report.terminal(),
            ComponentGraphNodeTerminal::RuntimeUnavailable
        );
        assert_eq!(report.fuel().limit(), principal.fuel_limit());
        assert_eq!(report.fuel().consumed(), 0);
        assert_eq!(
            report.resources().declared_types(),
            principal.budget().resource_types
        );
        assert_eq!(
            report.resources().slot_limit(),
            principal.resource_slot_limit()
        );
        assert_eq!(report.resources().peak_slots(), 0);
        assert_eq!(report.resources().live_slots(), 0);
    }
    let unknown = ComponentGraphNodeId::new(u16::MAX);
    assert_eq!(
        template.runtime_unavailable_report(unknown),
        Err(ComponentGraphNodeReportError::UnknownNode { node: unknown })
    );
}

#[test]
fn admitted_resource_edges_are_public_inert_and_freshly_revalidated() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_resource_graph()))
        .expect("resource template must build");

    assert!(!template.runtime_ready());
    assert!(template.async_edges().is_empty());
    assert_eq!(template.resource_edges().len(), 1);
    let route = &template.resource_edges()[0];
    assert_eq!(route.edge(), resource_edge());
    assert_eq!(route.mode(), ComponentGraphResourceMode::Borrow);
    assert_eq!(route.resources().len(), 1);
    assert_eq!(route.resources()[0], "handle");
    template
        .revalidate()
        .expect("resource edges require fresh admission provenance");
}

#[test]
fn admitted_async_edges_are_public_inert_exact_and_freshly_revalidated() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_async_graph()))
        .expect("async template must build");

    assert!(!template.runtime_ready());
    assert_eq!(template.async_edges().len(), 2);
    let route = &template.async_edges()[0];
    assert_eq!(route.edge(), async_edge());
    assert_eq!(route.async_functions(), 1);
    assert_eq!(route.streams(), 4);
    assert_eq!(route.futures(), 4);
    let second_route = &template.async_edges()[1];
    assert_eq!(second_route.edge(), second_async_edge());
    assert_eq!(second_route.async_functions(), 1);
    assert_eq!(second_route.streams(), 4);
    assert_eq!(second_route.futures(), 4);
    assert!(template.resource_edges().is_empty());
    template
        .revalidate()
        .expect("async edges require fresh exact shape evidence");

    let output = format!("{template:?}");
    assert!(output.contains("ComponentGraphAsyncEdgeManifest"));
    assert!(output.contains("async_functions"));
    for forbidden in [
        "TaskId",
        "CSpace",
        "HostOperationToken",
        "Cap(",
        "generation",
    ] {
        assert!(
            !output.contains(forbidden),
            "debug leaked {forbidden}: {output}"
        );
    }
}

#[test]
fn command_information_flow_delegates_the_closed_fresh_admission_projection() {
    let admitted = Arc::new(admitted_async_graph());
    let expected = admitted
        .information_flow()
        .expect("direct admission diagnostic");
    let template = ComponentGraphPrincipalTemplate::new(Arc::clone(&admitted))
        .expect("async template must build");
    let observed = template
        .information_flow()
        .expect("command diagnostic must freshly revalidate");

    assert!(!observed.runtime_ready());
    assert_eq!(observed.to_string(), expected.to_string());
    assert_eq!(format!("{observed:?}"), format!("{expected:?}"));
}

#[test]
fn supervisor_prepared_async_report_is_endpoint_only_positive_bounded_and_guest_inert() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_async_graph()))
        .expect("async template must build");

    for node in [graph_node(0), graph_node(1), graph_node(2)] {
        let principal = template.principal(node).unwrap();
        let report = template
            .supervisor_prepared_async_unavailable_report(node, 1)
            .expect("both sealed async-edge endpoints may report measured setup use");
        assert_eq!(report.node(), node);
        assert_eq!(
            report.terminal(),
            ComponentGraphNodeTerminal::RuntimeUnavailable
        );
        assert_eq!(report.fuel().limit(), principal.fuel_limit());
        assert_eq!(report.fuel().consumed(), 0);
        assert_eq!(report.resources().peak_slots(), 1);
        assert_eq!(report.resources().live_slots(), 0);
    }

    let at_limit = template
        .supervisor_prepared_async_unavailable_report(graph_node(0), 3)
        .expect("the exact manifest slot ceiling is inclusive");
    assert_eq!(at_limit.resources().peak_slots(), 3);
    assert_eq!(at_limit.resources().live_slots(), 0);
    assert!(!template.runtime_ready());
}

#[test]
fn supervisor_prepared_async_report_rejects_zero_non_endpoint_unknown_and_over_limit() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_async_graph()))
        .expect("async template must build");
    assert_eq!(
        template.supervisor_prepared_async_unavailable_report(graph_node(0), 0),
        Err(ComponentGraphNodeReportError::SupervisorPreparedPeakRequired)
    );
    assert_eq!(
        template.supervisor_prepared_async_unavailable_report(graph_node(0), 4),
        Err(ComponentGraphNodeReportError::ResourceLimitExceeded)
    );
    assert_eq!(
        template.supervisor_prepared_async_unavailable_report(graph_node(3), 1),
        Err(ComponentGraphNodeReportError::AsyncEdgeRequired {
            node: graph_node(3),
        })
    );
    let unknown = graph_node(u16::MAX);
    assert_eq!(
        template.supervisor_prepared_async_unavailable_report(unknown, 1),
        Err(ComponentGraphNodeReportError::UnknownNode { node: unknown })
    );

    let ordinary = template.runtime_unavailable_report(graph_node(0)).unwrap();
    assert_eq!(ordinary.fuel().consumed(), 0);
    assert_eq!(ordinary.resources().peak_slots(), 0);
    assert_eq!(ordinary.resources().live_slots(), 0);
}

#[test]
fn supervisor_prepared_resource_report_is_positive_bounded_and_guest_inert() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_resource_graph()))
        .expect("resource template must build");

    for node in [graph_node(0), graph_node(1)] {
        let principal = template.principal(node).unwrap();
        let report = template
            .supervisor_prepared_resource_unavailable_report(node, 1)
            .expect("both exact resource-edge endpoints may report measured setup use");
        assert_eq!(report.node(), node);
        assert_eq!(
            report.terminal(),
            ComponentGraphNodeTerminal::RuntimeUnavailable
        );
        assert_eq!(report.fuel().limit(), principal.fuel_limit());
        assert_eq!(report.fuel().consumed(), 0);
        assert_eq!(
            report.resources().slot_limit(),
            principal.resource_slot_limit()
        );
        assert_eq!(report.resources().peak_slots(), 1);
        assert_eq!(report.resources().live_slots(), 0);

        // The ordinary path remains a distinct zero-resource report even
        // after the supervisor-prepared builder is available.
        let ordinary = template.runtime_unavailable_report(node).unwrap();
        assert_eq!(ordinary.resources().peak_slots(), 0);
        assert_eq!(ordinary.resources().live_slots(), 0);
    }
    let at_limit = template
        .supervisor_prepared_resource_unavailable_report(graph_node(0), 3)
        .expect("the exact manifest slot ceiling is inclusive");
    assert_eq!(at_limit.resources().peak_slots(), 3);
    assert_eq!(at_limit.resources().live_slots(), 0);
    assert!(!template.runtime_ready());
}

#[test]
fn supervisor_prepared_resource_report_rejects_zero_unrouted_unknown_and_over_limit() {
    let resource_template =
        ComponentGraphPrincipalTemplate::new(Arc::new(admitted_resource_graph()))
            .expect("resource template must build");
    assert_eq!(
        resource_template.supervisor_prepared_resource_unavailable_report(graph_node(0), 0),
        Err(ComponentGraphNodeReportError::SupervisorPreparedPeakRequired)
    );
    assert_eq!(
        resource_template.supervisor_prepared_resource_unavailable_report(graph_node(0), 4),
        Err(ComponentGraphNodeReportError::ResourceLimitExceeded)
    );
    let unknown = graph_node(u16::MAX);
    assert_eq!(
        resource_template.supervisor_prepared_resource_unavailable_report(unknown, 1),
        Err(ComponentGraphNodeReportError::UnknownNode { node: unknown })
    );

    let resource_free = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_graph()))
        .expect("resource-free template must build");
    assert_eq!(
        resource_free.supervisor_prepared_resource_unavailable_report(graph_node(0), 1),
        Err(ComponentGraphNodeReportError::ResourceEdgeRequired {
            node: graph_node(0),
        })
    );
    // Its pre-existing ordinary report remains valid and strictly zero.
    assert_eq!(
        resource_free
            .runtime_unavailable_report(graph_node(0))
            .unwrap()
            .resources()
            .peak_slots(),
        0
    );
}

#[test]
fn debug_output_redacts_admitted_graph_and_artifact_identity() {
    let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted_graph()))
        .expect("template must build");
    let identity = template.principals()[0].artifact();
    let digest = identity
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = format!("{template:?}");

    assert!(output.contains("admitted_graph: \"<redacted>\""));
    assert!(output.contains("ComponentIdentity(<redacted>)"));
    assert!(!output.contains(&digest));
    assert!(!output.contains("TaskId"));
    assert!(!output.contains("CSpace"));
    assert!(!output.contains("Cap("));

    let report = template
        .runtime_unavailable_report(ComponentGraphNodeId::new(0))
        .unwrap();
    let report_debug = format!("{report:?}");
    assert!(report_debug.contains("RuntimeUnavailable"));
    assert!(!report_debug.contains("TaskId"));
    assert!(!report_debug.contains("CSpace"));
    assert!(!report_debug.contains("Cap("));
}

#[test]
fn replacement_template_is_exact_inert_send_sync_and_revalidates_twice() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<ComponentGraphNodeReplacementTemplate>();
    let admitted = Arc::new(admitted_async_replacement());
    let manifest = admitted.manifest();
    let template = ComponentGraphNodeReplacementTemplate::new(Arc::clone(&admitted))
        .expect("sealed replacement must project");

    assert!(!template.runtime_ready());
    assert!(core::ptr::eq(
        template.admitted_replacement(),
        admitted.as_ref()
    ));
    assert_eq!(template.target(), graph_node(1));
    assert_eq!(template.max_replacements(), 1);
    assert_eq!(
        template.incident_edges(),
        [recreate(async_edge()), recreate(second_async_edge())]
    );
    assert_eq!(template.transient_account(), manifest.transient_account());
    assert_eq!(template.current_graph().async_edges().len(), 2);
    assert_eq!(template.candidate_graph().async_edges().len(), 2);
    assert_eq!(
        template
            .current_principal()
            .expect("current target projection")
            .label(),
        "async-relay"
    );
    assert_ne!(
        template
            .candidate_principal()
            .expect("candidate target projection")
            .artifact(),
        template
            .current_principal()
            .expect("current target projection")
            .artifact()
    );
    template.revalidate().expect("first template revalidation");
    template.revalidate().expect("second template revalidation");
}

#[test]
fn replacement_template_debug_redacts_graphs_artifacts_and_runtime_identities() {
    let template =
        ComponentGraphNodeReplacementTemplate::new(Arc::new(admitted_async_replacement()))
            .expect("sealed replacement must project");
    let output = format!("{template:?}");

    assert!(output.contains("ComponentGraphNodeReplacementTemplate"));
    assert!(output.contains("<redacted>"));
    assert!(output.contains("max_replacements: 1"));
    assert!(output.contains("RecreateFresh"));
    assert!(output.contains("runtime_ready: false"));
    for forbidden in [
        "ComponentIdentity",
        "async-relay",
        "test:c65-chain",
        "TaskId",
        "CSpace",
        "Cap(",
        "ResourceToken",
        "HostOperationToken",
        "generation",
        "digest",
    ] {
        assert!(
            !output.contains(forbidden),
            "replacement Debug leaked {forbidden}: {output}"
        );
    }
}
