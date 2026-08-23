use std::sync::Arc;

use vibeos_component_admission::{
    admit_component_graph, admit_component_graph_replacement,
    admit_component_graph_with_resource_policy, AdmissionError, AdmittedComponentGraph,
    AdmittedComponentGraphReplacement, ArtifactTrust, AuthorityOffer, CallerAuthority,
    ComponentArtifact, ComponentGraphAdmissionError, ComponentGraphAdmissionPolicy,
    ComponentGraphBindingMismatch, ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy,
    ComponentGraphNodeReplacementPolicy, ComponentGraphReplacementAdmissionError,
    ComponentGraphReplacementEdgeAction, ComponentGraphReplacementEdgePolicy,
    ComponentGraphResourceEdgePolicy, ComponentGraphResourceMode, InstanceLimits, InterfaceCeiling,
    ProfileIdentity, STREAM_FILTER_WORLD,
};
use vibeos_component_format::{LimitKind, PROFILE_1_COMPONENT_GRAPH_LIMITS};
use vibeos_component_host::{HostResourceKind, STREAM_INTERFACE};
use vibeos_component_runtime::{
    graph::{
        ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
        ComponentGraphExternalImportSpec, ComponentGraphImportEndpoint, ComponentGraphNesting,
        ComponentGraphNodeId, ComponentGraphPublishedExportSpec,
    },
    world::WorldContract,
};
use vibeos_core::cap::Rights;

trait GraphAdmissionResultExt {
    fn expect_graph_error(self) -> ComponentGraphAdmissionError;
}

impl GraphAdmissionResultExt for Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    fn expect_graph_error(self) -> ComponentGraphAdmissionError {
        match self {
            Ok(_) => panic!("graph admission unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

trait GraphReplacementAdmissionResultExt {
    fn expect_replacement_error(self) -> ComponentGraphReplacementAdmissionError;
}

impl GraphReplacementAdmissionResultExt
    for Result<AdmittedComponentGraphReplacement, ComponentGraphReplacementAdmissionError>
{
    fn expect_replacement_error(self) -> ComponentGraphReplacementAdmissionError {
        match self {
            Ok(_) => panic!("graph replacement admission unexpectedly succeeded"),
            Err(error) => error,
        }
    }
}

const PIPE_WIT: &str = r#"
    package test:c62@1.0.0;

    interface pipe {
        send: func(value: u32) -> u32;
    }

    world producer {
        export pipe;
    }

    world consumer {
        import pipe;
    }

    world relay {
        import pipe;
        export pipe;
    }
"#;

const PRODUCER_WORLD: &str = "test:c62/producer@1.0.0";
const CONSUMER_WORLD: &str = "test:c62/consumer@1.0.0";
const RELAY_WORLD: &str = "test:c62/relay@1.0.0";

const PRODUCER_WAT: &str = r#"
    (component
      (core module $module
        (func (export "send") (param i32) (result i32)
          local.get 0))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send" (core func $send-core))
      (type $send-type (func (param "value" u32) (result u32)))
      (func $send (type $send-type) (canon lift (core func $send-core)))
      (instance $pipe (export "send" (func $send)))
      (export "test:c62/pipe@1.0.0" (instance $pipe)))
"#;

const CONSUMER_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (type $send-type (func (param "value" u32) (result u32)))
          (export "send" (func (type $send-type)))))
      (import "test:c62/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const RELAY_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (type $send-type (func (param "value" u32) (result u32)))
          (export "send" (func (type $send-type)))))
      (import "test:c62/pipe@1.0.0" (instance $pipe-in (type $pipe)))
      (core module $module
        (func (export "send") (param i32) (result i32)
          local.get 0))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send" (core func $send-core))
      (type $send-type (func (param "value" u32) (result u32)))
      (func $send (type $send-type) (canon lift (core func $send-core)))
      (instance $pipe-out (export "send" (func $send)))
      (export "test:c62/pipe@1.0.0" (instance $pipe-out)))
"#;

const PRODUCER_V2_WAT: &str = r#"
    (component
      (core module $module
        (func (export "send") (param i32) (result i32)
          local.get 0
          i32.const 2
          i32.add))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send" (core func $send-core))
      (type $send-type (func (param "value" u32) (result u32)))
      (func $send (type $send-type) (canon lift (core func $send-core)))
      (instance $pipe (export "send" (func $send)))
      (export "test:c62/pipe@1.0.0" (instance $pipe)))
"#;

const RELAY_V2_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (type $send-type (func (param "value" u32) (result u32)))
          (export "send" (func (type $send-type)))))
      (import "test:c62/pipe@1.0.0" (instance $pipe-in (type $pipe)))
      (core module $module
        (func (export "send") (param i32) (result i32)
          local.get 0
          i32.const 1
          i32.add))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send" (core func $send-core))
      (type $send-type (func (param "value" u32) (result u32)))
      (func $send (type $send-type) (canon lift (core func $send-core)))
      (instance $pipe-out (export "send" (func $send)))
      (export "test:c62/pipe@1.0.0" (instance $pipe-out)))
"#;

const DIRECT_WIT: &str = r#"
    package test:c62-direct@1.0.0;

    world producer {
        export out: func(value: u32) -> u32;
    }

    world consumer {
        import input: func(value: u32) -> u32;
    }
"#;

const DIRECT_PRODUCER_WAT: &str = r#"
    (component
      (core module $module
        (func (export "out") (param i32) (result i32)
          local.get 0))
      (core instance $instance (instantiate $module))
      (alias core export $instance "out" (core func $out-core))
      (type $out-type (func (param "value" u32) (result u32)))
      (func $out (type $out-type) (canon lift (core func $out-core)))
      (export "out" (func $out)))
"#;

const DIRECT_CONSUMER_WAT: &str = r#"
    (component
      (type $input-type (func (param "value" u32) (result u32)))
      (import "input" (func $input (type $input-type))))
"#;

const REORDERED_WORLD_WIT: &str = r#"
    package test:c62-order@1.0.0;

    world two-exports {
        export alpha: func() -> u32;
        export beta: func() -> u32;
    }
"#;

const REORDERED_WORLD_WAT: &str = r#"
    (component
      (core module $module
        (func (export "alpha") (result i32) i32.const 1)
        (func (export "beta") (result i32) i32.const 2))
      (core instance $instance (instantiate $module))
      (type $value (func (result u32)))
      (func $alpha (type $value) (canon lift (core func $instance "alpha")))
      (func $beta (type $value) (canon lift (core func $instance "beta")))
      (export "alpha" (func $alpha))
      (export "beta" (func $beta)))
"#;

const RESOURCE_WIT: &str = r#"
    package test:c62-resource@1.0.0;

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

const RESOURCE_PRODUCER_WORLD: &str = "test:c62-resource/producer@1.0.0";
const RESOURCE_CONSUMER_WORLD: &str = "test:c62-resource/consumer@1.0.0";

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
      (export "test:c62-resource/pipe@1.0.0" (instance $pipe)))
"#;

const RESOURCE_CONSUMER_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (export "handle" (type $handle (sub resource)))
          (type $borrow-handle (borrow $handle))
          (type $send-type (func (param "value" $borrow-handle)))
          (export "send" (func (type $send-type)))))
      (import "test:c62-resource/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const MIXED_RESOURCE_WIT: &str = r#"
    package test:c62-resource@1.0.0;

    interface pipe {
        resource handle;
        send-borrow: func(value: borrow<handle>);
        send-own: func(value: option<own<handle>>);
    }

    world producer {
        export pipe;
    }

    world consumer {
        import pipe;
    }
"#;

const MIXED_RESOURCE_PRODUCER_WAT: &str = r#"
    (component
      (type $handle (resource (rep i32)))
      (type $borrow-handle (borrow $handle))
      (type $own-handle (own $handle))
      (type $maybe-own (option $own-handle))
      (type $borrow-type (func (param "value" $borrow-handle)))
      (type $own-type (func (param "value" $maybe-own)))
      (core module $module
        (func (export "send-borrow") (param i32))
        (func (export "send-own") (param i32 i32)))
      (core instance $instance (instantiate $module))
      (alias core export $instance "send-borrow" (core func $borrow-core))
      (alias core export $instance "send-own" (core func $own-core))
      (func $send-borrow (type $borrow-type) (canon lift (core func $borrow-core)))
      (func $send-own (type $own-type) (canon lift (core func $own-core)))
      (instance $pipe
        (export "handle" (type $handle))
        (export "send-borrow" (func $send-borrow))
        (export "send-own" (func $send-own)))
      (export "test:c62-resource/pipe@1.0.0" (instance $pipe)))
"#;

const MIXED_RESOURCE_CONSUMER_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (export "handle" (type $handle (sub resource)))
          (type $borrow-handle (borrow $handle))
          (type $own-handle (own $handle))
          (type $maybe-own (option $own-handle))
          (type $borrow-type (func (param "value" $borrow-handle)))
          (type $own-type (func (param "value" $maybe-own)))
          (export "send-borrow" (func (type $borrow-type)))
          (export "send-own" (func (type $own-type)))))
      (import "test:c62-resource/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const AMBIGUOUS_RESOURCE_WIT: &str = r#"
    package test:c62-resource@1.0.0;

    interface pipe {
        resource first;
        resource second;
    }

    world producer {
        export pipe;
    }

    world consumer {
        import pipe;
    }
"#;

const AMBIGUOUS_RESOURCE_PRODUCER_WAT: &str = r#"
    (component
      (type $handle (resource (rep i32)))
      (instance $pipe
        (export "first" (type $handle))
        (export "second" (type $handle)))
      (export "test:c62-resource/pipe@1.0.0" (instance $pipe)))
"#;

const AMBIGUOUS_RESOURCE_CONSUMER_WAT: &str = r#"
    (component
      (type $pipe
        (instance
          (export "first" (type $handle (sub resource)))
          (export "second" (type (eq $handle)))))
      (import "test:c62-resource/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const STREAM_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-stream.component.wat");
const STREAM_WIT: &str = include_str!("../../../component-format/tests/corpus/wit/stream.wit");
const ASYNC_CHAIN_WIT: &str = include_str!("../../../policy/image/artifacts/c65-async-chain.wit");
const ASYNC_SOURCE_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-source.component.wat");
const ASYNC_RELAY_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-relay.component.wat");
const ASYNC_SINK_WAT: &str =
    include_str!("../../../policy/image/artifacts/c65-async-sink.component.wat");
const ASYNC_SOURCE_WORLD: &str = "test:c65-chain/source@1.0.0";
const ASYNC_RELAY_WORLD: &str = "test:c65-chain/relay@1.0.0";
const ASYNC_SINK_WORLD: &str = "test:c65-chain/sink@1.0.0";

fn node(index: u16) -> ComponentGraphNodeId {
    ComponentGraphNodeId::new(index)
}

fn entity(index: u16) -> ComponentGraphEntityIndex {
    ComponentGraphEntityIndex::new(index)
}

fn export(node_index: u16, export_index: u16) -> ComponentGraphExportEndpoint {
    ComponentGraphExportEndpoint::new(node(node_index), entity(export_index))
}

fn import(node_index: u16, import_index: u16) -> ComponentGraphImportEndpoint {
    ComponentGraphImportEndpoint::new(node(node_index), entity(import_index))
}

fn edge(source_node: u16, target_node: u16) -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(export(source_node, 0), import(target_node, 0))
}

fn limits() -> InstanceLimits {
    InstanceLimits {
        memory_bytes: 64 * 1024,
        total_fuel: 1_000,
        poll_quantum: 100,
        resources: 16,
    }
}

fn artifact(source: &str) -> ComponentArtifact {
    let bytes = wat::parse_str(source).expect("component WAT must parse");
    ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1)
        .expect("component artifact must fit the profile")
}

fn async_artifact(source: &str) -> ComponentArtifact {
    let bytes = wat::parse_str(source).expect("async component WAT must parse");
    ComponentArtifact::copy_from(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("async component artifact must fit the profile")
}

fn world(source: &str, identity: &str) -> WorldContract {
    WorldContract::parse(source, identity).expect("trusted WIT world must parse")
}

fn policy_node<'a>(
    label: &'a str,
    exact_world: &'a WorldContract,
    artifact: &ComponentArtifact,
    interfaces: &'a [InterfaceCeiling<'a>],
) -> ComponentGraphNodeAdmissionPolicy<'a> {
    ComponentGraphNodeAdmissionPolicy {
        label,
        nesting: ComponentGraphNesting::Root,
        exact_world,
        trust: ArtifactTrust::ImagePinned(artifact.identity()),
        limits: limits(),
        interfaces,
    }
}

fn admit_pair(
    consumer_wit: &str,
    consumer_world_identity: &str,
    consumer_wat: &str,
    edges: &[ComponentGraphEdgeSpec],
    external_imports: &[ComponentGraphExternalImportSpec],
    published_exports: &[ComponentGraphPublishedExportSpec],
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let provider_world = world(PIPE_WIT, PRODUCER_WORLD);
    let consumer_world = world(consumer_wit, consumer_world_identity);
    let provider = artifact(PRODUCER_WAT);
    let consumer = artifact(consumer_wat);
    let nodes = [
        policy_node("provider", &provider_world, &provider, &[]),
        policy_node("consumer", &consumer_world, &consumer, &[]),
    ];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-free-pipe",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges,
        external_imports,
        published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(
        vec![provider, consumer],
        &policy,
        &CallerAuthority { offers: &[] },
    )
}

fn admit_resource_pair(
    exact_wit: &str,
    producer_wat: &str,
    consumer_wat: &str,
    resource_policy: &[ComponentGraphResourceEdgePolicy],
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let producer_world = world(exact_wit, RESOURCE_PRODUCER_WORLD);
    let consumer_world = world(exact_wit, RESOURCE_CONSUMER_WORLD);
    let producer = artifact(producer_wat);
    let consumer = artifact(consumer_wat);
    let nodes = [
        policy_node("resource-provider", &producer_world, &producer, &[]),
        policy_node("resource-consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-edge",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph_with_resource_policy(
        vec![producer, consumer],
        &policy,
        resource_policy,
        &CallerAuthority { offers: &[] },
    )
}

fn admit_async_pair() -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let source_world = world(ASYNC_CHAIN_WIT, ASYNC_SOURCE_WORLD);
    let relay_world = world(ASYNC_CHAIN_WIT, ASYNC_RELAY_WORLD);
    let source = async_artifact(ASYNC_SOURCE_WAT);
    let relay = async_artifact(ASYNC_RELAY_WAT);
    let nodes = [
        policy_node("async-source", &source_world, &source, &[]),
        policy_node("async-relay", &relay_world, &relay, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "async-edge-evidence",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(
        vec![source, relay],
        &policy,
        &CallerAuthority { offers: &[] },
    )
}

fn admit_async_chain() -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let source_world = world(ASYNC_CHAIN_WIT, ASYNC_SOURCE_WORLD);
    let relay_world = world(ASYNC_CHAIN_WIT, ASYNC_RELAY_WORLD);
    let sink_world = world(ASYNC_CHAIN_WIT, ASYNC_SINK_WORLD);
    let source = async_artifact(ASYNC_SOURCE_WAT);
    let relay = async_artifact(ASYNC_RELAY_WAT);
    let sink = async_artifact(ASYNC_SINK_WAT);
    let nodes = [
        policy_node("async-source", &source_world, &source, &[]),
        policy_node("async-relay", &relay_world, &relay, &[]),
        policy_node("async-sink", &sink_world, &sink, &[]),
    ];
    let edges = [edge(0, 1), edge(1, 2)];
    let published_exports = [ComponentGraphPublishedExportSpec::new(export(2, 0))];
    let policy = ComponentGraphAdmissionPolicy {
        name: "async-chain-evidence",
        profile: ProfileIdentity::PROFILE_1_ASYNC,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(
        vec![source, relay, sink],
        &policy,
        &CallerAuthority { offers: &[] },
    )
}

fn recreate(edge: ComponentGraphEdgeSpec) -> ComponentGraphReplacementEdgePolicy {
    ComponentGraphReplacementEdgePolicy {
        edge,
        action: ComponentGraphReplacementEdgeAction::RecreateFresh,
    }
}

fn admit_replacement_chain_with(
    producer_wat: &str,
    relay_wat: &str,
    relay_limits: InstanceLimits,
    relay_nesting: ComponentGraphNesting,
    publish_relay: bool,
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let producer_world = world(PIPE_WIT, PRODUCER_WORLD);
    let relay_world = world(PIPE_WIT, RELAY_WORLD);
    let consumer_world = world(PIPE_WIT, CONSUMER_WORLD);
    let producer = artifact(producer_wat);
    let relay = artifact(relay_wat);
    let consumer = artifact(CONSUMER_WAT);
    let mut relay_policy = policy_node("relay", &relay_world, &relay, &[]);
    relay_policy.limits = relay_limits;
    relay_policy.nesting = relay_nesting;
    let nodes = [
        policy_node("producer", &producer_world, &producer, &[]),
        relay_policy,
        policy_node("consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1), edge(1, 2)];
    let published_exports = if publish_relay {
        vec![ComponentGraphPublishedExportSpec::new(export(1, 0))]
    } else {
        Vec::new()
    };
    let policy = ComponentGraphAdmissionPolicy {
        name: "replacement-chain",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(
        vec![producer, relay, consumer],
        &policy,
        &CallerAuthority { offers: &[] },
    )
}

fn admitted_replacement_chain(relay_wat: &str) -> Arc<AdmittedComponentGraph> {
    Arc::new(
        admit_replacement_chain_with(
            PRODUCER_WAT,
            relay_wat,
            limits(),
            ComponentGraphNesting::Root,
            false,
        )
        .expect("replacement chain must admit"),
    )
}

fn admitted_max_node_replacement_graph() -> Arc<AdmittedComponentGraph> {
    const LABELS: [&str; 16] = [
        "replacement-node-00",
        "replacement-node-01",
        "replacement-node-02",
        "replacement-node-03",
        "replacement-node-04",
        "replacement-node-05",
        "replacement-node-06",
        "replacement-node-07",
        "replacement-node-08",
        "replacement-node-09",
        "replacement-node-10",
        "replacement-node-11",
        "replacement-node-12",
        "replacement-node-13",
        "replacement-node-14",
        "replacement-node-15",
    ];

    assert_eq!(
        LABELS.len(),
        PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes as usize
    );
    let exact_world = world(PIPE_WIT, PRODUCER_WORLD);
    let artifacts = LABELS
        .iter()
        .map(|_| artifact(PRODUCER_WAT))
        .collect::<Vec<_>>();
    let nodes = LABELS
        .iter()
        .zip(&artifacts)
        .map(|(label, artifact)| policy_node(label, &exact_world, artifact, &[]))
        .collect::<Vec<_>>();
    let policy = ComponentGraphAdmissionPolicy {
        name: "replacement-capacity",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &[],
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    Arc::new(
        admit_component_graph(artifacts, &policy, &CallerAuthority { offers: &[] })
            .expect("graph at the exact node ceiling must independently admit"),
    )
}

fn admit_provider(
    published_exports: &[ComponentGraphPublishedExportSpec],
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let exact_world = world(PIPE_WIT, PRODUCER_WORLD);
    let provider = artifact(PRODUCER_WAT);
    let nodes = [policy_node("provider", &exact_world, &provider, &[])];
    let policy = ComponentGraphAdmissionPolicy {
        name: "published-pipe",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &[],
        external_imports: &[],
        published_exports,
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(vec![provider], &policy, &CallerAuthority { offers: &[] })
}

#[test]
fn two_independently_parsed_nodes_admit_as_owned_inert_send_and_revalidate_twice() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<AdmittedComponentGraph>();
    let graph = admit_pair(
        PIPE_WIT,
        CONSUMER_WORLD,
        CONSUMER_WAT,
        &[edge(0, 1)],
        &[],
        &[],
    )
    .expect("exact resource-free interface graph must admit");

    assert!(!graph.runtime_ready());
    assert_eq!(graph.manifest().name(), "resource-free-pipe");
    assert_eq!(graph.manifest().profile(), ProfileIdentity::PROFILE_1);
    assert_eq!(graph.manifest().nodes().len(), 2);
    assert_eq!(graph.manifest().edges(), [edge(0, 1)]);
    assert_eq!(graph.manifest().account().nodes, 2);
    assert_eq!(graph.manifest().account().edges, 1);
    assert!(graph.manifest().async_edges().is_empty());
    assert_eq!(graph.node_inspections().len(), 2);
    assert_eq!(graph.node_inspections()[0].world(), PRODUCER_WORLD);
    assert_eq!(graph.node_inspections()[1].world(), CONSUMER_WORLD);
    assert!(graph.grants().is_empty());
    graph.revalidate().expect("first complete revalidation");
    graph.revalidate().expect("second complete revalidation");
}

#[test]
fn recursive_async_edge_evidence_is_exact_bounded_inert_and_revalidated() {
    let graph = admit_async_pair().expect("exact async interface graph must admit");

    assert!(!graph.runtime_ready());
    assert_eq!(graph.manifest().async_edges().len(), 1);
    let route = &graph.manifest().async_edges()[0];
    assert_eq!(route.edge(), edge(0, 1));
    assert_eq!(route.async_functions(), 1);
    assert_eq!(route.streams(), 4);
    assert_eq!(route.futures(), 4);
    assert!(
        route.async_functions()
            <= vibeos_component_format::PROFILE_1_LIMITS.max_component_definitions
    );
    assert!(route.streams() <= vibeos_component_format::PROFILE_1_LIMITS.max_component_definitions);
    assert!(route.futures() <= vibeos_component_format::PROFILE_1_LIMITS.max_component_definitions);
    assert!(graph.manifest().resource_edges().is_empty());

    let debug = format!("{route:?}");
    assert!(debug.contains("async_functions"));
    assert!(debug.contains("streams"));
    assert!(debug.contains("futures"));
    for forbidden in ["Task", "CSpace", "HostOperationToken", "Cap(", "generation"] {
        assert!(
            !debug.contains(forbidden),
            "debug leaked {forbidden}: {debug}"
        );
    }

    graph.revalidate().expect("first fresh async derivation");
    graph.revalidate().expect("second fresh async derivation");
}

#[test]
fn multi_hop_async_evidence_preserves_edge_order_and_published_sink() {
    let graph = admit_async_chain().expect("source-to-relay-to-sink graph must admit");

    assert!(!graph.runtime_ready());
    assert_eq!(graph.manifest().edges(), [edge(0, 1), edge(1, 2)]);
    assert_eq!(graph.manifest().async_edges().len(), 2);
    for (route, expected_edge) in graph
        .manifest()
        .async_edges()
        .iter()
        .zip([edge(0, 1), edge(1, 2)])
    {
        assert_eq!(route.edge(), expected_edge);
        assert_eq!(route.async_functions(), 1);
        assert_eq!(route.streams(), 4);
        assert_eq!(route.futures(), 4);
    }
    assert_eq!(
        graph.manifest().published_exports(),
        [ComponentGraphPublishedExportSpec::new(export(2, 0))]
    );
    graph
        .revalidate()
        .expect("all hops require fresh exact async evidence");
}

#[test]
fn reordered_name_keyed_world_policy_revalidates_against_the_same_contract() {
    let mut exact_world = world(REORDERED_WORLD_WIT, "test:c62-order/two-exports@1.0.0");
    exact_world.exports.swap(0, 1);
    let component = artifact(REORDERED_WORLD_WAT);
    let nodes = [policy_node("ordered", &exact_world, &component, &[])];
    let policy = ComponentGraphAdmissionPolicy {
        name: "reordered-policy",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &[],
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    let graph = admit_component_graph(vec![component], &policy, &CallerAuthority { offers: &[] })
        .expect("top-level world entities are name-keyed");
    graph
        .revalidate()
        .expect("canonical policy commitment must ignore top-level order");
}

#[test]
fn missing_and_duplicate_import_bindings_fail_closed() {
    let target = import(1, 0);
    assert_eq!(
        admit_pair(PIPE_WIT, CONSUMER_WORLD, CONSUMER_WAT, &[], &[], &[]).expect_graph_error(),
        ComponentGraphAdmissionError::MissingBinding { target }
    );

    let duplicate = [edge(0, 1), edge(0, 1)];
    assert_eq!(
        admit_pair(PIPE_WIT, CONSUMER_WORLD, CONSUMER_WAT, &duplicate, &[], &[],)
            .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateBinding { target }
    );
}

#[test]
fn internal_plus_external_binding_is_an_ordinary_duplicate() {
    let target = import(1, 0);
    let external = [ComponentGraphExternalImportSpec::new(target)];
    assert_eq!(
        admit_pair(
            PIPE_WIT,
            CONSUMER_WORLD,
            CONSUMER_WAT,
            &[edge(0, 1)],
            &external,
            &[],
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateBinding { target }
    );
}

#[test]
fn exact_interface_version_and_type_mismatches_are_distinct() {
    let adjacent_wit = PIPE_WIT.replace("@1.0.0", "@2.0.0");
    let adjacent_wat = CONSUMER_WAT.replace("@1.0.0", "@2.0.0");
    assert_eq!(
        admit_pair(
            &adjacent_wit,
            "test:c62/consumer@2.0.0",
            &adjacent_wat,
            &[edge(0, 1)],
            &[],
            &[],
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::BindingMismatch {
            edge: 0,
            kind: ComponentGraphBindingMismatch::InterfaceVersion,
        }
    );

    let wrong_type_wit = PIPE_WIT.replace("u32", "u64");
    let wrong_type_wat = CONSUMER_WAT.replace("u32", "u64");
    assert_eq!(
        admit_pair(
            &wrong_type_wit,
            CONSUMER_WORLD,
            &wrong_type_wat,
            &[edge(0, 1)],
            &[],
            &[],
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::BindingMismatch {
            edge: 0,
            kind: ComponentGraphBindingMismatch::Type,
        }
    );
}

#[test]
fn direct_non_interface_edge_is_rejected_even_when_function_shapes_match() {
    let provider_world = world(DIRECT_WIT, "test:c62-direct/producer@1.0.0");
    let consumer_world = world(DIRECT_WIT, "test:c62-direct/consumer@1.0.0");
    let provider = artifact(DIRECT_PRODUCER_WAT);
    let consumer = artifact(DIRECT_CONSUMER_WAT);
    let nodes = [
        policy_node("direct-provider", &provider_world, &provider, &[]),
        policy_node("direct-consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "direct-functions",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![provider, consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::UnsupportedBindingSurface { edge: 0 }
    );
}

#[test]
fn exact_resource_edge_requires_explicit_policy() {
    let producer_world = world(RESOURCE_WIT, RESOURCE_PRODUCER_WORLD);
    let consumer_world = world(RESOURCE_WIT, RESOURCE_CONSUMER_WORLD);
    let left = artifact(RESOURCE_PRODUCER_WAT);
    let right = artifact(RESOURCE_CONSUMER_WAT);
    let nodes = [
        policy_node("resource-provider", &producer_world, &left, &[]),
        policy_node("resource-consumer", &consumer_world, &right, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-edge",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(vec![left, right], &policy, &CallerAuthority { offers: &[] },)
            .expect_graph_error(),
        ComponentGraphAdmissionError::UnauthorizedResourceBinding { edge: 0 }
    );
}

#[test]
fn exact_borrow_resource_edge_is_inert_owned_and_freshly_revalidated() {
    let routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    let graph = admit_resource_pair(
        RESOURCE_WIT,
        RESOURCE_PRODUCER_WAT,
        RESOURCE_CONSUMER_WAT,
        &routes,
    )
    .expect("exact borrow policy and nominal provenance must admit");

    assert!(!graph.runtime_ready());
    assert!(graph.grants().is_empty());
    assert_eq!(graph.manifest().resource_edges().len(), 1);
    assert!(graph.manifest().async_edges().is_empty());
    let route = &graph.manifest().resource_edges()[0];
    assert_eq!(route.edge(), edge(0, 1));
    assert_eq!(route.mode(), ComponentGraphResourceMode::Borrow);
    assert_eq!(route.resources(), [String::from("handle")]);
    graph
        .revalidate()
        .expect("revalidation must obtain fresh exact provenance");
}

#[test]
fn exact_own_resource_edge_is_inert_and_revalidated() {
    let own_wit = RESOURCE_WIT.replace("borrow<handle>", "own<handle>");
    let own_producer = RESOURCE_PRODUCER_WAT.replace("(borrow $handle)", "(own $handle)");
    let own_consumer = RESOURCE_CONSUMER_WAT.replace("(borrow $handle)", "(own $handle)");
    let routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Own,
    }];
    let graph = admit_resource_pair(&own_wit, &own_producer, &own_consumer, &routes)
        .expect("exact own policy and nominal provenance must admit");

    assert!(!graph.runtime_ready());
    assert_eq!(
        graph.manifest().resource_edges()[0].mode(),
        ComponentGraphResourceMode::Own
    );
    graph.revalidate().expect("fresh own provenance");
}

#[test]
fn nested_mixed_resource_modes_require_the_exact_combined_policy() {
    let routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::OwnAndBorrow,
    }];
    let graph = admit_resource_pair(
        MIXED_RESOURCE_WIT,
        MIXED_RESOURCE_PRODUCER_WAT,
        MIXED_RESOURCE_CONSUMER_WAT,
        &routes,
    )
    .expect("nested own plus direct borrow must be derived recursively");
    assert_eq!(
        graph.manifest().resource_edges()[0].mode(),
        ComponentGraphResourceMode::OwnAndBorrow
    );
    graph.revalidate().expect("fresh mixed provenance");
}

#[test]
fn resource_policy_must_be_exact_and_cannot_attach_to_a_resource_free_edge() {
    for wrong in [
        ComponentGraphResourceMode::Own,
        ComponentGraphResourceMode::OwnAndBorrow,
    ] {
        let routes = [ComponentGraphResourceEdgePolicy {
            edge: edge(0, 1),
            mode: wrong,
        }];
        assert_eq!(
            admit_resource_pair(
                RESOURCE_WIT,
                RESOURCE_PRODUCER_WAT,
                RESOURCE_CONSUMER_WAT,
                &routes,
            )
            .expect_graph_error(),
            ComponentGraphAdmissionError::UnauthorizedResourceBinding { edge: 0 }
        );
    }

    let provider_world = world(PIPE_WIT, PRODUCER_WORLD);
    let consumer_world = world(PIPE_WIT, CONSUMER_WORLD);
    let provider = artifact(PRODUCER_WAT);
    let consumer = artifact(CONSUMER_WAT);
    let nodes = [
        policy_node("provider", &provider_world, &provider, &[]),
        policy_node("consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-free-extra-policy",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    let routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    assert_eq!(
        admit_component_graph_with_resource_policy(
            vec![provider, consumer],
            &policy,
            &routes,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::UnauthorizedResourceBinding { edge: 0 }
    );
}

#[test]
fn duplicate_or_unknown_resource_policy_is_invalid() {
    let route = ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Borrow,
    };
    assert_eq!(
        admit_resource_pair(
            RESOURCE_WIT,
            RESOURCE_PRODUCER_WAT,
            RESOURCE_CONSUMER_WAT,
            &[route, route],
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::InvalidPolicy
    );

    let unknown = [ComponentGraphResourceEdgePolicy {
        edge: edge(1, 0),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    assert_eq!(
        admit_resource_pair(
            RESOURCE_WIT,
            RESOURCE_PRODUCER_WAT,
            RESOURCE_CONSUMER_WAT,
            &unknown,
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::InvalidPolicy
    );
}

#[test]
fn matching_surface_without_exact_nominal_roots_fails_before_policy() {
    let routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    assert_eq!(
        admit_resource_pair(
            AMBIGUOUS_RESOURCE_WIT,
            AMBIGUOUS_RESOURCE_PRODUCER_WAT,
            AMBIGUOUS_RESOURCE_CONSUMER_WAT,
            &routes,
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::UnsupportedResourceBinding { edge: 0 }
    );
}

#[test]
fn resource_bearing_source_fanout_is_rejected_before_route_admission() {
    let producer_world = world(RESOURCE_WIT, RESOURCE_PRODUCER_WORLD);
    let first_consumer_world = world(RESOURCE_WIT, RESOURCE_CONSUMER_WORLD);
    let second_consumer_world = world(RESOURCE_WIT, RESOURCE_CONSUMER_WORLD);
    let provider = artifact(RESOURCE_PRODUCER_WAT);
    let first_consumer = artifact(RESOURCE_CONSUMER_WAT);
    let second_consumer = artifact(RESOURCE_CONSUMER_WAT);
    let nodes = [
        policy_node("resource-provider", &producer_world, &provider, &[]),
        policy_node(
            "resource-consumer-a",
            &first_consumer_world,
            &first_consumer,
            &[],
        ),
        policy_node(
            "resource-consumer-b",
            &second_consumer_world,
            &second_consumer,
            &[],
        ),
    ];
    let edges = [edge(0, 1), edge(0, 2)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-fanout",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![provider, first_consumer, second_consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateResourceSource {
            source: export(0, 0),
        }
    );
}

#[test]
fn owned_resource_source_fanout_is_also_rejected_conservatively() {
    let own_wit = RESOURCE_WIT.replace("borrow<handle>", "own<handle>");
    let own_producer_wat = RESOURCE_PRODUCER_WAT.replace("(borrow $handle)", "(own $handle)");
    let own_consumer_wat = RESOURCE_CONSUMER_WAT.replace("(borrow $handle)", "(own $handle)");
    let producer_world = world(&own_wit, RESOURCE_PRODUCER_WORLD);
    let first_consumer_world = world(&own_wit, RESOURCE_CONSUMER_WORLD);
    let second_consumer_world = world(&own_wit, RESOURCE_CONSUMER_WORLD);
    let provider = artifact(&own_producer_wat);
    let first_consumer = artifact(&own_consumer_wat);
    let second_consumer = artifact(&own_consumer_wat);
    let nodes = [
        policy_node("own-provider", &producer_world, &provider, &[]),
        policy_node(
            "own-consumer-a",
            &first_consumer_world,
            &first_consumer,
            &[],
        ),
        policy_node(
            "own-consumer-b",
            &second_consumer_world,
            &second_consumer,
            &[],
        ),
    ];
    let edges = [edge(0, 1), edge(0, 2)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "owned-resource-fanout",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![provider, first_consumer, second_consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateResourceSource {
            source: export(0, 0),
        }
    );
}

#[test]
fn resource_free_source_fanout_remains_admissible() {
    let producer_world = world(PIPE_WIT, PRODUCER_WORLD);
    let first_consumer_world = world(PIPE_WIT, CONSUMER_WORLD);
    let second_consumer_world = world(PIPE_WIT, CONSUMER_WORLD);
    let provider = artifact(PRODUCER_WAT);
    let first_consumer = artifact(CONSUMER_WAT);
    let second_consumer = artifact(CONSUMER_WAT);
    let nodes = [
        policy_node("provider", &producer_world, &provider, &[]),
        policy_node("consumer-a", &first_consumer_world, &first_consumer, &[]),
        policy_node("consumer-b", &second_consumer_world, &second_consumer, &[]),
    ];
    let edges = [edge(0, 1), edge(0, 2)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-free-fanout",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    let graph = admit_component_graph(
        vec![provider, first_consumer, second_consumer],
        &policy,
        &CallerAuthority { offers: &[] },
    )
    .expect("resource-free interfaces may have explicit fanout");
    assert_eq!(graph.manifest().edges(), edges);
    assert!(graph.grants().is_empty());
}

#[test]
fn resource_ownership_mismatch_is_rejected_before_nominal_provenance() {
    let consumer_wit = RESOURCE_WIT.replace("borrow<handle>", "own<handle>");
    let consumer_wat = RESOURCE_CONSUMER_WAT.replace("(borrow $handle)", "(own $handle)");
    let producer_world = world(RESOURCE_WIT, RESOURCE_PRODUCER_WORLD);
    let consumer_world = world(&consumer_wit, RESOURCE_CONSUMER_WORLD);
    let provider = artifact(RESOURCE_PRODUCER_WAT);
    let consumer = artifact(&consumer_wat);
    let nodes = [
        policy_node("resource-provider", &producer_world, &provider, &[]),
        policy_node("resource-consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-ownership",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![provider, consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::BindingMismatch {
            edge: 0,
            kind: ComponentGraphBindingMismatch::Ownership,
        }
    );
}

#[test]
fn internal_plus_external_resource_binding_reports_the_resource_duplicate() {
    let producer_world = world(RESOURCE_WIT, RESOURCE_PRODUCER_WORLD);
    let consumer_world = world(RESOURCE_WIT, RESOURCE_CONSUMER_WORLD);
    let provider = artifact(RESOURCE_PRODUCER_WAT);
    let consumer = artifact(RESOURCE_CONSUMER_WAT);
    let nodes = [
        policy_node("resource-provider", &producer_world, &provider, &[]),
        policy_node("resource-consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let target = import(1, 0);
    let external = [ComponentGraphExternalImportSpec::new(target)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "resource-duplicate",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &external,
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![provider, consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateResourceBinding { target }
    );
}

#[test]
fn self_and_two_node_dependency_cycles_are_rejected() {
    let exact_world = world(PIPE_WIT, RELAY_WORLD);
    let self_relay = artifact(RELAY_WAT);
    let self_nodes = [policy_node("self-relay", &exact_world, &self_relay, &[])];
    let self_edges = [edge(0, 0)];
    let self_policy = ComponentGraphAdmissionPolicy {
        name: "self-cycle",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &self_nodes,
        edges: &self_edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![self_relay],
            &self_policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DependencyCycle { node: node(0) }
    );

    let left = artifact(RELAY_WAT);
    let right = artifact(RELAY_WAT);
    let nodes = [
        policy_node("cycle-left", &exact_world, &left, &[]),
        policy_node("cycle-right", &exact_world, &right, &[]),
    ];
    let edges = [edge(0, 1), edge(1, 0)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "two-node-cycle",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(vec![left, right], &policy, &CallerAuthority { offers: &[] },)
            .expect_graph_error(),
        ComponentGraphAdmissionError::DependencyCycle { node: node(0) }
    );

    let first = artifact(RELAY_WAT);
    let second = artifact(RELAY_WAT);
    let third = artifact(RELAY_WAT);
    let nodes = [
        policy_node("cycle-first", &exact_world, &first, &[]),
        policy_node("cycle-second", &exact_world, &second, &[]),
        policy_node("cycle-third", &exact_world, &third, &[]),
    ];
    let edges = [edge(0, 1), edge(1, 2), edge(2, 0)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "three-node-cycle",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![first, second, third],
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DependencyCycle { node: node(0) }
    );
}

#[test]
fn duplicate_published_export_is_rejected() {
    let source = export(0, 0);
    let published = [
        ComponentGraphPublishedExportSpec::new(source),
        ComponentGraphPublishedExportSpec::new(source),
    ];
    assert_eq!(
        admit_provider(&published).expect_graph_error(),
        ComponentGraphAdmissionError::DuplicatePublishedExport { source }
    );
}

fn stream_ceilings() -> [InterfaceCeiling<'static>; 2] {
    [
        InterfaceCeiling {
            label: "stdin",
            interface: STREAM_INTERFACE,
            kind: HostResourceKind::ByteStreamReader,
            rights: Rights::RECV,
        },
        InterfaceCeiling {
            label: "stdout",
            interface: STREAM_INTERFACE,
            kind: HostResourceKind::ByteStreamWriter,
            rights: Rights::SEND,
        },
    ]
}

fn stream_offers() -> [AuthorityOffer<'static>; 2] {
    [
        AuthorityOffer {
            label: "stdin",
            kind: HostResourceKind::ByteStreamReader,
            grantable: Rights::RECV,
        },
        AuthorityOffer {
            label: "stdout",
            kind: HostResourceKind::ByteStreamWriter,
            grantable: Rights::SEND,
        },
    ]
}

fn admit_stream(
    ceilings: &[InterfaceCeiling<'_>],
    offers: &[AuthorityOffer<'_>],
) -> Result<AdmittedComponentGraph, ComponentGraphAdmissionError> {
    let exact_world = world(STREAM_WIT, STREAM_FILTER_WORLD);
    let stream = artifact(STREAM_COMPONENT);
    let nodes = [policy_node(
        "stream-filter",
        &exact_world,
        &stream,
        ceilings,
    )];
    let external = [ComponentGraphExternalImportSpec::new(import(0, 0))];
    let policy = ComponentGraphAdmissionPolicy {
        name: "external-stream",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &[],
        external_imports: &external,
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    admit_component_graph(vec![stream], &policy, &CallerAuthority { offers })
}

#[test]
fn exact_external_host_authority_is_inert_owned_and_revalidated() {
    let ceilings = stream_ceilings();
    let offers = stream_offers();
    let graph = admit_stream(&ceilings, &offers).expect("exact host authority must admit");

    assert!(!graph.runtime_ready());
    assert_eq!(graph.grants().len(), 2);
    assert_eq!(graph.grants()[0].target(), import(0, 0));
    assert_eq!(graph.grants()[0].source_label(), "stdin");
    assert_eq!(graph.grants()[0].kind(), HostResourceKind::ByteStreamReader);
    assert_eq!(graph.grants()[0].rights(), Rights::RECV);
    assert_eq!(graph.grants()[1].target(), import(0, 0));
    assert_eq!(graph.grants()[1].source_label(), "stdout");
    assert_eq!(graph.grants()[1].kind(), HostResourceKind::ByteStreamWriter);
    assert_eq!(graph.grants()[1].rights(), Rights::SEND);
    graph.revalidate().expect("external authority revalidation");
}

#[test]
fn external_host_authority_requires_exact_ceilings_and_offers() {
    let target = import(0, 0);
    let ceilings = stream_ceilings();
    let offers = stream_offers();

    assert_eq!(
        admit_stream(&ceilings[1..], &offers).expect_graph_error(),
        ComponentGraphAdmissionError::MissingImageCeiling { target }
    );
    assert_eq!(
        admit_stream(&ceilings, &offers[..1]).expect_graph_error(),
        ComponentGraphAdmissionError::MissingCallerAuthority { target }
    );
}

#[test]
fn one_authority_offer_cannot_be_reused_by_two_nodes() {
    let exact_world = world(STREAM_WIT, STREAM_FILTER_WORLD);
    let left = artifact(STREAM_COMPONENT);
    let right = artifact(STREAM_COMPONENT);
    let ceilings = stream_ceilings();
    let offers = stream_offers();
    let nodes = [
        policy_node("stream-left", &exact_world, &left, &ceilings),
        policy_node("stream-right", &exact_world, &right, &ceilings),
    ];
    let external = [
        ComponentGraphExternalImportSpec::new(import(0, 0)),
        ComponentGraphExternalImportSpec::new(import(1, 0)),
    ];
    let policy = ComponentGraphAdmissionPolicy {
        name: "duplicate-authority",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &[],
        external_imports: &external,
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert_eq!(
        admit_component_graph(
            vec![left, right],
            &policy,
            &CallerAuthority { offers: &offers },
        )
        .expect_graph_error(),
        ComponentGraphAdmissionError::DuplicateAuthoritySource {
            target: import(1, 0),
        }
    );
}

#[test]
fn over_righted_ceiling_and_offer_are_invalid_before_authority_intersection() {
    let mut ceilings = stream_ceilings();
    ceilings[0].rights = Rights::RECV.union(Rights::READ);
    assert_eq!(
        admit_stream(&ceilings, &stream_offers()).expect_graph_error(),
        ComponentGraphAdmissionError::InvalidPolicy
    );

    let ceilings = stream_ceilings();
    let mut offers = stream_offers();
    offers[1].grantable = Rights::SEND.union(Rights::WRITE);
    assert_eq!(
        admit_stream(&ceilings, &offers).expect_graph_error(),
        ComponentGraphAdmissionError::InvalidPolicy
    );
}

#[test]
fn narrowed_ceiling_or_offer_cannot_amplify_into_required_operation_rights() {
    let target = import(0, 0);
    let mut ceilings = stream_ceilings();
    ceilings[0].rights = Rights::NONE;
    assert_eq!(
        admit_stream(&ceilings, &stream_offers()).expect_graph_error(),
        ComponentGraphAdmissionError::AuthorityAmplification { target }
    );

    let ceilings = stream_ceilings();
    let mut offers = stream_offers();
    offers[0].grantable = Rights::NONE;
    assert_eq!(
        admit_stream(&ceilings, &offers).expect_graph_error(),
        ComponentGraphAdmissionError::AuthorityAmplification { target }
    );
}

#[test]
fn node_world_failure_remains_scoped_to_the_exact_node() {
    let wrong_world = PIPE_WIT.replace("u32", "u64");
    let provider_world = world(PIPE_WIT, PRODUCER_WORLD);
    let consumer_world = world(&wrong_world, CONSUMER_WORLD);
    let provider = artifact(PRODUCER_WAT);
    let consumer = artifact(CONSUMER_WAT);
    let nodes = [
        policy_node("provider", &provider_world, &provider, &[]),
        policy_node("consumer", &consumer_world, &consumer, &[]),
    ];
    let edges = [edge(0, 1)];
    let policy = ComponentGraphAdmissionPolicy {
        name: "wrong-node-world",
        profile: ProfileIdentity::PROFILE_1,
        nodes: &nodes,
        edges: &edges,
        external_imports: &[],
        published_exports: &[],
        cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
    };
    assert!(matches!(
        admit_component_graph(
            vec![provider, consumer],
            &policy,
            &CallerAuthority { offers: &[] },
        ),
        Err(ComponentGraphAdmissionError::Node {
            node: failed,
            error: AdmissionError::World(_),
        }) if failed == node(1)
    ));
}

#[test]
fn replacement_admission_allows_only_target_artifact_change_and_canonicalizes_recreate_fresh() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<AdmittedComponentGraphReplacement>();
    let current = admitted_replacement_chain(RELAY_WAT);
    let candidate = admitted_replacement_chain(RELAY_V2_WAT);
    assert_ne!(
        current.manifest().nodes()[1].artifact(),
        candidate.manifest().nodes()[1].artifact()
    );
    let supplied = [recreate(edge(1, 2)), recreate(edge(0, 1))];
    let policy = ComponentGraphNodeReplacementPolicy {
        target: node(1),
        max_replacements: 1,
        incident_edges: &supplied,
    };

    let admitted =
        admit_component_graph_replacement(Arc::clone(&current), Arc::clone(&candidate), &policy)
            .expect("exact target-only update must admit");

    assert!(!admitted.runtime_ready());
    assert!(Arc::ptr_eq(admitted.current_graph_arc(), &current));
    assert!(Arc::ptr_eq(admitted.candidate_graph_arc(), &candidate));
    assert_eq!(admitted.manifest().target(), node(1));
    assert_eq!(admitted.manifest().max_replacements(), 1);
    assert_eq!(
        admitted.manifest().incident_edges(),
        [recreate(edge(0, 1)), recreate(edge(1, 2))]
    );
    let current_account = current.manifest().account();
    let candidate_budget = candidate.manifest().nodes()[1].budget();
    let transient = admitted.manifest().transient_account();
    assert_eq!(transient.nodes, current_account.nodes + 1);
    assert_eq!(transient.edges, current_account.edges);
    assert_eq!(transient.maximum_nesting, current_account.maximum_nesting);
    assert_eq!(transient.external_imports, current_account.external_imports);
    assert_eq!(
        transient.published_exports,
        current_account.published_exports
    );
    assert_eq!(
        transient.component_bytes,
        current_account.component_bytes + candidate_budget.component_bytes
    );
    assert_eq!(
        transient.core_instances,
        current_account.core_instances + candidate_budget.core_instances
    );
    assert_eq!(
        transient.adapters,
        current_account.adapters + candidate_budget.adapters
    );
    assert_eq!(
        transient.resource_types,
        current_account.resource_types + candidate_budget.resource_types
    );
    assert_eq!(
        transient.resource_slots,
        current_account.resource_slots + candidate_budget.resource_slots
    );
    assert_eq!(
        transient.memory_bytes,
        current_account.memory_bytes + candidate_budget.memory_bytes
    );
    assert_eq!(
        transient.total_fuel,
        current_account.total_fuel + candidate_budget.total_fuel
    );
    assert_eq!(
        transient.maximum_poll_quantum,
        current_account
            .maximum_poll_quantum
            .max(candidate_budget.poll_quantum)
    );
    admitted
        .revalidate()
        .expect("first replacement revalidation");
    admitted
        .revalidate()
        .expect("second replacement revalidation");
}

#[test]
fn replacement_rejects_candidate_overlap_above_the_graph_node_ceiling() {
    let current = admitted_max_node_replacement_graph();
    let candidate = admitted_max_node_replacement_graph();
    let error = admit_component_graph_replacement(
        current,
        candidate,
        &ComponentGraphNodeReplacementPolicy {
            target: node(15),
            max_replacements: 1,
            incident_edges: &[],
        },
    )
    .expect_replacement_error();

    let ComponentGraphReplacementAdmissionError::TransientAccountLimit(limit) = error else {
        panic!("expected transient-account rejection, got {error:?}");
    };
    assert_eq!(limit.kind, LimitKind::GraphNodes);
    assert_eq!(
        limit.attempted,
        PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes + 1
    );
    assert_eq!(limit.maximum, PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes);
}

#[test]
fn replacement_admission_revalidates_exact_resource_and_async_edge_shapes() {
    let resource_routes = [ComponentGraphResourceEdgePolicy {
        edge: edge(0, 1),
        mode: ComponentGraphResourceMode::Borrow,
    }];
    let resource_current = Arc::new(
        admit_resource_pair(
            RESOURCE_WIT,
            RESOURCE_PRODUCER_WAT,
            RESOURCE_CONSUMER_WAT,
            &resource_routes,
        )
        .expect("current resource graph"),
    );
    let resource_candidate = Arc::new(
        admit_resource_pair(
            RESOURCE_WIT,
            RESOURCE_PRODUCER_WAT,
            RESOURCE_CONSUMER_WAT,
            &resource_routes,
        )
        .expect("candidate resource graph"),
    );
    let resource_edges = [recreate(edge(0, 1))];
    let resource_replacement = admit_component_graph_replacement(
        resource_current,
        resource_candidate,
        &ComponentGraphNodeReplacementPolicy {
            target: node(1),
            max_replacements: 1,
            incident_edges: &resource_edges,
        },
    )
    .expect("fresh exact resource provenance must admit replacement");
    assert_eq!(
        resource_replacement
            .current_graph()
            .manifest()
            .resource_edges()
            .len(),
        1
    );
    resource_replacement
        .revalidate()
        .expect("resource replacement revalidation");

    let async_current = Arc::new(admit_async_chain().expect("current async graph"));
    let async_candidate = Arc::new(admit_async_chain().expect("candidate async graph"));
    let async_edges = [recreate(edge(1, 2)), recreate(edge(0, 1))];
    let async_replacement = admit_component_graph_replacement(
        async_current,
        async_candidate,
        &ComponentGraphNodeReplacementPolicy {
            target: node(1),
            max_replacements: 1,
            incident_edges: &async_edges,
        },
    )
    .expect("exact async shape must admit replacement");
    assert_eq!(
        async_replacement
            .candidate_graph()
            .manifest()
            .async_edges()
            .len(),
        2
    );
    async_replacement
        .revalidate()
        .expect("async replacement revalidation");
}

#[test]
fn replacement_policy_rejects_wrong_count_unknown_target_and_incomplete_edge_set() {
    let current = admitted_replacement_chain(RELAY_WAT);
    let candidate = admitted_replacement_chain(RELAY_V2_WAT);
    let complete = [recreate(edge(0, 1)), recreate(edge(1, 2))];

    assert_eq!(
        admit_component_graph_replacement(
            Arc::clone(&current),
            Arc::clone(&candidate),
            &ComponentGraphNodeReplacementPolicy {
                target: node(1),
                max_replacements: 0,
                incident_edges: &complete,
            },
        )
        .expect_replacement_error(),
        ComponentGraphReplacementAdmissionError::InvalidPolicy
    );
    assert_eq!(
        admit_component_graph_replacement(
            Arc::clone(&current),
            Arc::clone(&candidate),
            &ComponentGraphNodeReplacementPolicy {
                target: node(9),
                max_replacements: 1,
                incident_edges: &[],
            },
        )
        .expect_replacement_error(),
        ComponentGraphReplacementAdmissionError::UnknownTarget { target: node(9) }
    );

    for incident_edges in [
        vec![recreate(edge(0, 1))],
        vec![recreate(edge(0, 1)), recreate(edge(0, 1))],
        vec![
            recreate(edge(0, 1)),
            recreate(edge(1, 2)),
            recreate(edge(0, 2)),
        ],
    ] {
        assert_eq!(
            admit_component_graph_replacement(
                Arc::clone(&current),
                Arc::clone(&candidate),
                &ComponentGraphNodeReplacementPolicy {
                    target: node(1),
                    max_replacements: 1,
                    incident_edges: &incident_edges,
                },
            )
            .expect_replacement_error(),
            ComponentGraphReplacementAdmissionError::IncidentEdgePolicyMismatch
        );
    }
}

#[test]
fn replacement_rejects_non_target_change_and_target_contract_change() {
    let current = admitted_replacement_chain(RELAY_WAT);
    let changed_non_target = Arc::new(
        admit_replacement_chain_with(
            PRODUCER_V2_WAT,
            RELAY_V2_WAT,
            limits(),
            ComponentGraphNesting::Root,
            false,
        )
        .expect("candidate with changed producer must independently admit"),
    );
    let complete = [recreate(edge(0, 1)), recreate(edge(1, 2))];
    assert_eq!(
        admit_component_graph_replacement(
            Arc::clone(&current),
            changed_non_target,
            &ComponentGraphNodeReplacementPolicy {
                target: node(1),
                max_replacements: 1,
                incident_edges: &complete,
            },
        )
        .expect_replacement_error(),
        ComponentGraphReplacementAdmissionError::NonTargetMismatch { node: node(0) }
    );

    let mut changed_limits = limits();
    changed_limits.resources -= 1;
    let changed_target_contract = Arc::new(
        admit_replacement_chain_with(
            PRODUCER_WAT,
            RELAY_V2_WAT,
            changed_limits,
            ComponentGraphNesting::Root,
            false,
        )
        .expect("candidate with changed target limits must independently admit"),
    );
    assert_eq!(
        admit_component_graph_replacement(
            current,
            changed_target_contract,
            &ComponentGraphNodeReplacementPolicy {
                target: node(1),
                max_replacements: 1,
                incident_edges: &complete,
            },
        )
        .expect_replacement_error(),
        ComponentGraphReplacementAdmissionError::TargetContractMismatch
    );
}

#[test]
fn replacement_rejects_published_or_nested_target_surface() {
    let complete = [recreate(edge(0, 1)), recreate(edge(1, 2))];
    for (nesting, publish_relay) in [
        (ComponentGraphNesting::Root, true),
        (ComponentGraphNesting::Nested { parent: node(0) }, false),
    ] {
        let current = Arc::new(
            admit_replacement_chain_with(PRODUCER_WAT, RELAY_WAT, limits(), nesting, publish_relay)
                .expect("current restricted-surface graph must independently admit"),
        );
        let candidate = Arc::new(
            admit_replacement_chain_with(
                PRODUCER_WAT,
                RELAY_V2_WAT,
                limits(),
                nesting,
                publish_relay,
            )
            .expect("candidate restricted-surface graph must independently admit"),
        );
        assert_eq!(
            admit_component_graph_replacement(
                current,
                candidate,
                &ComponentGraphNodeReplacementPolicy {
                    target: node(1),
                    max_replacements: 1,
                    incident_edges: &complete,
                },
            )
            .expect_replacement_error(),
            ComponentGraphReplacementAdmissionError::UnsupportedTargetSurface
        );
    }

    let ceilings = stream_ceilings();
    let offers = stream_offers();
    let current = Arc::new(
        admit_stream(&ceilings, &offers)
            .expect("current external-authority graph must independently admit"),
    );
    let candidate = Arc::new(
        admit_stream(&ceilings, &offers)
            .expect("candidate external-authority graph must independently admit"),
    );
    assert_eq!(current.grants().len(), 2);
    assert_eq!(
        admit_component_graph_replacement(
            current,
            candidate,
            &ComponentGraphNodeReplacementPolicy {
                target: node(0),
                max_replacements: 1,
                incident_edges: &[],
            },
        )
        .expect_replacement_error(),
        ComponentGraphReplacementAdmissionError::UnsupportedTargetSurface
    );
}
