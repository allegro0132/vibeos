use core::ptr;
use std::fmt::Write as _;

use vibeos_component_format::{
    ComponentGraphInstanceBudget, LimitKind, ProfileIdentity, PROFILE_1_COMPONENT_GRAPH_LIMITS,
};
use vibeos_component_runtime::{
    decode::{inspect_component, inspect_component_for_profile, ComponentPlan},
    graph::{
        plan_component_graph, preflight_component_graph, ComponentGraphEdgeSpec,
        ComponentGraphEntityIndex, ComponentGraphError, ComponentGraphExportEndpoint,
        ComponentGraphExternalImportSpec, ComponentGraphImportEndpoint, ComponentGraphNesting,
        ComponentGraphNodeBudgetError, ComponentGraphNodeId, ComponentGraphNodeSpec,
        ComponentGraphPublishedExportSpec,
    },
};
use wasm_encoder::{
    Component, ComponentTypeSection, ConstExpr, DataSection, MemorySection, MemoryType, Module,
    ModuleSection, ValType,
};

const EMPTY_COMPONENT: &str = "(component)";
const ROUTE_COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/async-0.255.0.component.wat");

fn minimum_budget() -> ComponentGraphInstanceBudget {
    ComponentGraphInstanceBudget {
        resource_slots: 1,
        memory_bytes: 1,
        total_fuel: 1,
        poll_quantum: 1,
    }
}

fn inspect(bytes: &[u8]) -> ComponentPlan<'_> {
    inspect_component(bytes).expect("test component must inspect")
}

fn inspect_async(bytes: &[u8]) -> ComponentPlan<'_> {
    inspect_component_for_profile(bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("test async component must inspect")
}

fn node<'plan, 'bytes>(
    plan: &'plan ComponentPlan<'bytes>,
    nesting: ComponentGraphNesting,
    budget: ComponentGraphInstanceBudget,
) -> ComponentGraphNodeSpec<'plan> {
    ComponentGraphNodeSpec::from_plan("node", "test:graph/world@1.0.0", nesting, plan, budget)
}

fn root<'plan, 'bytes>(plan: &'plan ComponentPlan<'bytes>) -> ComponentGraphNodeSpec<'plan> {
    node(plan, ComponentGraphNesting::Root, minimum_budget())
}

fn node_id(index: u16) -> ComponentGraphNodeId {
    ComponentGraphNodeId::new(index)
}

fn entity(index: u16) -> ComponentGraphEntityIndex {
    ComponentGraphEntityIndex::new(index)
}

fn export(node: u16, index: u16) -> ComponentGraphExportEndpoint {
    ComponentGraphExportEndpoint::new(node_id(node), entity(index))
}

fn import(node: u16, index: u16) -> ComponentGraphImportEndpoint {
    ComponentGraphImportEndpoint::new(node_id(node), entity(index))
}

fn edge(source_node: u16, target_node: u16) -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(export(source_node, 0), import(target_node, 0))
}

fn assert_limit(error: ComponentGraphError, kind: LimitKind, attempted: u64, maximum: u64) {
    match error {
        ComponentGraphError::Limit(error) => {
            assert_eq!(error.kind, kind);
            assert_eq!(error.attempted, attempted);
            assert_eq!(error.maximum, maximum);
        }
        other => panic!("expected {kind:?} limit, got {other:?}"),
    }
}

fn module_with_data(payload_bytes: usize) -> Module {
    let pages = payload_bytes.div_ceil(65_536) as u64;
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: pages,
        maximum: Some(pages),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    let mut data = DataSection::new();
    data.active(
        0,
        &ConstExpr::i32_const(0),
        core::iter::repeat(0_u8).take(payload_bytes),
    );
    let mut module = Module::new();
    module.section(&memories).section(&data);
    module
}

fn component_with_data_payloads(left: usize, right: usize) -> Vec<u8> {
    let left = module_with_data(left);
    let right = module_with_data(right);
    let mut component = Component::new();
    component
        .section(&ModuleSection(&left))
        .section(&ModuleSection(&right));
    component.finish()
}

fn component_with_exact_size(target: usize) -> Vec<u8> {
    let mut left = target.saturating_sub(128) / 2;
    let mut right = target.saturating_sub(128) - left;
    for _ in 0..32 {
        let bytes = component_with_data_payloads(left, right);
        match bytes.len().cmp(&target) {
            core::cmp::Ordering::Equal => return bytes,
            core::cmp::Ordering::Less => {
                let difference = target - bytes.len();
                left += difference / 2;
                right += difference - difference / 2;
            }
            core::cmp::Ordering::Greater => {
                let difference = bytes.len() - target;
                let from_left = difference / 2;
                left = left
                    .checked_sub(from_left)
                    .expect("left payload adjustment");
                right = right
                    .checked_sub(difference - from_left)
                    .expect("right payload adjustment");
            }
        }
    }
    panic!("could not encode an exact {target}-byte component")
}

fn component_with_core_instances(count: usize) -> Vec<u8> {
    let mut source = String::from("(component (core module $m)");
    for index in 0..count {
        write!(source, " (core instance $instance{index} (instantiate $m))").unwrap();
    }
    source.push(')');
    wat::parse_str(source).unwrap()
}

fn component_with_adapters(count: usize) -> Vec<u8> {
    let mut source = String::from("(component (type $t (func)) (import \"f\" (func $f (type $t)))");
    for _ in 0..count {
        source.push_str(" (core func (canon lower (func $f)))");
    }
    source.push(')');
    wat::parse_str(source).unwrap()
}

fn component_with_resources(count: usize) -> Vec<u8> {
    let mut types = ComponentTypeSection::new();
    for _ in 0..count {
        types.resource(ValType::I32, None);
    }
    let mut component = Component::new();
    component.section(&types);
    component.finish()
}

#[test]
fn empty_graph_is_rejected_before_planning() {
    assert_eq!(
        preflight_component_graph(&[], &[], &[], &[]),
        Err(ComponentGraphError::EmptyGraph)
    );
    assert!(matches!(
        plan_component_graph(&[], &[], &[], &[]),
        Err(ComponentGraphError::EmptyGraph)
    ));
}

#[test]
fn sixteen_nodes_are_exact_and_the_seventeenth_is_rejected() {
    let bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let plan = inspect(&bytes);
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let nodes = vec![root(&plan); limits.max_nodes as usize];

    let graph = plan_component_graph(&nodes, &[], &[], &[]).unwrap();
    assert_eq!(graph.nodes().len(), limits.max_nodes as usize);
    assert_eq!(graph.account().nodes, limits.max_nodes);
    assert!(!graph.runtime_ready());

    let mut over = nodes;
    over.push(root(&plan));
    assert_limit(
        plan_component_graph(&over, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphNodes,
        limits.max_nodes + 1,
        limits.max_nodes,
    );
}

#[test]
fn every_invalid_node_budget_is_rejected_with_its_exact_reason() {
    let empty_bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let empty = inspect(&empty_bytes);
    let invalid = [
        (
            ComponentGraphInstanceBudget {
                resource_slots: 0,
                ..minimum_budget()
            },
            ComponentGraphNodeBudgetError::ZeroResourceSlots,
        ),
        (
            ComponentGraphInstanceBudget {
                memory_bytes: 0,
                ..minimum_budget()
            },
            ComponentGraphNodeBudgetError::ZeroMemoryBytes,
        ),
        (
            ComponentGraphInstanceBudget {
                total_fuel: 0,
                ..minimum_budget()
            },
            ComponentGraphNodeBudgetError::ZeroTotalFuel,
        ),
        (
            ComponentGraphInstanceBudget {
                poll_quantum: 0,
                ..minimum_budget()
            },
            ComponentGraphNodeBudgetError::ZeroPollQuantum,
        ),
        (
            ComponentGraphInstanceBudget {
                total_fuel: 1,
                poll_quantum: 2,
                ..minimum_budget()
            },
            ComponentGraphNodeBudgetError::PollQuantumExceedsFuel,
        ),
    ];
    for (budget, reason) in invalid {
        let nodes = [node(&empty, ComponentGraphNesting::Root, budget)];
        assert_eq!(
            preflight_component_graph(&nodes, &[], &[], &[]),
            Err(ComponentGraphError::InvalidNodeBudget {
                node: node_id(0),
                reason,
            }),
            "budget {budget:?}"
        );
    }

    let resource_bytes = component_with_resources(2);
    let resources = inspect(&resource_bytes);
    assert_eq!(resources.summary().resources, 2);
    let nodes = [node(
        &resources,
        ComponentGraphNesting::Root,
        ComponentGraphInstanceBudget {
            resource_slots: 1,
            ..minimum_budget()
        },
    )];
    assert_eq!(
        preflight_component_graph(&nodes, &[], &[], &[]),
        Err(ComponentGraphError::InvalidNodeBudget {
            node: node_id(0),
            reason: ComponentGraphNodeBudgetError::ResourceTypesExceedSlots,
        })
    );
}

#[test]
fn aggregate_component_bytes_reject_exactly_one_over_the_graph_limit() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let empty_bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let target = limits.max_component_bytes as usize - empty_bytes.len() + 1;
    let large_bytes = component_with_exact_size(target);
    assert_eq!(large_bytes.len(), target);

    let large = inspect(&large_bytes);
    let empty = inspect(&empty_bytes);
    let nodes = [root(&large), root(&empty)];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphComponentBytes,
        limits.max_component_bytes + 1,
        limits.max_component_bytes,
    );
}

#[test]
fn every_other_aggregate_budget_rejects_exactly_one_over() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let empty_bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let empty = inspect(&empty_bytes);

    let maximum_instances_bytes = component_with_core_instances(limits.max_core_instances as usize);
    let one_instance_bytes = component_with_core_instances(1);
    let maximum_instances = inspect(&maximum_instances_bytes);
    let one_instance = inspect(&one_instance_bytes);
    assert_eq!(
        maximum_instances.runtime_instance_count() as u64,
        limits.max_core_instances
    );
    let nodes = [root(&maximum_instances), root(&one_instance)];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphCoreInstances,
        limits.max_core_instances + 1,
        limits.max_core_instances,
    );

    let maximum_adapters_bytes = component_with_adapters(limits.max_adapters as usize);
    let one_adapter_bytes = component_with_adapters(1);
    let maximum_adapters = inspect(&maximum_adapters_bytes);
    let one_adapter = inspect(&one_adapter_bytes);
    assert_eq!(
        maximum_adapters.summary().adapters as u64,
        limits.max_adapters
    );
    let nodes = [root(&maximum_adapters), root(&one_adapter)];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphAdapters,
        limits.max_adapters + 1,
        limits.max_adapters,
    );

    let maximum_resources_bytes = component_with_resources(limits.max_resource_types as usize);
    let one_resource_bytes = component_with_resources(1);
    let maximum_resources = inspect(&maximum_resources_bytes);
    let one_resource = inspect(&one_resource_bytes);
    assert_eq!(
        maximum_resources.summary().resources as u64,
        limits.max_resource_types
    );
    let nodes = [
        node(
            &maximum_resources,
            ComponentGraphNesting::Root,
            ComponentGraphInstanceBudget {
                resource_slots: limits.max_resource_slots,
                ..minimum_budget()
            },
        ),
        root(&one_resource),
    ];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphResourceTypes,
        limits.max_resource_types + 1,
        limits.max_resource_types,
    );

    let nodes = [
        node(
            &empty,
            ComponentGraphNesting::Root,
            ComponentGraphInstanceBudget {
                resource_slots: limits.max_resource_slots,
                ..minimum_budget()
            },
        ),
        root(&empty),
    ];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphResourceSlots,
        limits.max_resource_slots + 1,
        limits.max_resource_slots,
    );

    let nodes = [
        node(
            &empty,
            ComponentGraphNesting::Root,
            ComponentGraphInstanceBudget {
                memory_bytes: limits.max_memory_bytes,
                ..minimum_budget()
            },
        ),
        root(&empty),
    ];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphMemoryBytes,
        limits.max_memory_bytes + 1,
        limits.max_memory_bytes,
    );

    let nodes = [
        node(
            &empty,
            ComponentGraphNesting::Root,
            ComponentGraphInstanceBudget {
                total_fuel: limits.max_total_fuel,
                ..minimum_budget()
            },
        ),
        root(&empty),
    ];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphTotalFuel,
        limits.max_total_fuel + 1,
        limits.max_total_fuel,
    );

    let nodes = [node(
        &empty,
        ComponentGraphNesting::Root,
        ComponentGraphInstanceBudget {
            total_fuel: limits.max_poll_quantum + 1,
            poll_quantum: limits.max_poll_quantum + 1,
            ..minimum_budget()
        },
    )];
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphPollQuantum,
        limits.max_poll_quantum + 1,
        limits.max_poll_quantum,
    );
}

#[test]
fn containment_depth_eight_is_exact_and_nine_is_rejected() {
    let bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let plan = inspect(&bytes);
    let mut exact = Vec::new();
    exact.push(root(&plan));
    for index in 1..PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting as u16 {
        exact.push(node(
            &plan,
            ComponentGraphNesting::Nested {
                parent: node_id(index - 1),
            },
            minimum_budget(),
        ));
    }
    let graph = plan_component_graph(&exact, &[], &[], &[]).unwrap();
    assert_eq!(
        graph.account().maximum_nesting,
        PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting
    );

    let mut over = exact;
    over.push(node(
        &plan,
        ComponentGraphNesting::Nested {
            parent: node_id(PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting as u16 - 1),
        },
        minimum_budget(),
    ));
    assert_limit(
        plan_component_graph(&over, &[], &[], &[]).unwrap_err(),
        LimitKind::GraphNesting,
        PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting + 1,
        PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting,
    );
}

#[test]
fn invalid_parent_self_parent_and_two_node_containment_cycle_are_distinct() {
    let bytes = wat::parse_str(EMPTY_COMPONENT).unwrap();
    let plan = inspect(&bytes);

    let bad_parent = [
        root(&plan),
        node(
            &plan,
            ComponentGraphNesting::Nested { parent: node_id(2) },
            minimum_budget(),
        ),
    ];
    assert_eq!(
        preflight_component_graph(&bad_parent, &[], &[], &[]),
        Err(ComponentGraphError::InvalidParent {
            node: node_id(1),
            parent: node_id(2),
        })
    );

    let self_parent = [node(
        &plan,
        ComponentGraphNesting::Nested { parent: node_id(0) },
        minimum_budget(),
    )];
    assert_eq!(
        preflight_component_graph(&self_parent, &[], &[], &[]),
        Err(ComponentGraphError::ContainmentCycle { node: node_id(0) })
    );

    let cycle = [
        node(
            &plan,
            ComponentGraphNesting::Nested { parent: node_id(1) },
            minimum_budget(),
        ),
        node(
            &plan,
            ComponentGraphNesting::Nested { parent: node_id(0) },
            minimum_budget(),
        ),
    ];
    assert_eq!(
        preflight_component_graph(&cycle, &[], &[], &[]),
        Err(ComponentGraphError::ContainmentCycle { node: node_id(0) })
    );
}

#[test]
fn every_endpoint_node_and_entity_index_is_range_checked() {
    let bytes = wat::parse_str(ROUTE_COMPONENT).unwrap();
    let plan = inspect_async(&bytes);
    assert_eq!((plan.imports().len(), plan.exports().len()), (1, 1));
    let nodes = [root(&plan)];

    let bad_export_node = [ComponentGraphEdgeSpec::new(export(1, 0), import(0, 0))];
    assert_eq!(
        preflight_component_graph(&nodes, &bad_export_node, &[], &[]),
        Err(ComponentGraphError::InvalidExportNode { node: node_id(1) })
    );

    let bad_import_node = [ComponentGraphEdgeSpec::new(export(0, 0), import(1, 0))];
    assert_eq!(
        preflight_component_graph(&nodes, &bad_import_node, &[], &[]),
        Err(ComponentGraphError::InvalidImportNode { node: node_id(1) })
    );

    let bad_export = export(0, 1);
    let bad_export_index = [ComponentGraphEdgeSpec::new(bad_export, import(0, 0))];
    assert_eq!(
        preflight_component_graph(&nodes, &bad_export_index, &[], &[]),
        Err(ComponentGraphError::InvalidExportIndex {
            endpoint: bad_export,
        })
    );

    let bad_import = import(0, 1);
    let bad_import_index = [ComponentGraphEdgeSpec::new(export(0, 0), bad_import)];
    assert_eq!(
        preflight_component_graph(&nodes, &bad_import_index, &[], &[]),
        Err(ComponentGraphError::InvalidImportIndex {
            endpoint: bad_import,
        })
    );

    let external = [ComponentGraphExternalImportSpec::new(import(2, 0))];
    assert_eq!(
        preflight_component_graph(&nodes, &[], &external, &[]),
        Err(ComponentGraphError::InvalidImportNode { node: node_id(2) })
    );
    let external = [ComponentGraphExternalImportSpec::new(bad_import)];
    assert_eq!(
        preflight_component_graph(&nodes, &[], &external, &[]),
        Err(ComponentGraphError::InvalidImportIndex {
            endpoint: bad_import,
        })
    );
    let published = [ComponentGraphPublishedExportSpec::new(export(2, 0))];
    assert_eq!(
        preflight_component_graph(&nodes, &[], &[], &published),
        Err(ComponentGraphError::InvalidExportNode { node: node_id(2) })
    );
    let published = [ComponentGraphPublishedExportSpec::new(bad_export)];
    assert_eq!(
        preflight_component_graph(&nodes, &[], &[], &published),
        Err(ComponentGraphError::InvalidExportIndex {
            endpoint: bad_export,
        })
    );
}

#[test]
fn edges_external_imports_and_published_exports_accept_exact_limit_and_reject_one_more() {
    let bytes = wat::parse_str(ROUTE_COMPONENT).unwrap();
    let plan = inspect_async(&bytes);
    let nodes = [root(&plan)];
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;

    let edges = vec![edge(0, 0); limits.max_edges as usize];
    let graph = plan_component_graph(&nodes, &edges, &[], &[]).unwrap();
    assert_eq!(graph.edges().len(), limits.max_edges as usize);
    assert_eq!(graph.account().edges, limits.max_edges);
    let mut over = edges;
    over.push(edge(0, 0));
    assert_limit(
        plan_component_graph(&nodes, &over, &[], &[]).unwrap_err(),
        LimitKind::GraphEdges,
        limits.max_edges + 1,
        limits.max_edges,
    );

    let external = vec![
        ComponentGraphExternalImportSpec::new(import(0, 0));
        limits.max_external_imports as usize
    ];
    let graph = plan_component_graph(&nodes, &[], &external, &[]).unwrap();
    assert_eq!(
        graph.external_imports().len(),
        limits.max_external_imports as usize
    );
    assert_eq!(
        graph.account().external_imports,
        limits.max_external_imports
    );
    let mut over = external;
    over.push(ComponentGraphExternalImportSpec::new(import(0, 0)));
    assert_limit(
        plan_component_graph(&nodes, &[], &over, &[]).unwrap_err(),
        LimitKind::GraphExternalImports,
        limits.max_external_imports + 1,
        limits.max_external_imports,
    );

    let published = vec![
        ComponentGraphPublishedExportSpec::new(export(0, 0));
        limits.max_published_exports as usize
    ];
    let graph = plan_component_graph(&nodes, &[], &[], &published).unwrap();
    assert_eq!(
        graph.published_exports().len(),
        limits.max_published_exports as usize
    );
    assert_eq!(
        graph.account().published_exports,
        limits.max_published_exports
    );
    let mut over = published;
    over.push(ComponentGraphPublishedExportSpec::new(export(0, 0)));
    assert_limit(
        plan_component_graph(&nodes, &[], &[], &over).unwrap_err(),
        LimitKind::GraphPublishedExports,
        limits.max_published_exports + 1,
        limits.max_published_exports,
    );
}

#[test]
fn plan_preserves_input_order_endpoint_provenance_and_borrowed_shapes() {
    let u32_bytes = wat::parse_str(ROUTE_COMPONENT).unwrap();
    let u64_bytes = wat::parse_str(ROUTE_COMPONENT.replace("future u32", "future u64")).unwrap();
    let u32_route = inspect_async(&u32_bytes);
    let u64_route = inspect_async(&u64_bytes);
    let nodes = [
        ComponentGraphNodeSpec::from_plan(
            "provider",
            "test:provider/world@1.0.0",
            ComponentGraphNesting::Root,
            &u32_route,
            minimum_budget(),
        ),
        ComponentGraphNodeSpec::from_plan(
            "consumer",
            "test:consumer/world@1.0.0",
            ComponentGraphNesting::Root,
            &u64_route,
            minimum_budget(),
        ),
    ];
    let edges = [edge(0, 1), edge(1, 0)];
    let external = [
        ComponentGraphExternalImportSpec::new(import(1, 0)),
        ComponentGraphExternalImportSpec::new(import(0, 0)),
    ];
    let published = [
        ComponentGraphPublishedExportSpec::new(export(0, 0)),
        ComponentGraphPublishedExportSpec::new(export(1, 0)),
    ];

    let graph = plan_component_graph(&nodes, &edges, &external, &published).unwrap();
    assert_eq!(
        graph
            .nodes()
            .iter()
            .map(|node| (node.id().index(), node.label(), node.world()))
            .collect::<Vec<_>>(),
        [
            (0, "provider", "test:provider/world@1.0.0"),
            (1, "consumer", "test:consumer/world@1.0.0"),
        ]
    );
    assert_eq!(graph.edges()[0].source(), export(0, 0));
    assert_eq!(graph.edges()[0].target(), import(1, 0));
    assert_eq!(graph.edges()[1].source(), export(1, 0));
    assert_eq!(graph.edges()[1].target(), import(0, 0));
    assert!(ptr::eq(
        graph.edges()[0].source_shape(),
        &u32_route.exports()[0]
    ));
    assert!(ptr::eq(
        graph.edges()[0].target_shape(),
        &u64_route.imports()[0]
    ));
    assert!(ptr::eq(
        graph.edges()[1].source_shape(),
        &u64_route.exports()[0]
    ));
    assert!(ptr::eq(
        graph.edges()[1].target_shape(),
        &u32_route.imports()[0]
    ));
    assert_eq!(graph.external_imports()[0].target(), import(1, 0));
    assert!(ptr::eq(
        graph.external_imports()[0].shape(),
        &u64_route.imports()[0]
    ));
    assert_eq!(graph.external_imports()[1].target(), import(0, 0));
    assert!(ptr::eq(
        graph.external_imports()[1].shape(),
        &u32_route.imports()[0]
    ));
    assert_eq!(graph.published_exports()[0].source(), export(0, 0));
    assert!(ptr::eq(
        graph.published_exports()[0].shape(),
        &u32_route.exports()[0]
    ));
    assert_eq!(graph.published_exports()[1].source(), export(1, 0));
    assert!(ptr::eq(
        graph.published_exports()[1].shape(),
        &u64_route.exports()[0]
    ));
    assert!(!graph.runtime_ready());
}

#[test]
fn c61_is_inert_about_missing_edges_shape_mismatch_duplicates_and_dataflow_cycles() {
    let u32_bytes = wat::parse_str(ROUTE_COMPONENT).unwrap();
    let u64_bytes = wat::parse_str(ROUTE_COMPONENT.replace("future u32", "future u64")).unwrap();
    let u32_route = inspect_async(&u32_bytes);
    let u64_route = inspect_async(&u64_bytes);
    assert_ne!(
        &u32_route.exports()[0].entity,
        &u64_route.imports()[0].entity,
        "fixture must exercise a real shape mismatch"
    );

    // An import without an edge is a C6.2 missing-import decision, not a C6.1
    // structural error.
    let one = [root(&u32_route)];
    let graph = plan_component_graph(&one, &[], &[], &[]).unwrap();
    assert_eq!(graph.nodes()[0].imports().len(), 1);
    assert!(graph.edges().is_empty());
    assert!(!graph.runtime_ready());

    let nodes = [root(&u32_route), root(&u64_route)];
    let declarations = [
        edge(0, 1), // shape mismatch is deferred
        edge(0, 1), // duplicate edge is deferred
        edge(0, 0), // self data-flow cycle is deferred
        edge(1, 0), // completes a two-node data-flow cycle
    ];
    let graph = plan_component_graph(&nodes, &declarations, &[], &[]).unwrap();
    assert_eq!(graph.edges().len(), declarations.len());
    assert_eq!(graph.account().edges, declarations.len() as u64);
    assert!(!graph.runtime_ready());
}

#[derive(Clone, Copy)]
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bounded(&mut self, maximum: usize) -> usize {
        (self.next() as usize) % maximum
    }
}

#[test]
fn fixed_seed_small_graph_fuzz_is_deterministic_bounded_and_inert() {
    const SEEDS: [u64; 4] = [
        0x243f_6a88_85a3_08d3,
        0x1319_8a2e_0370_7344,
        0xa409_3822_299f_31d0,
        0x082e_fa98_ec4e_6c89,
    ];
    const STEPS: usize = 64;

    let bytes = wat::parse_str(ROUTE_COMPONENT).unwrap();
    let component = inspect_async(&bytes);
    for seed in SEEDS {
        let mut random = Prng(seed);
        for step in 0..STEPS {
            let node_count = 1 + random.bounded(4);
            let nodes = vec![root(&component); node_count];
            let mut edges = Vec::new();
            let mut external = Vec::new();
            let mut published = Vec::new();

            for _ in 0..random.bounded(9) {
                let source_node = random.bounded(node_count + 1) as u16;
                let target_node = random.bounded(node_count + 1) as u16;
                let source_index = random.bounded(2) as u16;
                let target_index = random.bounded(2) as u16;
                edges.push(ComponentGraphEdgeSpec::new(
                    export(source_node, source_index),
                    import(target_node, target_index),
                ));
            }
            for _ in 0..random.bounded(9) {
                external.push(ComponentGraphExternalImportSpec::new(import(
                    random.bounded(node_count + 1) as u16,
                    random.bounded(2) as u16,
                )));
            }
            for _ in 0..random.bounded(9) {
                published.push(ComponentGraphPublishedExportSpec::new(export(
                    random.bounded(node_count + 1) as u16,
                    random.bounded(2) as u16,
                )));
            }

            let first = preflight_component_graph(&nodes, &edges, &external, &published);
            let second = preflight_component_graph(&nodes, &edges, &external, &published);
            assert_eq!(
                first, second,
                "seed={seed:#018x} step={step} action=preflight"
            );

            match first {
                Err(expected) => assert_eq!(
                    plan_component_graph(&nodes, &edges, &external, &published).unwrap_err(),
                    expected,
                    "seed={seed:#018x} step={step} action=invalid-plan"
                ),
                Ok(preflight) => {
                    let graph = plan_component_graph(&nodes, &edges, &external, &published)
                        .unwrap_or_else(|error| {
                            panic!("seed={seed:#018x} step={step} action=valid-plan: {error:?}")
                        });
                    assert_eq!(
                        graph.account(),
                        preflight.account(),
                        "seed={seed:#018x} step={step} action=account"
                    );
                    assert_eq!(graph.nodes().len(), node_count);
                    assert_eq!(graph.edges().len(), edges.len());
                    assert_eq!(graph.external_imports().len(), external.len());
                    assert_eq!(graph.published_exports().len(), published.len());
                    assert!(
                        !graph.runtime_ready(),
                        "seed={seed:#018x} step={step} action=readiness"
                    );
                    for (edge, spec) in graph.edges().iter().zip(&edges) {
                        assert_eq!(edge.source(), spec.source());
                        assert_eq!(edge.target(), spec.target());
                        let source = usize::from(spec.source().node().index());
                        let target = usize::from(spec.target().node().index());
                        assert!(ptr::eq(
                            edge.source_shape(),
                            &nodes[source].exports()[usize::from(spec.source().export().index())]
                        ));
                        assert!(ptr::eq(
                            edge.target_shape(),
                            &nodes[target].imports()[usize::from(spec.target().import().index())]
                        ));
                    }
                }
            }
        }
    }
}
