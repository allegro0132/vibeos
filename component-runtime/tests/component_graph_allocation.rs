use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibeos_component_format::{
    ComponentGraphInstanceBudget, LimitError, LimitKind, ProfileIdentity,
    PROFILE_1_COMPONENT_GRAPH_LIMITS,
};
use vibeos_component_runtime::{
    decode::inspect_component_for_profile,
    graph::{
        plan_component_graph, ComponentGraphEdgeSpec, ComponentGraphEntityIndex,
        ComponentGraphError, ComponentGraphExportEndpoint, ComponentGraphImportEndpoint,
        ComponentGraphNesting, ComponentGraphNodeId, ComponentGraphNodeSpec,
    },
};

struct CountingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);

fn count_tracked_call() {
    if TRACKING.load(Ordering::Relaxed) {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_tracked_call();
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_tracked_call();
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_tracked_call();
        System.realloc(pointer, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct TrackingWindow;

impl Drop for TrackingWindow {
    fn drop(&mut self) {
        TRACKING.store(false, Ordering::SeqCst);
    }
}

fn allocation_calls_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATION_CALLS.store(0, Ordering::Relaxed);
    let window = TrackingWindow;
    assert!(!TRACKING.swap(true, Ordering::SeqCst));
    let result = operation();
    drop(window);
    (result, ALLOCATION_CALLS.load(Ordering::Relaxed))
}

fn budget(total_fuel: u64) -> ComponentGraphInstanceBudget {
    ComponentGraphInstanceBudget {
        resource_slots: 1,
        memory_bytes: 1,
        total_fuel,
        poll_quantum: 1,
    }
}

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

#[test]
fn top_level_planner_rejects_tail_preflight_failures_without_allocating() {
    // Keep every allocation needed by the fixture, decoded plan, and graph specs
    // outside the tracked windows. This fixture has exactly one import and one
    // export, which makes both a valid edge prefix and an invalid tail possible.
    let bytes = wat::parse_str(include_str!(
        "../../component-format/tests/corpus/component/async-0.255.0.component.wat"
    ))
    .expect("C6.1 allocation-test component WAT");
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC)
        .expect("C6.1 allocation-test component plan");
    assert_eq!(plan.imports().len(), 1);
    assert_eq!(plan.exports().len(), 1);

    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;

    let aggregate_nodes = [
        ComponentGraphNodeSpec::from_plan(
            "aggregate-prefix",
            "fixture:graph/aggregate-prefix@1.0.0",
            ComponentGraphNesting::Root,
            &plan,
            budget(limits.max_total_fuel - 1),
        ),
        ComponentGraphNodeSpec::from_plan(
            "aggregate-tail",
            "fixture:graph/aggregate-tail@1.0.0",
            ComponentGraphNesting::Root,
            &plan,
            budget(2),
        ),
    ];
    let (aggregate_error, aggregate_allocations) =
        allocation_calls_during(|| plan_component_graph(&aggregate_nodes, &[], &[], &[]).err());
    assert_eq!(
        aggregate_error,
        Some(ComponentGraphError::Limit(LimitError {
            kind: LimitKind::GraphTotalFuel,
            attempted: limits.max_total_fuel + 1,
            maximum: limits.max_total_fuel,
        }))
    );
    assert_eq!(
        aggregate_allocations, 0,
        "a tail aggregate failure reached graph-plan allocation"
    );

    let endpoint_nodes = [ComponentGraphNodeSpec::from_plan(
        "endpoint",
        "fixture:graph/endpoint@1.0.0",
        ComponentGraphNesting::Root,
        &plan,
        budget(1),
    )];
    let valid_edge = ComponentGraphEdgeSpec::new(export(0, 0), import(0, 0));
    let invalid_target = import(0, 1);
    let endpoint_edges = [
        valid_edge,
        ComponentGraphEdgeSpec::new(export(0, 0), invalid_target),
    ];
    let (endpoint_error, endpoint_allocations) = allocation_calls_during(|| {
        plan_component_graph(&endpoint_nodes, &endpoint_edges, &[], &[]).err()
    });
    assert_eq!(
        endpoint_error,
        Some(ComponentGraphError::InvalidImportIndex {
            endpoint: invalid_target,
        })
    );
    assert_eq!(
        endpoint_allocations, 0,
        "an invalid endpoint at the tail reached graph-plan allocation"
    );

    let cycle_node = node(2);
    let containment_nodes = [
        ComponentGraphNodeSpec::from_plan(
            "containment-prefix-0",
            "fixture:graph/containment-prefix-0@1.0.0",
            ComponentGraphNesting::Root,
            &plan,
            budget(1),
        ),
        ComponentGraphNodeSpec::from_plan(
            "containment-prefix-1",
            "fixture:graph/containment-prefix-1@1.0.0",
            ComponentGraphNesting::Root,
            &plan,
            budget(1),
        ),
        ComponentGraphNodeSpec::from_plan(
            "containment-tail",
            "fixture:graph/containment-tail@1.0.0",
            ComponentGraphNesting::Nested { parent: cycle_node },
            &plan,
            budget(1),
        ),
    ];
    let (cycle_error, cycle_allocations) =
        allocation_calls_during(|| plan_component_graph(&containment_nodes, &[], &[], &[]).err());
    assert_eq!(
        cycle_error,
        Some(ComponentGraphError::ContainmentCycle { node: cycle_node })
    );
    assert_eq!(
        cycle_allocations, 0,
        "a containment cycle at the tail reached graph-plan allocation"
    );
}
