use vibeos_component_format::{
    ComponentGraphAccount, ComponentGraphInstanceBudget, ComponentGraphNodeBudget, LimitError,
    LimitKind, PROFILE_1_COMPONENT_GRAPH_LIMITS, PROFILE_1_LIMITS,
};

type GraphCharge = fn(&mut ComponentGraphAccount, u64) -> Result<(), LimitError>;
type AccountValue = fn(&ComponentGraphAccount) -> u64;

fn assert_limit(error: LimitError, kind: LimitKind, attempted: u64, maximum: u64) {
    assert_eq!(error.kind, kind);
    assert_eq!(error.attempted, attempted);
    assert_eq!(error.maximum, maximum);
}

fn account_value(account: &ComponentGraphAccount, kind: LimitKind) -> u64 {
    match kind {
        LimitKind::GraphComponentBytes => account.component_bytes,
        LimitKind::GraphCoreInstances => account.core_instances,
        LimitKind::GraphAdapters => account.adapters,
        LimitKind::GraphResourceTypes => account.resource_types,
        LimitKind::GraphResourceSlots => account.resource_slots,
        LimitKind::GraphMemoryBytes => account.memory_bytes,
        LimitKind::GraphTotalFuel => account.total_fuel,
        LimitKind::GraphPollQuantum => account.maximum_poll_quantum,
        _ => panic!("not a graph-node budget limit: {kind:?}"),
    }
}

#[test]
fn graph_limits_are_exact_absolute_ceilings() {
    let graph = PROFILE_1_COMPONENT_GRAPH_LIMITS;

    assert_eq!(graph.max_nodes, 16);
    assert_eq!(graph.max_edges, 256);
    assert_eq!(graph.max_nesting, 8);
    assert_eq!(graph.max_external_imports, 256);
    assert_eq!(graph.max_published_exports, 256);
    assert_eq!(graph.max_component_bytes, 1024 * 1024);
    assert_eq!(graph.max_core_instances, 16);
    assert_eq!(graph.max_adapters, 16);
    assert_eq!(graph.max_resource_types, 256);
    assert_eq!(graph.max_resource_slots, 256);
    assert_eq!(graph.max_memory_bytes, 16 * 1024 * 1024);
    assert_eq!(graph.max_total_fuel, 10_000_000);
    assert_eq!(graph.max_poll_quantum, 10_000);

    assert_eq!(
        graph.max_component_bytes,
        PROFILE_1_LIMITS.max_component_bytes as u64
    );
    assert_eq!(
        graph.max_core_instances,
        PROFILE_1_LIMITS.max_component_instances as u64
    );
    assert_eq!(graph.max_adapters, PROFILE_1_LIMITS.max_adapters as u64);
    assert_eq!(
        graph.max_resource_types,
        PROFILE_1_LIMITS.max_resources as u64
    );
    assert_eq!(
        graph.max_resource_slots,
        PROFILE_1_LIMITS.max_resources as u64
    );
    assert_eq!(
        graph.max_memory_bytes,
        PROFILE_1_LIMITS.max_memory_pages as u64 * 65_536
    );
    assert_eq!(graph.max_total_fuel, PROFILE_1_LIMITS.total_fuel);
    assert_eq!(graph.max_poll_quantum, PROFILE_1_LIMITS.poll_quantum);
}

#[test]
fn every_node_budget_accepts_exact_limit_and_rejects_one_more_atomically() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let cases = [
        (
            ComponentGraphNodeBudget {
                component_bytes: limits.max_component_bytes,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                component_bytes: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphComponentBytes,
            limits.max_component_bytes,
        ),
        (
            ComponentGraphNodeBudget {
                core_instances: limits.max_core_instances,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                core_instances: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphCoreInstances,
            limits.max_core_instances,
        ),
        (
            ComponentGraphNodeBudget {
                adapters: limits.max_adapters,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                adapters: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphAdapters,
            limits.max_adapters,
        ),
        (
            ComponentGraphNodeBudget {
                resource_types: limits.max_resource_types,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                resource_types: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphResourceTypes,
            limits.max_resource_types,
        ),
        (
            ComponentGraphNodeBudget {
                resource_slots: limits.max_resource_slots,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                resource_slots: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphResourceSlots,
            limits.max_resource_slots,
        ),
        (
            ComponentGraphNodeBudget {
                memory_bytes: limits.max_memory_bytes,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                memory_bytes: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphMemoryBytes,
            limits.max_memory_bytes,
        ),
        (
            ComponentGraphNodeBudget {
                total_fuel: limits.max_total_fuel,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                total_fuel: 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphTotalFuel,
            limits.max_total_fuel,
        ),
        (
            ComponentGraphNodeBudget {
                poll_quantum: limits.max_poll_quantum,
                ..ComponentGraphNodeBudget::default()
            },
            ComponentGraphNodeBudget {
                poll_quantum: limits.max_poll_quantum + 1,
                ..ComponentGraphNodeBudget::default()
            },
            LimitKind::GraphPollQuantum,
            limits.max_poll_quantum,
        ),
    ];

    for (exact, over, kind, maximum) in cases {
        let mut account = ComponentGraphAccount::default();
        account.charge_node(exact).unwrap();
        assert_eq!(account_value(&account, kind), maximum, "{kind:?}");

        let before = account;
        let error = account.charge_node(over).unwrap_err();
        assert_limit(error, kind, maximum + 1, maximum);
        assert_eq!(account, before, "failed {kind:?} charge mutated account");
    }
}

#[test]
fn node_count_accepts_exact_limit_and_rejects_the_next_node_atomically() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let mut account = ComponentGraphAccount::default();

    for _ in 0..limits.max_nodes {
        account
            .charge_node(ComponentGraphNodeBudget::default())
            .unwrap();
    }
    assert_eq!(account.nodes, limits.max_nodes);

    let before = account;
    let error = account
        .charge_node(ComponentGraphNodeBudget::default())
        .unwrap_err();
    assert_limit(
        error,
        LimitKind::GraphNodes,
        limits.max_nodes + 1,
        limits.max_nodes,
    );
    assert_eq!(account, before);
}

#[test]
fn nesting_edges_external_imports_and_published_exports_have_live_boundaries() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
    let cases: [(GraphCharge, AccountValue, u64, u64, LimitKind); 4] = [
        (
            ComponentGraphAccount::observe_nesting,
            |account| account.maximum_nesting,
            limits.max_nesting,
            limits.max_nesting + 1,
            LimitKind::GraphNesting,
        ),
        (
            ComponentGraphAccount::charge_edges,
            |account| account.edges,
            limits.max_edges,
            1,
            LimitKind::GraphEdges,
        ),
        (
            ComponentGraphAccount::charge_external_imports,
            |account| account.external_imports,
            limits.max_external_imports,
            1,
            LimitKind::GraphExternalImports,
        ),
        (
            ComponentGraphAccount::charge_published_exports,
            |account| account.published_exports,
            limits.max_published_exports,
            1,
            LimitKind::GraphPublishedExports,
        ),
    ];

    for (charge, value, exact, over_amount, kind) in cases {
        let mut account = ComponentGraphAccount::default();
        charge(&mut account, exact).unwrap();
        assert_eq!(value(&account), exact, "{kind:?}");

        let before = account;
        let error = charge(&mut account, over_amount).unwrap_err();
        assert_limit(error, kind, exact + 1, exact);
        assert_eq!(account, before, "failed {kind:?} charge mutated account");
    }
}

#[test]
fn checked_add_overflow_reports_saturated_attempt_and_preserves_the_account() {
    let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;

    let mut edge_account = ComponentGraphAccount {
        edges: u64::MAX,
        ..ComponentGraphAccount::default()
    };
    let before = edge_account;
    let error = edge_account.charge_edges(1).unwrap_err();
    assert_limit(error, LimitKind::GraphEdges, u64::MAX, limits.max_edges);
    assert_eq!(edge_account, before);

    let mut node_account = ComponentGraphAccount {
        component_bytes: u64::MAX,
        ..ComponentGraphAccount::default()
    };
    let before = node_account;
    let error = node_account
        .charge_node(ComponentGraphNodeBudget {
            component_bytes: 1,
            ..ComponentGraphNodeBudget::default()
        })
        .unwrap_err();
    assert_limit(
        error,
        LimitKind::GraphComponentBytes,
        u64::MAX,
        limits.max_component_bytes,
    );
    assert_eq!(node_account, before);
}

#[test]
fn instance_and_complete_node_budgets_preserve_every_input_field() {
    let instance = ComponentGraphInstanceBudget {
        resource_slots: 3,
        memory_bytes: 5 * 65_536,
        total_fuel: 7_000,
        poll_quantum: 700,
    };
    let copied_instance = instance;
    assert_eq!(copied_instance, instance);
    assert_eq!(copied_instance.resource_slots, 3);
    assert_eq!(copied_instance.memory_bytes, 5 * 65_536);
    assert_eq!(copied_instance.total_fuel, 7_000);
    assert_eq!(copied_instance.poll_quantum, 700);

    let node = ComponentGraphNodeBudget {
        component_bytes: 11,
        core_instances: 2,
        adapters: 3,
        resource_types: 5,
        resource_slots: instance.resource_slots,
        memory_bytes: instance.memory_bytes,
        total_fuel: instance.total_fuel,
        poll_quantum: instance.poll_quantum,
    };
    let copied_node = node;
    assert_eq!(copied_node, node);
    assert_eq!(copied_node.component_bytes, 11);
    assert_eq!(copied_node.core_instances, 2);
    assert_eq!(copied_node.adapters, 3);
    assert_eq!(copied_node.resource_types, 5);
    assert_eq!(copied_node.resource_slots, 3);
    assert_eq!(copied_node.memory_bytes, 5 * 65_536);
    assert_eq!(copied_node.total_fuel, 7_000);
    assert_eq!(copied_node.poll_quantum, 700);
}
