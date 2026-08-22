use std::sync::Arc;

use vibeos_component_admission::{
    admit_component_graph, ArtifactTrust, CallerAuthority, ComponentArtifact,
    ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy,
    InstanceLimits, ProfileIdentity,
};
use vibeos_component_command::{
    ComponentGraphNodePrincipalTemplate, ComponentGraphNodeReportError, ComponentGraphNodeTerminal,
    ComponentGraphPrincipalIsolation, ComponentGraphPrincipalTemplate,
};
use vibeos_component_runtime::{
    graph::{ComponentGraphNesting, ComponentGraphNodeId},
    world::WorldContract,
};

const EMPTY_WORLD_WIT: &str = r#"
    package test:c63@1.0.0;

    world empty {}
"#;

const EMPTY_WORLD: &str = "test:c63/empty@1.0.0";

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
