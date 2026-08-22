use vibeos_component_runtime::{
    decode::{inspect_component, inspect_component_graph},
    graph::{ComponentGraphEntityIndex, ComponentGraphResourceStatus},
};

const RESOURCE_PRODUCER: &str = r#"
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
      (export "test:graph-resource/pipe@1.0.0" (instance $pipe)))
"#;

const RESOURCE_CONSUMER: &str = r#"
    (component
      (type $pipe
        (instance
          (export "handle" (type $handle (sub resource)))
          (type $borrow-handle (borrow $handle))
          (type $send-type (func (param "value" $borrow-handle)))
          (export "send" (func (type $send-type)))))
      (import "test:graph-resource/pipe@1.0.0" (instance $pipe-in (type $pipe))))
"#;

const CROSS_ENTITY_RESOURCE_USE: &str = include_str!("fixtures/host-stream.component.wat");

const DUPLICATE_INTERFACE_RESOURCE_ROOT: &str = r#"
    (component
      (type $handle (resource (rep i32)))
      (instance $pipe
        (export "first" (type $handle))
        (export "second" (type $handle)))
      (export "test:graph-resource/duplicate@1.0.0" (instance $pipe)))
"#;

#[test]
fn graph_inspection_is_opt_in_and_resource_free_evidence_is_aligned() {
    let bytes = wat::parse_str(
        r#"
            (component
              (type $ping (func (param "value" u32)))
              (import "ping" (func $ping (type $ping))))
        "#,
    )
    .unwrap();
    let ordinary = inspect_component(&bytes).unwrap();
    let graph = inspect_component_graph(&bytes).unwrap();

    assert_eq!(ordinary.summary(), graph.plan().summary());
    assert_eq!(ordinary.imports(), graph.plan().imports());
    assert_eq!(ordinary.exports(), graph.plan().exports());
    assert_eq!(graph.resources().imports().len(), 1);
    assert!(graph.resources().exports().is_empty());
    assert_eq!(
        graph.resources().imports()[0].status(),
        ComponentGraphResourceStatus::ResourceFree
    );
    assert!(graph.resources().imports()[0].declarations().is_empty());

    let (plan, resources) = graph.into_parts();
    assert_eq!(plan.summary(), ordinary.summary());
    assert_eq!(resources.imports().len(), plan.imports().len());
    assert_eq!(resources.exports().len(), plan.exports().len());
}

#[test]
fn direct_interface_resource_and_exact_borrow_are_graph_matchable() {
    let producer = wat::parse_str(RESOURCE_PRODUCER).unwrap();
    let consumer = wat::parse_str(RESOURCE_CONSUMER).unwrap();
    let producer = inspect_component_graph(&producer).unwrap();
    let consumer = inspect_component_graph(&consumer).unwrap();

    let exported = producer
        .resources()
        .export(ComponentGraphEntityIndex::new(0))
        .unwrap();
    let imported = consumer
        .resources()
        .import(ComponentGraphEntityIndex::new(0))
        .unwrap();
    assert_eq!(
        exported.status(),
        ComponentGraphResourceStatus::ExactInterface
    );
    assert_eq!(
        imported.status(),
        ComponentGraphResourceStatus::ExactInterface
    );
    assert_eq!(exported.declarations().len(), 1);
    assert_eq!(imported.declarations().len(), 1);
    assert_eq!(exported.declarations()[0].member().index(), 0);
    assert_eq!(imported.declarations()[0].member().index(), 0);
}

#[test]
fn cross_entity_nominal_use_fails_closed_only_in_sidecar() {
    let bytes = wat::parse_str(CROSS_ENTITY_RESOURCE_USE).unwrap();

    // Ordinary inspection continues accepting this valid Component.
    let ordinary = inspect_component(&bytes).unwrap();
    let graph = inspect_component_graph(&bytes).unwrap();
    assert_eq!(ordinary.summary(), graph.plan().summary());

    assert_eq!(
        graph.resources().imports()[0].status(),
        ComponentGraphResourceStatus::Unsupported
    );
    assert_eq!(
        graph.resources().exports()[0].status(),
        ComponentGraphResourceStatus::Unsupported
    );
    assert!(graph.resources().imports()[0].declarations().is_empty());
    assert!(graph.resources().exports()[0].declarations().is_empty());
}

#[test]
fn two_interface_members_for_one_nominal_root_fail_closed_only_in_sidecar() {
    let bytes = wat::parse_str(DUPLICATE_INTERFACE_RESOURCE_ROOT).unwrap();

    // The Component itself remains valid; only graph nominal routing rejects
    // the ambiguous pair of semantic member names for one resource root.
    let ordinary = inspect_component(&bytes).unwrap();
    let graph = inspect_component_graph(&bytes).unwrap();
    assert_eq!(ordinary.summary(), graph.plan().summary());
    assert_eq!(ordinary.exports(), graph.plan().exports());
    assert_eq!(
        graph.resources().exports()[0].status(),
        ComponentGraphResourceStatus::Unsupported
    );
    assert!(graph.resources().exports()[0].declarations().is_empty());
}
