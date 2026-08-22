use vibeos_component_format::ProfileIdentity;
use vibeos_component_host::{
    HostManifestError, HostResourceKind, VibeHostManifest, CLOCK_INTERFACE, RANDOM_INTERFACE,
};
use vibeos_component_runtime::decode::{inspect_component, inspect_component_for_profile};
use vibeos_core::cap::Rights;

const CLOCK_COMPONENT: &str =
    include_str!("../../../component-runtime/tests/fixtures/host-clock.component.wat");
const INTERNAL_INTERFACE: &str = "test:graph/internal@1.0.0";
const UNUSED_CLOCK_COMPONENT: &str = r#"
    (component
      (type $clock-interface
        (instance
          (export "clock" (type (sub resource)))
          (type $borrow-clock (borrow 0))
          (type $now-type
            (func
              (param "clock" $borrow-clock)
              (result u64)))
          (export "now" (func (type $now-type)))))
      (import "vibe:clock/monotonic@1.0.0"
        (instance $clock (type $clock-interface))))
"#;
const ASYNC_UNUSED_CLOCK_COMPONENT: &str = r#"
    (component
      (type $clock-interface
        (instance
          (export "clock" (type (sub resource)))
          (type $borrow-clock (borrow 0))
          (type $now-type
            (func
              (param "clock" $borrow-clock)
              (result u64)))
          (export "now" (func (type $now-type)))))
      (import "vibe:clock/monotonic@1.0.0"
        (instance $clock (type $clock-interface)))

      (type $pending-u32 (future u32))
      (type $run-type (func async (param "pending" $pending-u32)))
      (import "source" (func $source (type $run-type)))
      (export "run" (func $source)))
"#;

fn clock_with_unused_random_source() -> String {
    CLOCK_COMPONENT.replacen(
        "  (type $clock-interface",
        r#"  (type $unused-random-interface
    (instance
      (export "random-source" (type $random-source-in (sub resource)))
      (type $borrow-source-in (borrow $random-source-in))
      (type $error-private (enum "denied" "exhausted"))
      (export "random-error" (type $error-in (eq $error-private)))
      (type $fill-type
        (func
          (param "source" $borrow-source-in)
          (param "len" u32)
          (result (result (list u8) (error $error-in)))))
      (export "fill" (func (type $fill-type)))))
  (import "vibe:random/random@1.0.0"
    (instance $unused-random (type $unused-random-interface)))

  (type $clock-interface"#,
        1,
    )
}

fn mixed_source() -> String {
    let source = CLOCK_COMPONENT.replacen(
        "  (type $clock-interface",
        r#"  (type $internal-interface
    (instance
      (type $ping-type (func))
      (export "ping" (func (type $ping-type)))))
  (import "test:graph/internal@1.0.0"
    (instance $internal (type $internal-interface)))
  (alias export $internal "ping" (func $ping))
  (core func $lowered-ping (canon lower (func $ping)))
  (core instance $internal-core
    (export "ping" (func $lowered-ping)))

  (type $clock-interface"#,
        1,
    );
    let source = source.replacen(
        "    (import \"vibe:clock/monotonic@1.0.0\" \"now\"",
        "    (import \"test:graph/internal@1.0.0\" \"ping\" (func $ping))\n    (import \"vibe:clock/monotonic@1.0.0\" \"now\"",
        1,
    );
    source.replacen(
        "      (with \"vibe:clock/monotonic@1.0.0\" (instance $clock-core))))",
        "      (with \"vibe:clock/monotonic@1.0.0\" (instance $clock-core))\n      (with \"test:graph/internal@1.0.0\" (instance $internal-core))))",
        1,
    )
}

#[test]
fn full_plan_behavior_is_unchanged_and_exact_selection_is_equivalent() {
    let bytes = wat::parse_str(CLOCK_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.imports().len(), 1);

    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[0]).unwrap(),
        VibeHostManifest::from_plan(&plan).unwrap()
    );
}

#[test]
fn selected_import_excludes_unselected_normalized_import_and_flattened_calls() {
    let source = mixed_source();
    assert_ne!(source, CLOCK_COMPONENT);
    let bytes = wat::parse_str(&source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.imports().len(), 2);
    assert_eq!(plan.imports()[0].name, INTERNAL_INTERFACE);
    assert_eq!(plan.imports()[1].name, CLOCK_INTERFACE);
    assert!(plan
        .host_imports()
        .any(|import| import.interface == INTERNAL_INTERFACE));
    assert!(plan
        .host_imports()
        .any(|import| import.interface == CLOCK_INTERFACE));

    assert_eq!(
        VibeHostManifest::from_plan(&plan),
        Err(HostManifestError::UnexpectedImport)
    );
    let selected = VibeHostManifest::from_selected_imports(&plan, &[1]).unwrap();
    let requirements = selected.requirements().collect::<Vec<_>>();
    assert_eq!(requirements.len(), 1);
    assert_eq!(requirements[0].interface(), CLOCK_INTERFACE);
    assert_eq!(requirements[0].resource(), "clock");
    assert_eq!(requirements[0].kind(), HostResourceKind::Clock);
    assert_eq!(requirements[0].rights(), Rights::READ);

    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[0]),
        Err(HostManifestError::UnexpectedImport)
    );
    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[])
            .unwrap()
            .requirements()
            .count(),
        0
    );
}

#[test]
fn duplicate_and_out_of_range_import_indices_fail_closed() {
    let bytes = wat::parse_str(CLOCK_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();

    for selected in [&[0, 0][..], &[1][..], &[u16::MAX][..]] {
        assert_eq!(
            VibeHostManifest::from_selected_imports(&plan, selected),
            Err(HostManifestError::InvalidSelection),
            "selection={selected:?}"
        );
    }
}

#[test]
fn selected_interface_without_resolved_calls_never_yields_an_empty_authority_manifest() {
    let bytes = wat::parse_str(UNUSED_CLOCK_COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.imports().len(), 1);
    assert_eq!(plan.host_imports().count(), 0);
    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[0]),
        Err(HostManifestError::Empty)
    );
}

#[test]
fn multi_selection_rejects_one_exact_host_interface_without_resolved_calls() {
    let source = clock_with_unused_random_source();
    assert_ne!(source, CLOCK_COMPONENT);
    let bytes = wat::parse_str(&source).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.imports().len(), 2);
    assert_eq!(plan.imports()[0].name, RANDOM_INTERFACE);
    assert_eq!(plan.imports()[1].name, CLOCK_INTERFACE);
    let flattened = plan.host_imports().collect::<Vec<_>>();
    assert_eq!(flattened.len(), 1);
    assert_eq!(flattened[0].interface, CLOCK_INTERFACE);

    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[1])
            .unwrap()
            .requirements()
            .count(),
        1
    );
    for selected in [&[0, 1][..], &[1, 0][..]] {
        assert_eq!(
            VibeHostManifest::from_selected_imports(&plan, selected),
            Err(HostManifestError::Empty),
            "selection={selected:?}"
        );
    }
}

#[test]
fn selected_host_import_without_calls_fails_closed_in_an_async_plan() {
    let bytes = wat::parse_str(ASYNC_UNUSED_CLOCK_COMPONENT).unwrap();
    let plan = inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert!(!plan.summary().async_abi.is_empty());
    assert!(!plan.native_async_runtime_ready());
    assert_eq!(plan.imports()[0].name, CLOCK_INTERFACE);
    assert_eq!(plan.host_imports().count(), 0);

    assert_eq!(
        VibeHostManifest::from_selected_imports(&plan, &[0]),
        Err(HostManifestError::Empty)
    );
}
