use vibeos_component_runtime::{
    decode::{inspect_component, CanonicalStringEncoding, DecodeError},
    resource::ResourceTypeId,
    value::{ResourceOwnership, ValueType},
    world::{WorldContract, WorldError},
};

const COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/typed.component.wat");
const RICH_EXECUTABLE_COMPONENT: &str = include_str!("fixtures/rich.component.wat");
const PROFILE_WORLD: &str = include_str!("../../component-format/tests/corpus/wit/world.wit");

const WORLD: &str = r#"
    package vibe:fixture@1.0.0;
    world calculator {
        export add: func(lhs: s32, rhs: s32) -> s32;
    }
"#;

const RICH_WORLD: &str = r#"
    package vibe:fixture@1.0.0;
    interface filter {
        resource random-source;
        flags flags-value { urgent, audited }
        enum error-code { denied, invalid, exhausted }
        record request {
            label: string,
            payload: list<u8>,
            attributes: flags-value,
        }
        variant response {
            accepted(tuple<string, list<u8>>),
            rejected(error-code),
        }
        transform: func(value: request) -> response;
    }
    world typed-filter {
        import filter;
    }
"#;

const RICH_COMPONENT: &str = r#"
    (component
      (type $filter
        (instance
          (export "random-source" (type (sub resource)))
          (type $borrow (borrow 0))
          (type $flags (flags "urgent" "audited"))
          (export "flags-value" (type $flags-public (eq $flags)))
          (type $error (enum "denied" "invalid" "exhausted"))
          (export "error-code" (type $error-public (eq $error)))
          (type $bytes (list u8))
          (type $request
            (record
              (field "label" string)
              (field "payload" $bytes)
              (field "attributes" $flags-public)))
          (export "request" (type $request-public (eq $request)))
          (type $accepted (tuple string $bytes))
          (type $response
            (variant
              (case "accepted" $accepted)
              (case "rejected" $error-public)))
          (export "response" (type $response-public (eq $response)))
          (type $transform
            (func
              (param "value" $request-public)
              (result $response-public)))
          (export "transform" (func (type $transform)))))
      (import "vibe:fixture/filter@1.0.0" (instance $imported (type $filter)))
    )
"#;

#[test]
fn exact_world_matches_validated_component_types() {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(plan.summary.embedded_modules, 1);
    assert_eq!(plan.summary.core_instances, 1);
    assert_eq!(plan.summary.canonical_functions, 2);
    assert_eq!(plan.summary.adapters, 1);
    assert_eq!(plan.exports.len(), 1);
    let world = WorldContract::parse(WORLD, "vibe:fixture/calculator@1.0.0").unwrap();
    plan.check_world(&world).unwrap();
}

#[test]
fn rich_interface_graph_matches_records_variants_and_resources_exactly() {
    let bytes = wat::parse_str(RICH_COMPONENT).unwrap();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(&bytes)
        .unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract::parse(RICH_WORLD, "vibe:fixture/typed-filter@1.0.0").unwrap();
    plan.check_world(&world).unwrap();

    let wrong = RICH_WORLD.replace("payload: list<u8>", "payload: list<u16>");
    let wrong = WorldContract::parse(&wrong, "vibe:fixture/typed-filter@1.0.0").unwrap();
    assert_eq!(plan.check_world(&wrong), Err(WorldError::TypeMismatch));
}

#[test]
fn executable_rich_fixture_matches_the_exact_profile_world() {
    let bytes = wat::parse_str(RICH_EXECUTABLE_COMPONENT).unwrap();
    let mut features = wasmparser::WasmFeatures::empty();
    features.set(wasmparser::WasmFeatures::COMPONENT_MODEL, true);
    wasmparser::Validator::new_with_features(features)
        .validate_all(&bytes)
        .unwrap();

    let plan = inspect_component(&bytes).unwrap();
    let world = WorldContract::parse(PROFILE_WORLD, "vibe:fixture/typed-filter@1.0.0").unwrap();
    plan.check_world(&world).unwrap();
    let exports: Vec<_> = plan.executable_exports().collect();
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].name, "vibe:fixture/filter@1.0.0#transform");
    assert_eq!(exports[0].core_instance, 0);
    assert_eq!(exports[0].core_function, "transform");
    assert_eq!(
        exports[0].string_encoding,
        Some(CanonicalStringEncoding::Utf8)
    );
    assert_eq!(exports[0].memory.as_deref(), Some("memory"));
    assert_eq!(exports[0].realloc.as_deref(), Some("cabi_realloc"));
    assert_eq!(
        exports[0].post_return.as_deref(),
        Some("cabi_post_transform")
    );
    assert_eq!(exports[0].function.parameters[0].name, "value");
    assert_eq!(
        exports[0].function.parameters[0].value,
        ValueType::Record(vec![
            ValueType::String,
            ValueType::List(Box::new(ValueType::U8)),
            ValueType::Flags(2),
        ])
    );
    assert_eq!(exports[0].function.parameters[1].name, "source");
    assert_eq!(
        exports[0].function.parameters[1].value,
        ValueType::Resource {
            resource_type: ResourceTypeId(1),
            ownership: ResourceOwnership::Borrow,
        }
    );
    assert_eq!(
        exports[0].function.result,
        Some(ValueType::Variant(vec![
            Some(ValueType::Tuple(vec![
                ValueType::String,
                ValueType::List(Box::new(ValueType::U8)),
            ])),
            Some(ValueType::Enum(3)),
        ]))
    );
}

#[test]
fn rich_fixture_rejects_missing_or_wrong_canonical_wiring() {
    let missing_memory = RICH_EXECUTABLE_COMPONENT.replace("\n      (memory $memory)", "");
    let bytes = wat::parse_str(&missing_memory).unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Malformed | DecodeError::InvalidWiring)
    ));

    let missing_realloc = RICH_EXECUTABLE_COMPONENT.replace("\n      (realloc $realloc)", "");
    let bytes = wat::parse_str(&missing_realloc).unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Malformed | DecodeError::InvalidWiring)
    ));

    let missing_post_return =
        RICH_EXECUTABLE_COMPONENT.replace("\n      (post-return $post-return)", "");
    let bytes = wat::parse_str(&missing_post_return).unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::InvalidWiring)
    ));

    let wrong_function = RICH_EXECUTABLE_COMPONENT.replace(
        "(canon lift (core func $transform)",
        "(canon lift (core func $realloc)",
    );
    let bytes = wat::parse_str(&wrong_function).unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::Malformed | DecodeError::InvalidWiring)
    ));

    let cross_instance_memory = RICH_EXECUTABLE_COMPONENT
        .replace(
            "  (core instance $guest-instance (instantiate $guest))",
            "  (core module $other (memory (export \"memory\") 1 1))\n\
             \n  (core instance $guest-instance (instantiate $guest))\n\
             \n  (core instance $other-instance (instantiate $other))",
        )
        .replace(
            "  (alias core export $guest-instance \"cabi_realloc\" (core func $realloc))",
            "  (alias core export $guest-instance \"cabi_realloc\" (core func $realloc))\n\
             \n  (alias core export $other-instance \"memory\" (core memory $other-memory))",
        )
        .replace("(memory $memory)", "(memory $other-memory)");
    let bytes = wat::parse_str(&cross_instance_memory).unwrap();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(&bytes)
        .unwrap();
    assert!(matches!(
        inspect_component(&bytes),
        Err(DecodeError::InvalidWiring)
    ));
}

#[test]
fn omitted_string_encoding_uses_the_validated_utf8_default() {
    let default_utf8 = RICH_EXECUTABLE_COMPONENT.replace("\n      string-encoding=utf8", "");
    let bytes = wat::parse_str(&default_utf8).unwrap();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all())
        .validate_all(&bytes)
        .unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let export = plan.executable_exports().next().unwrap();
    assert_eq!(export.string_encoding, None);
}

#[test]
fn local_instance_function_alias_preserves_the_validated_lift() {
    let bytes = wat::parse_str(
        r#"(component
              (core module $m (func (export "f") (result i32) i32.const 7))
              (core instance $i (instantiate $m))
              (alias core export $i "f" (core func $f))
              (type $t (func (result s32)))
              (func $lifted (type $t) (canon lift (core func $f)))
              (instance $interface (export "f" (func $lifted)))
              (alias export $interface "f" (func $aliased))
              (export "aliased" (func $aliased)))"#,
    )
    .unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let exports: Vec<_> = plan.executable_exports().collect();
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].name, "aliased");
    assert_eq!(exports[0].core_instance, 0);
    assert_eq!(exports[0].core_function, "f");
    assert_eq!(exports[0].function.result, Some(ValueType::S32));
}

#[test]
fn exact_version_names_and_types_fail_closed() {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    assert_eq!(
        WorldContract::parse(WORLD, "calculator"),
        Err(WorldError::VersionMismatch)
    );
    assert_eq!(
        WorldContract::parse(WORLD, "vibe:fixture/calculator@2.0.0"),
        Err(WorldError::VersionMismatch)
    );

    let wrong_type = WORLD.replace("rhs: s32", "rhs: u32");
    let contract = WorldContract::parse(&wrong_type, "vibe:fixture/calculator@1.0.0").unwrap();
    assert_eq!(plan.check_world(&contract), Err(WorldError::TypeMismatch));

    let extra = WORLD.replace("}", "export extra: func();\n}");
    let contract = WorldContract::parse(&extra, "vibe:fixture/calculator@1.0.0").unwrap();
    assert_eq!(plan.check_world(&contract), Err(WorldError::MissingExport));

    let duplicate = WORLD.replace(
        "export add: func(lhs: s32, rhs: s32) -> s32;",
        "export add: func(lhs: s32, rhs: s32) -> s32;\nexport add: func();",
    );
    assert_eq!(
        WorldContract::parse(&duplicate, "vibe:fixture/calculator@1.0.0"),
        Err(WorldError::InvalidWit)
    );
}

#[test]
fn unsupported_composition_async_and_invalid_core_are_rejected() {
    let nested = wat::parse_str("(component (component))").unwrap();
    assert!(matches!(
        inspect_component(&nested),
        Err(DecodeError::Unsupported)
    ));

    let asynchronous = wat::parse_str(
        r#"(component
              (core module $m (func (export "f")))
              (core instance $i (instantiate $m))
              (type $t (func))
              (func $f (type $t) (canon lift (core func $i "f") async))
              (export "f" (func $f)))"#,
    )
    .unwrap();
    assert!(matches!(
        inspect_component(&asynchronous),
        Err(DecodeError::Unsupported)
    ));

    let invalid_core = wat::parse_str("(component (core module (memory 1)))").unwrap();
    assert!(matches!(
        inspect_component(&invalid_core),
        Err(DecodeError::InvalidEmbeddedCore)
    ));
}

#[test]
fn definition_limit_is_checked_before_validation() {
    let mut source = String::from("(component");
    for _ in 0..=vibeos_component_format::PROFILE_1_LIMITS.max_component_definitions {
        source.push_str(" (type u32)");
    }
    source.push(')');
    let bytes = wat::parse_str(&source).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));
}

#[test]
fn aliases_instances_canonicals_and_adapters_have_independent_limits() {
    let limits = vibeos_component_format::PROFILE_1_LIMITS;

    let mut aliases = String::from(
        "(component (core module $m (func (export \"f\"))) \
         (core instance $i (instantiate $m))",
    );
    for index in 0..=limits.max_aliases {
        aliases.push_str(&format!(
            " (alias core export $i \"f\" (core func $a{index}))"
        ));
    }
    aliases.push(')');
    let bytes = wat::parse_str(&aliases).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));

    let mut instances =
        String::from("(component (type $t (func)) (import \"f\" (func $f (type $t)))");
    for _ in 0..=limits.max_component_instances {
        instances.push_str(" (instance (export \"f\" (func $f)))");
    }
    instances.push(')');
    let bytes = wat::parse_str(&instances).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));

    let mut canonicals = String::from(
        "(component (core module $m (func (export \"f\"))) \
         (core instance $i (instantiate $m)) \
         (alias core export $i \"f\" (core func $f)) (type $t (func))",
    );
    for _ in 0..=limits.max_canonical_functions {
        canonicals.push_str(" (func (type $t) (canon lift (core func $f)))");
    }
    canonicals.push(')');
    let bytes = wat::parse_str(&canonicals).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));

    let mut adapters =
        String::from("(component (type $t (func)) (import \"f\" (func $f (type $t)))");
    for _ in 0..=limits.max_adapters {
        adapters.push_str(" (core func (canon lower (func $f)))");
    }
    adapters.push(')');
    let bytes = wat::parse_str(&adapters).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));
}

#[test]
fn component_nesting_and_embedded_module_counts_are_bounded() {
    let limits = vibeos_component_format::PROFILE_1_LIMITS;
    let mut nested = String::from("u32");
    for _ in 0..=limits.max_component_nesting {
        nested = format!("(instance (type {nested}))");
    }
    let bytes = wat::parse_str(format!("(component (type {nested}))")).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));

    let mut modules = String::from("(component");
    for _ in 0..=limits.max_embedded_modules {
        modules.push_str(" (core module)");
    }
    modules.push(')');
    let bytes = wat::parse_str(&modules).unwrap();
    assert!(matches!(inspect_component(&bytes), Err(DecodeError::Limit)));
}

#[test]
fn missing_and_unexpected_world_items_are_distinct() {
    let bytes = wat::parse_str(COMPONENT).unwrap();
    let plan = inspect_component(&bytes).unwrap();
    let missing_import = r#"
        package vibe:fixture@1.0.0;
        world calculator {
            import clock: func() -> u64;
            export add: func(lhs: s32, rhs: s32) -> s32;
        }
    "#;
    let contract = WorldContract::parse(missing_import, "vibe:fixture/calculator@1.0.0").unwrap();
    assert_eq!(plan.check_world(&contract), Err(WorldError::MissingImport));

    let no_exports = r#"
        package vibe:fixture@1.0.0;
        world calculator {}
    "#;
    let contract = WorldContract::parse(no_exports, "vibe:fixture/calculator@1.0.0").unwrap();
    assert_eq!(
        plan.check_world(&contract),
        Err(WorldError::UnexpectedExport)
    );
}

#[test]
fn arbitrary_component_bytes_never_panic() {
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for length in 0..512_usize {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        assert!(std::panic::catch_unwind(|| {
            let _ = inspect_component(&bytes);
        })
        .is_ok());
    }
}
