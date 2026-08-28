use std::fmt::Write as _;

use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_component_runtime::decode::{inspect_component, ComponentSummary, DecodeError};
use wasm_encoder::{
    Component, ConstExpr, DataSection, MemorySection, MemoryType, Module, ModuleSection,
};

fn parse_component(source: String) -> Vec<u8> {
    wat::parse_str(source).expect("generated Component WAT must encode")
}

fn assert_limit(bytes: &[u8], label: &str) {
    assert_eq!(
        inspect_component(bytes).err(),
        Some(DecodeError::Limit),
        "{label} must fail during inert inspection"
    );
}

fn inspect_summary(bytes: &[u8], label: &str) -> ComponentSummary {
    inspect_component(bytes)
        .unwrap_or_else(|error| panic!("{label} must inspect at the exact limit: {error:?}"))
        .summary()
}

fn component_with_definitions(count: u32) -> Vec<u8> {
    let mut source = String::from("(component");
    for _ in 0..count {
        source.push_str(" (type u32)");
    }
    source.push(')');
    parse_component(source)
}

fn component_with_aliases(count: u32) -> Vec<u8> {
    let mut source = String::from(
        "(component (core module $m (func (export \"f\"))) \
         (core instance $i (instantiate $m))",
    );
    for index in 0..count {
        write!(
            source,
            " (alias core export $i \"f\" (core func $alias{index}))"
        )
        .unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_core_instances(count: u32) -> Vec<u8> {
    let mut source = String::from("(component (core module $m)");
    for index in 0..count {
        write!(source, " (core instance $instance{index} (instantiate $m))").unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_component_instances(count: u32) -> Vec<u8> {
    let mut source = String::from("(component (type $t (func)) (import \"f\" (func $f (type $t)))");
    for index in 0..count {
        write!(
            source,
            " (instance $instance{index} (export \"f\" (func $f)))"
        )
        .unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_both_instance_namespaces(core_count: u32, component_count: u32) -> Vec<u8> {
    let mut source = String::from(
        "(component (core module $m) (type $t (func)) \
         (import \"f\" (func $f (type $t)))",
    );
    for index in 0..core_count {
        write!(source, " (core instance $core{index} (instantiate $m))").unwrap();
    }
    for index in 0..component_count {
        write!(
            source,
            " (instance $component{index} (export \"f\" (func $f)))"
        )
        .unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_canonical_lifts(count: u32) -> Vec<u8> {
    let mut source = String::from(
        "(component (core module $m (func (export \"f\"))) \
         (core instance $i (instantiate $m)) \
         (alias core export $i \"f\" (core func $f)) (type $t (func))",
    );
    for index in 0..count {
        write!(
            source,
            " (func $lift{index} (type $t) (canon lift (core func $f)))"
        )
        .unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_adapters(count: u32) -> Vec<u8> {
    let mut source = String::from("(component (type $t (func)) (import \"f\" (func $f (type $t)))");
    for index in 0..count {
        write!(source, " (core func $lower{index} (canon lower (func $f)))").unwrap();
    }
    source.push(')');
    parse_component(source)
}

fn component_with_type_depth(depth: u32) -> Vec<u8> {
    assert!(depth != 0);
    let mut nested = String::from("u32");
    for _ in 1..depth {
        nested = format!("(instance (type {nested}))");
    }
    parse_component(format!("(component (type {nested}))"))
}

fn component_with_modules(count: u32) -> Vec<u8> {
    let mut source = String::from("(component");
    for _ in 0..count {
        source.push_str(" (core module)");
    }
    source.push(')');
    parse_component(source)
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
        std::iter::repeat_n(0_u8, payload_bytes),
    );
    let mut module = Module::new();
    module.section(&memories).section(&data);
    module
}

fn module_with_exact_size(target: usize) -> Module {
    let mut payload_bytes = target.saturating_sub(32);
    for _ in 0..16 {
        let module = module_with_data(payload_bytes);
        let actual = module.len();
        match actual.cmp(&target) {
            core::cmp::Ordering::Equal => return module,
            core::cmp::Ordering::Less => payload_bytes += target - actual,
            core::cmp::Ordering::Greater => {
                payload_bytes = payload_bytes
                    .checked_sub(actual - target)
                    .expect("module payload adjustment")
            }
        }
    }
    panic!("could not encode an exact {target}-byte Core module")
}

fn component_with_exact_module_size(module_bytes: usize) -> Vec<u8> {
    let module = module_with_exact_size(module_bytes);
    assert_eq!(module.len(), module_bytes);
    let mut component = Component::new();
    component.section(&ModuleSection(&module));
    component.finish()
}

#[test]
fn definitions_accept_the_exact_limit_and_reject_one_more() {
    let maximum = PROFILE_1_LIMITS.max_component_definitions;
    let at_limit = component_with_definitions(maximum);
    assert_eq!(
        inspect_summary(&at_limit, "definitions").definitions,
        maximum
    );
    assert_limit(
        &component_with_definitions(maximum + 1),
        "component definitions",
    );
}

#[test]
fn aliases_accept_the_exact_limit_and_reject_one_more() {
    let maximum = PROFILE_1_LIMITS.max_aliases;
    let at_limit = component_with_aliases(maximum);
    assert_eq!(inspect_summary(&at_limit, "aliases").aliases, maximum);
    assert_limit(&component_with_aliases(maximum + 1), "aliases");
}

#[test]
fn both_instance_namespaces_have_adjacent_limits() {
    let maximum = PROFILE_1_LIMITS.max_component_instances;

    let both_at_limit = component_with_both_instance_namespaces(maximum, maximum);
    let summary = inspect_summary(&both_at_limit, "both instance namespaces");
    assert_eq!(summary.core_instances, maximum);
    assert_eq!(summary.component_instances, maximum);
    assert_limit(
        &component_with_core_instances(maximum + 1),
        "Core instances",
    );

    assert_limit(
        &component_with_component_instances(maximum + 1),
        "Component instances",
    );
}

#[test]
fn canonical_functions_accept_the_exact_limit_and_reject_one_more() {
    let maximum = PROFILE_1_LIMITS.max_canonical_functions;
    let at_limit = component_with_canonical_lifts(maximum);
    assert_eq!(
        inspect_summary(&at_limit, "canonical functions").canonical_functions,
        maximum
    );
    assert_limit(
        &component_with_canonical_lifts(maximum + 1),
        "canonical functions",
    );
}

#[test]
fn adapters_accept_the_exact_limit_and_reject_one_more() {
    let maximum = PROFILE_1_LIMITS.max_adapters;
    let at_limit = component_with_adapters(maximum);
    let summary = inspect_summary(&at_limit, "adapters");
    assert_eq!(summary.adapters, maximum);
    assert_eq!(summary.canonical_functions, maximum);
    assert_limit(&component_with_adapters(maximum + 1), "adapters");
}

#[test]
fn component_type_nesting_has_an_adjacent_limit() {
    let maximum = PROFILE_1_LIMITS.max_component_nesting;
    inspect_summary(&component_with_type_depth(maximum), "component nesting");
    assert_limit(&component_with_type_depth(maximum + 1), "component nesting");
}

#[test]
fn embedded_module_count_has_an_adjacent_limit() {
    let maximum = PROFILE_1_LIMITS.max_embedded_modules;
    let at_limit = component_with_modules(maximum);
    assert_eq!(
        inspect_summary(&at_limit, "embedded module count").embedded_modules,
        maximum
    );
    assert_limit(
        &component_with_modules(maximum + 1),
        "embedded module count",
    );
}

#[test]
fn embedded_module_bytes_have_an_adjacent_limit_before_instantiation() {
    let maximum = PROFILE_1_LIMITS.max_core_module_bytes;
    let at_limit = component_with_exact_module_size(maximum);
    let summary = inspect_summary(&at_limit, "embedded Core module bytes");
    assert_eq!(summary.embedded_modules, 1);
    assert_eq!(summary.embedded_module_bytes, maximum as u64);

    let over_limit = component_with_exact_module_size(maximum + 1);
    assert!(over_limit.len() <= PROFILE_1_LIMITS.max_component_bytes);
    assert_limit(&over_limit, "embedded Core module bytes");
}
