use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, WasmParserFeatureSelection,
};
use vibeos_component_runtime::{
    decode::{current_component_validation_engine, inspect_component_with_current_engine},
    world::WorldContract,
};

const WIT: &str = r#"
    package test:current-engine@1.0.0;
    world api {}
"#;
const WORLD: &str = "test:current-engine/api@1.0.0";

#[test]
fn c75_component_and_wit_validation_consume_the_same_current_gate() {
    let gate = current_component_validation_engine(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    let expected = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    assert_eq!(gate.identity(), expected);
    assert_eq!(
        gate.identity().component_validator().strict_features(),
        WasmParserFeatureSelection::ComponentModel
    );

    let bytes = wat::parse_str("(component)").unwrap();
    let plan = inspect_component_with_current_engine(&bytes, &gate).unwrap();
    assert_eq!(plan.profile(), ProfileIdentity::PROFILE_1_SYNC);

    let world = WorldContract::parse_with_current_engine(WIT, WORLD, &gate).unwrap();
    assert_eq!(world.identity, WORLD);
    assert!(world.imports.is_empty());
    assert!(world.exports.is_empty());
}

#[test]
fn c75_async_selection_is_distinct_and_adjacent_profile_has_no_gate() {
    let async_gate = current_component_validation_engine(ProfileIdentity::PROFILE_1_ASYNC).unwrap();
    assert!(async_gate
        .identity()
        .component_validator()
        .predecode_async());
    assert_eq!(
        async_gate
            .identity()
            .component_validator()
            .strict_features(),
        WasmParserFeatureSelection::ComponentModelAsync
    );

    let mut adjacent = ProfileIdentity::PROFILE_1_SYNC;
    adjacent.wasm_tools_revision = "wasm-tools-adjacent";
    assert!(current_component_validation_engine(adjacent).is_none());
}
