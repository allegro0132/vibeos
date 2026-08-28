use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, WasmiCompilationMode, WasmiEnforcedLimits,
    WasmiFuelCosts,
};
use vibeos_wasm_runtime::{
    current_core_validation_engine, inspect_core_with_current_engine, ProfileEngine,
};

#[test]
fn c75_core_validation_and_execution_share_one_current_identity() {
    let gate = current_core_validation_engine(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    let expected = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    let runtime = gate.identity().runtime();
    assert_eq!(gate.identity(), expected);
    assert_eq!(runtime.compilation_mode(), WasmiCompilationMode::Eager);
    assert_eq!(runtime.enforced_limits(), WasmiEnforcedLimits::Strict);
    assert_eq!(runtime.fuel_costs(), WasmiFuelCosts::Wasmi110Default);

    let engine = ProfileEngine::new();
    assert_eq!(engine.validation_identity(), gate.identity());

    let core = wat::parse_str("(module (func (export \"run\") (result i32) i32.const 7))").unwrap();
    let summary = inspect_core_with_current_engine(&core, &gate).unwrap();
    assert_eq!(summary.functions, 1);
    assert_eq!(summary.exports, 1);
}

#[test]
fn c75_core_gate_rejects_an_adjacent_profile_without_fallback() {
    let mut adjacent = ProfileIdentity::PROFILE_1_SYNC;
    adjacent.core_revision = "webassembly-core-adjacent";
    assert!(current_core_validation_engine(adjacent).is_none());
    assert!(
        current_core_validation_engine(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none(),
        "C8.8-F1 code 5 must never enter the current Core engine resolver"
    );
}
