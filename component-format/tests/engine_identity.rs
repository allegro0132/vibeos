use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, WasmParserFeatureSelection,
    WasmiCompilationMode, WasmiEnforcedLimits, WasmiFuelCosts, COMPONENT_WASMPARSER_FEATURES,
    CORE_WASMPARSER_FEATURES, PROFILE_1_LIMITS, WASMI_1_1_0_CHECKSUM, WASMI_1_1_0_VERSION,
    WASMI_FEATURES, WASMI_WASMPARSER_0_239_0_CHECKSUM, WASMI_WASMPARSER_0_239_0_VERSION,
    WASMI_WASMPARSER_FEATURES, WASMPARSER_0_255_0_CHECKSUM, WASMPARSER_0_255_0_VERSION,
    WIT_PARSER_0_255_0_CHECKSUM, WIT_PARSER_0_255_0_VERSION, WIT_PARSER_FEATURES,
};

#[test]
fn c75_current_engine_identity_is_exact_and_profile_bound() {
    let identity = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    assert_eq!(identity.profile(), ProfileIdentity::PROFILE_1_SYNC);

    let component = identity.component_wasmparser();
    assert_eq!(component.name(), "wasmparser");
    assert_eq!(component.version(), WASMPARSER_0_255_0_VERSION);
    assert_eq!(component.checksum(), WASMPARSER_0_255_0_CHECKSUM);
    assert_eq!(component.features(), COMPONENT_WASMPARSER_FEATURES);

    let core = identity.core_wasmparser();
    assert_eq!(core.name(), "wasmparser");
    assert_eq!(core.version(), WASMPARSER_0_255_0_VERSION);
    assert_eq!(core.checksum(), WASMPARSER_0_255_0_CHECKSUM);
    assert_eq!(core.features(), CORE_WASMPARSER_FEATURES);

    let wit = identity.wit_parser();
    assert_eq!(wit.name(), "wit-parser");
    assert_eq!(wit.version(), WIT_PARSER_0_255_0_VERSION);
    assert_eq!(wit.checksum(), WIT_PARSER_0_255_0_CHECKSUM);
    assert_eq!(wit.features(), WIT_PARSER_FEATURES);

    let wasmi = identity.wasmi();
    assert_eq!(wasmi.name(), "wasmi");
    assert_eq!(wasmi.version(), WASMI_1_1_0_VERSION);
    assert_eq!(wasmi.checksum(), WASMI_1_1_0_CHECKSUM);
    assert_eq!(wasmi.features(), WASMI_FEATURES);

    let internal = identity.wasmi_wasmparser();
    assert_eq!(internal.name(), "wasmparser");
    assert_eq!(internal.version(), WASMI_WASMPARSER_0_239_0_VERSION);
    assert_eq!(internal.checksum(), WASMI_WASMPARSER_0_239_0_CHECKSUM);
    assert_eq!(internal.features(), WASMI_WASMPARSER_FEATURES);

    let component_validator = identity.component_validator();
    assert!(!component_validator.predecode_async());
    assert_eq!(
        component_validator.structural_features(),
        WasmParserFeatureSelection::All
    );
    assert_eq!(
        component_validator.strict_features(),
        WasmParserFeatureSelection::ComponentModel
    );
    assert_eq!(
        component_validator.diagnostic_features(),
        WasmParserFeatureSelection::All
    );

    let core_validator = identity.core_validator();
    assert_eq!(
        core_validator.structural_features(),
        WasmParserFeatureSelection::All
    );
    assert_eq!(
        core_validator.strict_features(),
        WasmParserFeatureSelection::Empty
    );
    assert_eq!(
        core_validator.diagnostic_features(),
        WasmParserFeatureSelection::All
    );
}

#[test]
fn c75_wasmi_configuration_is_closed_field_by_field() {
    let runtime = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC)
        .unwrap()
        .runtime();
    assert!(!runtime.floats());
    assert!(!runtime.mutable_global());
    assert!(!runtime.sign_extension());
    assert!(!runtime.saturating_float_to_int());
    assert!(!runtime.multi_value());
    assert!(!runtime.multi_memory());
    assert!(!runtime.bulk_memory());
    assert!(!runtime.reference_types());
    assert!(!runtime.tail_call());
    assert!(!runtime.extended_const());
    assert!(!runtime.custom_page_sizes());
    assert!(!runtime.memory64());
    assert!(!runtime.wide_arithmetic());
    assert!(!runtime.simd_compiled());
    assert!(!runtime.relaxed_simd_compiled());
    assert!(runtime.consume_fuel());
    assert!(!runtime.ignore_custom_sections());
    assert_eq!(runtime.compilation_mode(), WasmiCompilationMode::Eager);
    assert_eq!(runtime.max_recursion_depth(), 128);
    assert_eq!(
        runtime.max_recursion_depth(),
        PROFILE_1_LIMITS.max_call_depth as usize
    );
    assert_eq!(runtime.min_stack_height(), 4 * 1024);
    assert_eq!(runtime.max_stack_height(), 128 * 1024);
    assert_eq!(runtime.max_cached_stacks(), 0);
    assert_eq!(runtime.enforced_limits(), WasmiEnforcedLimits::Strict);
    assert_eq!(runtime.fuel_costs(), WasmiFuelCosts::Wasmi110Default);
}

#[test]
fn c75_engine_payloads_match_actual_cargo_pins_and_lock_checksums() {
    let component_manifest = include_str!("../../component-runtime/Cargo.toml");
    let core_manifest = include_str!("../../wasm-runtime/Cargo.toml");
    let lock = include_str!("../../Cargo.lock");

    assert!(component_manifest.contains(
        "wasmparser = { version = \"=0.255.0\", default-features = false, features = [\"component-model\", \"features\", \"prefer-btree-collections\", \"validate\"] }"
    ));
    assert!(component_manifest
        .contains("wit-parser = { version = \"=0.255.0\", default-features = false }"));
    assert!(core_manifest.contains(
        "wasmi = { version = \"=1.1.0\", default-features = false, features = [\"extra-checks\", \"prefer-btree-collections\"] }"
    ));
    assert!(core_manifest.contains(
        "wasmparser = { version = \"=0.255.0\", default-features = false, features = [\"features\", \"prefer-btree-collections\", \"validate\"] }"
    ));
    // These direct requests resolve to one wasmparser package instance in the
    // production graph, so both role identities must record the union rather
    // than describing the Core manifest's narrower request as compiled fact.
    assert_eq!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC)
            .unwrap()
            .component_wasmparser()
            .features(),
        "default-features=false;component-model,features,prefer-btree-collections,validate"
    );
    assert_eq!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC)
            .unwrap()
            .core_wasmparser()
            .features(),
        "default-features=false;component-model,features,prefer-btree-collections,validate"
    );

    for exact_entry in [
        "name = \"wasmi\"\nversion = \"1.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"2300d0f78cba12f14e29e8dd157ea64050c0a688179aefdb2050105805594a0c\"",
        "name = \"wasmparser\"\nversion = \"0.239.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"8c9d90bb93e764f6beabf1d02028c70a2156a6583e63ac4218dd07ef733368b0\"",
        "name = \"wasmparser\"\nversion = \"0.255.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"e8e329ef4b5d46e73b91d3ac6924417cad55a8cbbf869c199283383427c3320b\"",
        "name = \"wit-parser\"\nversion = \"0.255.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab5f6371fc71f15730b756c1dea3562a67adab1a7e519c4ca010173d883695bb\"",
    ] {
        assert!(lock.contains(exact_entry), "missing lock entry: {exact_entry}");
    }
    let wasmi_entry = lock
        .split("[[package]]")
        .find(|entry| entry.contains("name = \"wasmi\"") && entry.contains("version = \"1.1.0\""))
        .unwrap();
    assert!(wasmi_entry.contains("\"wasmparser 0.239.0\""));
}
