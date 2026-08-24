//! Closed identity of the validator and inert Core runtime selected by Vibe.
//!
//! Artifact profile fields are necessary but are not, by themselves, proof
//! that the booting kernel is using the same frontend and engine build.  This
//! module supplies the other half of that comparison.  All fields are private,
//! and the only identities returned to downstream crates are the three exact
//! identities constructed here.

use crate::{ProfileIdentity, PROFILE_1_LIMITS};

pub const WASMPARSER_0_255_0_VERSION: &str = "0.255.0";
pub const WIT_PARSER_0_255_0_VERSION: &str = "0.255.0";
pub const WASMI_1_1_0_VERSION: &str = "1.1.0";
pub const WASMI_1_1_0_CHECKSUM: &str =
    "2300d0f78cba12f14e29e8dd157ea64050c0a688179aefdb2050105805594a0c";
pub const WASMI_WASMPARSER_0_239_0_VERSION: &str = "0.239.0";
pub const WASMI_WASMPARSER_0_239_0_CHECKSUM: &str =
    "8c9d90bb93e764f6beabf1d02028c70a2156a6583e63ac4218dd07ef733368b0";

/// Cargo resolves the two direct wasmparser 0.255 users to one package
/// instance. Consequently both the Component and Core validator roles are
/// compiled with this exact union even though the Core manifest requests the
/// strict subset without `component-model`.
pub const RESOLVED_WASMPARSER_0_255_0_FEATURES: &str =
    "default-features=false;component-model,features,prefer-btree-collections,validate";
pub const COMPONENT_WASMPARSER_FEATURES: &str = RESOLVED_WASMPARSER_0_255_0_FEATURES;
pub const CORE_WASMPARSER_FEATURES: &str = RESOLVED_WASMPARSER_0_255_0_FEATURES;
pub const WIT_PARSER_FEATURES: &str = "default-features=false";
pub const WASMI_FEATURES: &str = "default-features=false;extra-checks,prefer-btree-collections";
pub const WASMI_WASMPARSER_FEATURES: &str =
    "default-features=false;features,prefer-btree-collections,validate";

/// One exact registry payload plus the Cargo feature selection with which it
/// participates in validation. Private fields prevent a caller from replacing
/// either the checksum or the feature set while retaining the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValidationCrateIdentity {
    name: &'static str,
    version: &'static str,
    checksum: &'static str,
    features: &'static str,
}

impl ValidationCrateIdentity {
    const fn new(
        name: &'static str,
        version: &'static str,
        checksum: &'static str,
        features: &'static str,
    ) -> Self {
        Self {
            name,
            version,
            checksum,
            features,
        }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn version(self) -> &'static str {
        self.version
    }

    pub const fn checksum(self) -> &'static str {
        self.checksum
    }

    pub const fn features(self) -> &'static str {
        self.features
    }
}

/// Closed wasmparser feature vectors used by the structural pass, strict
/// acceptance validator, and diagnostic-only fallback validator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WasmParserFeatureSelection {
    Empty,
    All,
    ComponentModel,
    ComponentModelAsync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentValidatorConfiguration {
    predecode_async: bool,
    structural: WasmParserFeatureSelection,
    strict: WasmParserFeatureSelection,
    diagnostic: WasmParserFeatureSelection,
}

impl ComponentValidatorConfiguration {
    const fn for_profile(profile: ProfileIdentity) -> Self {
        let async_enabled = profile.runtime_abi != ProfileIdentity::PROFILE_1_SYNC.runtime_abi;
        Self {
            predecode_async: async_enabled,
            structural: WasmParserFeatureSelection::All,
            strict: if async_enabled {
                WasmParserFeatureSelection::ComponentModelAsync
            } else {
                WasmParserFeatureSelection::ComponentModel
            },
            diagnostic: WasmParserFeatureSelection::All,
        }
    }

    pub const fn predecode_async(self) -> bool {
        self.predecode_async
    }

    pub const fn structural_features(self) -> WasmParserFeatureSelection {
        self.structural
    }

    pub const fn strict_features(self) -> WasmParserFeatureSelection {
        self.strict
    }

    pub const fn diagnostic_features(self) -> WasmParserFeatureSelection {
        self.diagnostic
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoreValidatorConfiguration {
    structural: WasmParserFeatureSelection,
    strict: WasmParserFeatureSelection,
    diagnostic: WasmParserFeatureSelection,
}

impl CoreValidatorConfiguration {
    const CURRENT: Self = Self {
        structural: WasmParserFeatureSelection::All,
        strict: WasmParserFeatureSelection::Empty,
        diagnostic: WasmParserFeatureSelection::All,
    };

    pub const fn structural_features(self) -> WasmParserFeatureSelection {
        self.structural
    }

    pub const fn strict_features(self) -> WasmParserFeatureSelection {
        self.strict
    }

    pub const fn diagnostic_features(self) -> WasmParserFeatureSelection {
        self.diagnostic
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WasmiCompilationMode {
    Eager,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WasmiEnforcedLimits {
    Strict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WasmiFuelCosts {
    Wasmi110Default,
}

/// Every explicit `wasmi::Config` setting used by [`vibeos-wasm-runtime`].
/// Settings which wasmi exposes only through its defaults are still bound by
/// the pinned wasmi version/checksum and the named default fuel schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WasmiRuntimeConfiguration {
    floats: bool,
    mutable_global: bool,
    sign_extension: bool,
    saturating_float_to_int: bool,
    multi_value: bool,
    multi_memory: bool,
    bulk_memory: bool,
    reference_types: bool,
    tail_call: bool,
    extended_const: bool,
    custom_page_sizes: bool,
    memory64: bool,
    wide_arithmetic: bool,
    simd_compiled: bool,
    relaxed_simd_compiled: bool,
    consume_fuel: bool,
    ignore_custom_sections: bool,
    compilation_mode: WasmiCompilationMode,
    max_recursion_depth: usize,
    min_stack_height: usize,
    max_stack_height: usize,
    max_cached_stacks: usize,
    enforced_limits: WasmiEnforcedLimits,
    fuel_costs: WasmiFuelCosts,
}

impl WasmiRuntimeConfiguration {
    const CURRENT: Self = Self {
        floats: false,
        mutable_global: false,
        sign_extension: false,
        saturating_float_to_int: false,
        multi_value: false,
        multi_memory: false,
        bulk_memory: false,
        reference_types: false,
        tail_call: false,
        extended_const: false,
        custom_page_sizes: false,
        memory64: false,
        wide_arithmetic: false,
        simd_compiled: false,
        relaxed_simd_compiled: false,
        consume_fuel: true,
        ignore_custom_sections: false,
        compilation_mode: WasmiCompilationMode::Eager,
        max_recursion_depth: PROFILE_1_LIMITS.max_call_depth as usize,
        min_stack_height: 4 * 1024,
        max_stack_height: 128 * 1024,
        max_cached_stacks: 0,
        enforced_limits: WasmiEnforcedLimits::Strict,
        fuel_costs: WasmiFuelCosts::Wasmi110Default,
    };

    pub const fn floats(self) -> bool {
        self.floats
    }

    pub const fn mutable_global(self) -> bool {
        self.mutable_global
    }

    pub const fn sign_extension(self) -> bool {
        self.sign_extension
    }

    pub const fn saturating_float_to_int(self) -> bool {
        self.saturating_float_to_int
    }

    pub const fn multi_value(self) -> bool {
        self.multi_value
    }

    pub const fn multi_memory(self) -> bool {
        self.multi_memory
    }

    pub const fn bulk_memory(self) -> bool {
        self.bulk_memory
    }

    pub const fn reference_types(self) -> bool {
        self.reference_types
    }

    pub const fn tail_call(self) -> bool {
        self.tail_call
    }

    pub const fn extended_const(self) -> bool {
        self.extended_const
    }

    pub const fn custom_page_sizes(self) -> bool {
        self.custom_page_sizes
    }

    pub const fn memory64(self) -> bool {
        self.memory64
    }

    pub const fn wide_arithmetic(self) -> bool {
        self.wide_arithmetic
    }

    pub const fn simd_compiled(self) -> bool {
        self.simd_compiled
    }

    pub const fn relaxed_simd_compiled(self) -> bool {
        self.relaxed_simd_compiled
    }

    pub const fn consume_fuel(self) -> bool {
        self.consume_fuel
    }

    pub const fn ignore_custom_sections(self) -> bool {
        self.ignore_custom_sections
    }

    pub const fn compilation_mode(self) -> WasmiCompilationMode {
        self.compilation_mode
    }

    pub const fn max_recursion_depth(self) -> usize {
        self.max_recursion_depth
    }

    pub const fn min_stack_height(self) -> usize {
        self.min_stack_height
    }

    pub const fn max_stack_height(self) -> usize {
        self.max_stack_height
    }

    pub const fn max_cached_stacks(self) -> usize {
        self.max_cached_stacks
    }

    pub const fn enforced_limits(self) -> WasmiEnforcedLimits {
        self.enforced_limits
    }

    pub const fn fuel_costs(self) -> WasmiFuelCosts {
        self.fuel_costs
    }
}

/// Complete current-boot validator/runtime identity. There is deliberately no
/// public constructor and no public field; callers may inspect or compare a
/// genuine identity but cannot manufacture an adjacent one.
///
/// ```compile_fail
/// use vibeos_component_format::ValidationEngineIdentity;
/// let _forged = ValidationEngineIdentity {};
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValidationEngineIdentity {
    profile: ProfileIdentity,
    component_wasmparser: ValidationCrateIdentity,
    core_wasmparser: ValidationCrateIdentity,
    wit_parser: ValidationCrateIdentity,
    wasmi: ValidationCrateIdentity,
    wasmi_wasmparser: ValidationCrateIdentity,
    component_validator: ComponentValidatorConfiguration,
    core_validator: CoreValidatorConfiguration,
    runtime: WasmiRuntimeConfiguration,
}

impl ValidationEngineIdentity {
    const fn for_profile(profile: ProfileIdentity) -> Self {
        Self {
            profile,
            component_wasmparser: ValidationCrateIdentity::new(
                "wasmparser",
                WASMPARSER_0_255_0_VERSION,
                crate::WASMPARSER_0_255_0_CHECKSUM,
                COMPONENT_WASMPARSER_FEATURES,
            ),
            core_wasmparser: ValidationCrateIdentity::new(
                "wasmparser",
                WASMPARSER_0_255_0_VERSION,
                crate::WASMPARSER_0_255_0_CHECKSUM,
                CORE_WASMPARSER_FEATURES,
            ),
            wit_parser: ValidationCrateIdentity::new(
                "wit-parser",
                WIT_PARSER_0_255_0_VERSION,
                crate::WIT_PARSER_0_255_0_CHECKSUM,
                WIT_PARSER_FEATURES,
            ),
            wasmi: ValidationCrateIdentity::new(
                "wasmi",
                WASMI_1_1_0_VERSION,
                WASMI_1_1_0_CHECKSUM,
                WASMI_FEATURES,
            ),
            wasmi_wasmparser: ValidationCrateIdentity::new(
                "wasmparser",
                WASMI_WASMPARSER_0_239_0_VERSION,
                WASMI_WASMPARSER_0_239_0_CHECKSUM,
                WASMI_WASMPARSER_FEATURES,
            ),
            component_validator: ComponentValidatorConfiguration::for_profile(profile),
            core_validator: CoreValidatorConfiguration::CURRENT,
            runtime: WasmiRuntimeConfiguration::CURRENT,
        }
    }

    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn component_wasmparser(self) -> ValidationCrateIdentity {
        self.component_wasmparser
    }

    pub const fn core_wasmparser(self) -> ValidationCrateIdentity {
        self.core_wasmparser
    }

    pub const fn wit_parser(self) -> ValidationCrateIdentity {
        self.wit_parser
    }

    pub const fn wasmi(self) -> ValidationCrateIdentity {
        self.wasmi
    }

    pub const fn wasmi_wasmparser(self) -> ValidationCrateIdentity {
        self.wasmi_wasmparser
    }

    pub const fn component_validator(self) -> ComponentValidatorConfiguration {
        self.component_validator
    }

    pub const fn core_validator(self) -> CoreValidatorConfiguration {
        self.core_validator
    }

    pub const fn runtime(self) -> WasmiRuntimeConfiguration {
        self.runtime
    }
}

const PROFILE_1_SYNC_ENGINE: ValidationEngineIdentity =
    ValidationEngineIdentity::for_profile(ProfileIdentity::PROFILE_1_SYNC);
const PROFILE_1_ASYNC_ENGINE: ValidationEngineIdentity =
    ValidationEngineIdentity::for_profile(ProfileIdentity::PROFILE_1_ASYNC);
const PROFILE_1_NATIVE_ASYNC_ENGINE: ValidationEngineIdentity =
    ValidationEngineIdentity::for_profile(ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE);

/// Resolve only a byte-for-byte supported profile to the engine identity that
/// is compiled into this boot. An artifact-provided adjacent profile returns
/// `None`; there is no fallback or caller-supplied engine descriptor.
pub fn current_validation_engine_identity(
    profile: ProfileIdentity,
) -> Option<&'static ValidationEngineIdentity> {
    if profile == ProfileIdentity::PROFILE_1_SYNC {
        Some(&PROFILE_1_SYNC_ENGINE)
    } else if profile == ProfileIdentity::PROFILE_1_ASYNC {
        Some(&PROFILE_1_ASYNC_ENGINE)
    } else if profile == ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE {
        Some(&PROFILE_1_NATIVE_ASYNC_ENGINE)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProfileStage;

    fn differs(expected: ValidationEngineIdentity, adjacent: ValidationEngineIdentity) {
        assert_ne!(expected, adjacent);
    }

    #[test]
    fn every_profile_identity_field_is_part_of_engine_identity() {
        let expected = PROFILE_1_SYNC_ENGINE;

        let mut adjacent = expected;
        adjacent.profile.artifact_abi += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.component_profile += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.core_profile += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.runtime_abi += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.core_revision = "adjacent-core";
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.component_revision = "adjacent-component";
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.canonical_abi_revision = "adjacent-canonical-abi";
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.wasm_tools_revision = "adjacent-wasm-tools";
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.wasi_revision = "adjacent-wasi";
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.canonical_features ^= 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.profile.stage = ProfileStage::ValidationOnly;
        differs(expected, adjacent);
    }

    #[test]
    fn every_frontend_payload_field_is_part_of_engine_identity() {
        let expected = PROFILE_1_SYNC_ENGINE;
        for slot in 0..5 {
            let mut adjacent = expected;
            let crate_identity = match slot {
                0 => &mut adjacent.component_wasmparser,
                1 => &mut adjacent.core_wasmparser,
                2 => &mut adjacent.wit_parser,
                3 => &mut adjacent.wasmi,
                _ => &mut adjacent.wasmi_wasmparser,
            };
            crate_identity.name = "adjacent-name";
            differs(expected, adjacent);

            let mut adjacent = expected;
            let crate_identity = match slot {
                0 => &mut adjacent.component_wasmparser,
                1 => &mut adjacent.core_wasmparser,
                2 => &mut adjacent.wit_parser,
                3 => &mut adjacent.wasmi,
                _ => &mut adjacent.wasmi_wasmparser,
            };
            crate_identity.version = "adjacent-version";
            differs(expected, adjacent);

            let mut adjacent = expected;
            let crate_identity = match slot {
                0 => &mut adjacent.component_wasmparser,
                1 => &mut adjacent.core_wasmparser,
                2 => &mut adjacent.wit_parser,
                3 => &mut adjacent.wasmi,
                _ => &mut adjacent.wasmi_wasmparser,
            };
            crate_identity.checksum = "adjacent-checksum";
            differs(expected, adjacent);

            let mut adjacent = expected;
            let crate_identity = match slot {
                0 => &mut adjacent.component_wasmparser,
                1 => &mut adjacent.core_wasmparser,
                2 => &mut adjacent.wit_parser,
                3 => &mut adjacent.wasmi,
                _ => &mut adjacent.wasmi_wasmparser,
            };
            crate_identity.features = "adjacent-features";
            differs(expected, adjacent);
        }
    }

    #[test]
    fn every_validator_selection_field_is_part_of_engine_identity() {
        let expected = PROFILE_1_SYNC_ENGINE;

        let mut adjacent = expected;
        adjacent.component_validator.predecode_async = true;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.component_validator.structural = WasmParserFeatureSelection::Empty;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.component_validator.strict = WasmParserFeatureSelection::All;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.component_validator.diagnostic = WasmParserFeatureSelection::Empty;
        differs(expected, adjacent);

        let mut adjacent = expected;
        adjacent.core_validator.structural = WasmParserFeatureSelection::Empty;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.core_validator.strict = WasmParserFeatureSelection::All;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.core_validator.diagnostic = WasmParserFeatureSelection::Empty;
        differs(expected, adjacent);
    }

    #[test]
    fn every_wasmi_configuration_field_is_part_of_engine_identity() {
        let expected = PROFILE_1_SYNC_ENGINE;

        macro_rules! flip {
            ($field:ident) => {{
                let mut adjacent = expected;
                adjacent.runtime.$field = !adjacent.runtime.$field;
                differs(expected, adjacent);
            }};
        }
        flip!(floats);
        flip!(mutable_global);
        flip!(sign_extension);
        flip!(saturating_float_to_int);
        flip!(multi_value);
        flip!(multi_memory);
        flip!(bulk_memory);
        flip!(reference_types);
        flip!(tail_call);
        flip!(extended_const);
        flip!(custom_page_sizes);
        flip!(memory64);
        flip!(wide_arithmetic);
        flip!(simd_compiled);
        flip!(relaxed_simd_compiled);
        flip!(consume_fuel);
        flip!(ignore_custom_sections);

        let mut adjacent = expected;
        adjacent.runtime.max_recursion_depth += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.runtime.min_stack_height += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.runtime.max_stack_height += 1;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.runtime.max_cached_stacks += 1;
        differs(expected, adjacent);

        // Single-variant enums make adjacent values impossible today. Their
        // equality still contributes to the identity and any future variant
        // forces the runtime's exhaustive mapping to be updated.
        assert_eq!(
            expected.runtime.compilation_mode,
            WasmiCompilationMode::Eager
        );
        assert_eq!(
            expected.runtime.enforced_limits,
            WasmiEnforcedLimits::Strict
        );
        assert_eq!(expected.runtime.fuel_costs, WasmiFuelCosts::Wasmi110Default);
    }

    #[test]
    fn adjacent_profile_never_resolves_to_a_current_engine() {
        let expected = ProfileIdentity::PROFILE_1_SYNC;

        let mut adjacent = expected;
        adjacent.artifact_abi += 1;
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.component_profile += 1;
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.core_profile += 1;
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.runtime_abi += 1;
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.core_revision = "adjacent-core";
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.component_revision = "adjacent-component";
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.canonical_abi_revision = "adjacent-canonical-abi";
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.wasm_tools_revision = "adjacent-wasm-tools";
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.wasi_revision = "adjacent-wasi";
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.canonical_features ^= 1;
        assert!(current_validation_engine_identity(adjacent).is_none());
        let mut adjacent = expected;
        adjacent.stage = ProfileStage::ValidationOnly;
        assert!(current_validation_engine_identity(adjacent).is_none());

        let sync = current_validation_engine_identity(expected).unwrap();
        let async_ = current_validation_engine_identity(ProfileIdentity::PROFILE_1_ASYNC).unwrap();
        let native = current_validation_engine_identity(
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        assert_eq!(sync.profile(), expected);
        assert_ne!(sync, async_);
        assert_ne!(async_, native);
    }
}
