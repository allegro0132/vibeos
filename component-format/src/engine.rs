//! Closed identity of the validator and inert Core runtime selected by Vibe.
//!
//! Artifact profile fields are necessary but are not, by themselves, proof
//! that the booting kernel is using the same frontend and engine build.  This
//! module supplies the other half of that comparison.  All fields are private,
//! and the only identities returned to downstream crates are exact identities
//! constructed here.

use crate::{
    FloatNaNPolicy, ProfileIdentity, ScalarFloatType, PROFILE_1_LIMITS,
    PROFILE_2_SYNC_FLOAT_NAN_POLICY, PROFILE_2_SYNC_FLOAT_SCALAR_TYPES,
};

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

/// Explicit Component validation mode. It is selected by each closed engine
/// contract instead of being inferred from an unrelated ABI number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ComponentValidationMode {
    Sync,
    Async,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ComponentValidatorConfiguration {
    mode: ComponentValidationMode,
    structural: WasmParserFeatureSelection,
    strict: WasmParserFeatureSelection,
    diagnostic: WasmParserFeatureSelection,
}

impl ComponentValidatorConfiguration {
    const fn for_mode(mode: ComponentValidationMode) -> Self {
        Self {
            mode,
            structural: WasmParserFeatureSelection::All,
            strict: match mode {
                ComponentValidationMode::Sync => WasmParserFeatureSelection::ComponentModel,
                ComponentValidationMode::Async => WasmParserFeatureSelection::ComponentModelAsync,
            },
            diagnostic: WasmParserFeatureSelection::All,
        }
    }

    pub const fn mode(self) -> ComponentValidationMode {
        self.mode
    }

    pub const fn predecode_async(self) -> bool {
        matches!(self.mode, ComponentValidationMode::Async)
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
pub enum CoreNumericProfile {
    Profile1IntegerOnly,
    Profile2ScalarF32F64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoreValidatorConfiguration {
    structural: WasmParserFeatureSelection,
    strict: WasmParserFeatureSelection,
    diagnostic: WasmParserFeatureSelection,
    numeric_profile: CoreNumericProfile,
    nan_policy: Option<FloatNaNPolicy>,
}

impl CoreValidatorConfiguration {
    const PROFILE_1: Self = Self {
        structural: WasmParserFeatureSelection::All,
        strict: WasmParserFeatureSelection::Empty,
        diagnostic: WasmParserFeatureSelection::All,
        numeric_profile: CoreNumericProfile::Profile1IntegerOnly,
        nan_policy: None,
    };

    const PROFILE_2_SYNC_FLOAT: Self = Self {
        structural: WasmParserFeatureSelection::All,
        // Scalar f32/f64 are part of the Core baseline rather than a
        // wasmparser proposal bit. The separate numeric profile below is the
        // Vibe inspection contract that distinguishes this from Profile 1.
        strict: WasmParserFeatureSelection::Empty,
        diagnostic: WasmParserFeatureSelection::All,
        numeric_profile: CoreNumericProfile::Profile2ScalarF32F64,
        nan_policy: Some(PROFILE_2_SYNC_FLOAT_NAN_POLICY),
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

    pub const fn numeric_profile(self) -> CoreNumericProfile {
        self.numeric_profile
    }

    pub const fn scalar_float_types(self) -> &'static [ScalarFloatType] {
        match self.numeric_profile {
            CoreNumericProfile::Profile1IntegerOnly => &[],
            CoreNumericProfile::Profile2ScalarF32F64 => &PROFILE_2_SYNC_FLOAT_SCALAR_TYPES,
        }
    }

    pub const fn nan_policy(self) -> Option<FloatNaNPolicy> {
        self.nan_policy
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

/// Every explicit target `wasmi::Config` setting selected by Vibe. A current
/// [`ValidationEngineIdentity`] additionally binds these settings to exact
/// package bytes. A future validation contract may use this setting vector
/// without claiming a package, source, or checksum identity.
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
    const PROFILE_1: Self = Self {
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

    /// Future F2 implementation target. F1 records this exact setting vector,
    /// including `Wasmi110Default` fuel costs, but does not expose it as a
    /// current runtime binding. A candidate with a different schedule requires
    /// a new reviewed contract; it cannot silently reinterpret code 5.
    const PROFILE_2_SYNC_FLOAT: Self = Self {
        floats: true,
        ..Self::PROFILE_1
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
    const fn for_contract(
        profile: ProfileIdentity,
        component_mode: ComponentValidationMode,
        core_validator: CoreValidatorConfiguration,
        runtime: WasmiRuntimeConfiguration,
    ) -> Self {
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
            component_validator: ComponentValidatorConfiguration::for_mode(component_mode),
            core_validator,
            runtime,
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

const PROFILE_1_SYNC_ENGINE: ValidationEngineIdentity = ValidationEngineIdentity::for_contract(
    ProfileIdentity::PROFILE_1_SYNC,
    ComponentValidationMode::Sync,
    CoreValidatorConfiguration::PROFILE_1,
    WasmiRuntimeConfiguration::PROFILE_1,
);
const PROFILE_1_ASYNC_ENGINE: ValidationEngineIdentity = ValidationEngineIdentity::for_contract(
    ProfileIdentity::PROFILE_1_ASYNC,
    ComponentValidationMode::Async,
    CoreValidatorConfiguration::PROFILE_1,
    WasmiRuntimeConfiguration::PROFILE_1,
);
const PROFILE_1_NATIVE_ASYNC_ENGINE: ValidationEngineIdentity =
    ValidationEngineIdentity::for_contract(
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        ComponentValidationMode::Async,
        CoreValidatorConfiguration::PROFILE_1,
        WasmiRuntimeConfiguration::PROFILE_1,
    );
/// Sealed C8.8-F1 contract metadata. It deliberately contains no frontend or
/// runtime crate/package/source/checksum identity: F2 must review and bind its
/// software-float candidate independently, without rewriting code 5's format
/// contract.
///
/// ```compile_fail
/// use vibeos_component_format::Profile2SyncFloatValidationContract;
/// let _forged = Profile2SyncFloatValidationContract {};
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::profile_2_sync_float_validation_contract;
/// let contract = profile_2_sync_float_validation_contract();
/// let _package_identity = contract.wasmi();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Profile2SyncFloatValidationContract {
    profile: ProfileIdentity,
    component_validator: ComponentValidatorConfiguration,
    core_validator: CoreValidatorConfiguration,
    target_wasmi_configuration: WasmiRuntimeConfiguration,
    nan_policy: FloatNaNPolicy,
    runtime_ready: bool,
}

impl Profile2SyncFloatValidationContract {
    pub const fn profile(self) -> ProfileIdentity {
        self.profile
    }

    pub const fn component_validator(self) -> ComponentValidatorConfiguration {
        self.component_validator
    }

    pub const fn core_validator(self) -> CoreValidatorConfiguration {
        self.core_validator
    }

    pub const fn target_wasmi_configuration(self) -> WasmiRuntimeConfiguration {
        self.target_wasmi_configuration
    }

    pub const fn nan_policy(self) -> FloatNaNPolicy {
        self.nan_policy
    }

    pub const fn runtime_ready(self) -> bool {
        self.runtime_ready
    }
}

const PROFILE_2_SYNC_FLOAT_VALIDATION_CONTRACT: Profile2SyncFloatValidationContract =
    Profile2SyncFloatValidationContract {
        profile: ProfileIdentity::PROFILE_2_SYNC_FLOAT,
        component_validator: ComponentValidatorConfiguration::for_mode(
            ComponentValidationMode::Sync,
        ),
        core_validator: CoreValidatorConfiguration::PROFILE_2_SYNC_FLOAT,
        target_wasmi_configuration: WasmiRuntimeConfiguration::PROFILE_2_SYNC_FLOAT,
        nan_policy: PROFILE_2_SYNC_FLOAT_NAN_POLICY,
        runtime_ready: false,
    };

/// Exact future validator/wasmi setting vector frozen by C8.8-F1. This is
/// contract metadata, not a current validation-engine or execution binding;
/// [`current_validation_engine_identity`] intentionally returns `None` for its
/// profile. Code 5 remains validation-only permanently; a future executable
/// float profile must receive a new profile code and ABI identity.
pub const fn profile_2_sync_float_validation_contract(
) -> &'static Profile2SyncFloatValidationContract {
    &PROFILE_2_SYNC_FLOAT_VALIDATION_CONTRACT
}

/// Resolve only a byte-for-byte supported profile to the engine identity that
/// is compiled into this boot. An artifact-provided adjacent profile returns
/// `None`; there is no fallback or caller-supplied engine descriptor.
pub fn current_validation_engine_identity(
    profile: ProfileIdentity,
) -> Option<&'static ValidationEngineIdentity> {
    // Change-control invariant: code 5 is format/contract metadata only and is
    // never promoted in place to a current engine binding.
    if profile == ProfileIdentity::PROFILE_2_SYNC_FLOAT {
        None
    } else if profile == ProfileIdentity::PROFILE_1_SYNC {
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
        adjacent.component_validator.mode = ComponentValidationMode::Async;
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
        let mut adjacent = expected;
        adjacent.core_validator.numeric_profile = CoreNumericProfile::Profile2ScalarF32F64;
        differs(expected, adjacent);
        let mut adjacent = expected;
        adjacent.core_validator.nan_policy = Some(PROFILE_2_SYNC_FLOAT_NAN_POLICY);
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

        assert!(
            current_validation_engine_identity(ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED)
                .is_none()
        );
        assert!(
            current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none()
        );

        let sync = current_validation_engine_identity(expected).unwrap();
        let async_ = current_validation_engine_identity(ProfileIdentity::PROFILE_1_ASYNC).unwrap();
        let native = current_validation_engine_identity(
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        assert_eq!(sync.profile(), expected);
        assert_ne!(sync, async_);
        assert_ne!(async_, native);

        let float = profile_2_sync_float_validation_contract();
        // Exhaustive destructuring is a compile-time schema lock: adding any
        // package/source/checksum field requires this contract audit to change.
        let Profile2SyncFloatValidationContract {
            profile,
            component_validator,
            core_validator,
            target_wasmi_configuration,
            nan_policy,
            runtime_ready,
        } = *float;
        assert_eq!(profile, ProfileIdentity::PROFILE_2_SYNC_FLOAT);
        assert_eq!(component_validator, float.component_validator());
        assert_eq!(core_validator, float.core_validator());
        assert_eq!(
            target_wasmi_configuration,
            float.target_wasmi_configuration()
        );
        assert_eq!(nan_policy, PROFILE_2_SYNC_FLOAT_NAN_POLICY);
        assert!(!runtime_ready);
        assert_eq!(float.profile(), ProfileIdentity::PROFILE_2_SYNC_FLOAT);
        assert!(!float.runtime_ready());
        assert!(!float.component_validator().predecode_async());
        assert_eq!(
            float.component_validator().mode(),
            ComponentValidationMode::Sync
        );
        assert_eq!(
            float.core_validator().numeric_profile(),
            CoreNumericProfile::Profile2ScalarF32F64
        );
        assert_eq!(
            float.core_validator().nan_policy(),
            Some(PROFILE_2_SYNC_FLOAT_NAN_POLICY)
        );
        assert_eq!(float.nan_policy(), PROFILE_2_SYNC_FLOAT_NAN_POLICY);
        assert!(float.target_wasmi_configuration().floats());
    }
}
