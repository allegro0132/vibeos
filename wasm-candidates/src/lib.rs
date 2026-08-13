//! Reproducible C0 engine and Component frontend qualification spike.
//!
//! Nothing in this crate is an admission API.  It keeps both candidates
//! buildable against the target allocator model and records the decision that
//! the production wrapper implemented in C1 must enforce.

#![no_std]

extern crate alloc;

use vibeos_component_format::PROFILE_1_LIMITS;
use wasmparser::{Encoding, Parser, Payload, Validator, WasmFeatures};
use wit_parser::Resolve;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Candidate {
    Wasmi,
    DlrInPlace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateEvidence {
    pub candidate: Candidate,
    pub crate_name: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub no_std_alloc: bool,
    pub validates: bool,
    pub interprets: bool,
    pub outer_limits: bool,
    pub engine_structure_limits: bool,
    pub deterministic_fuel: bool,
    pub resumable_out_of_fuel: bool,
    pub audited_release: bool,
    pub safe_address_api: bool,
    pub allocator_oom_recoverable: bool,
    pub panic_abort_compatible: bool,
    pub riscv64_unknown_none_build: bool,
    pub source_lines: u32,
    pub unsafe_syntax_sites: u32,
}

pub const ENGINE_EVIDENCE: [CandidateEvidence; 2] = [
    CandidateEvidence {
        candidate: Candidate::Wasmi,
        crate_name: "wasmi",
        version: "1.1.0",
        license: "MIT OR Apache-2.0",
        no_std_alloc: true,
        validates: true,
        interprets: true,
        outer_limits: true,
        engine_structure_limits: true,
        deterministic_fuel: true,
        resumable_out_of_fuel: true,
        audited_release: true,
        safe_address_api: true,
        allocator_oom_recoverable: false,
        panic_abort_compatible: true,
        riscv64_unknown_none_build: true,
        source_lines: 36_591,
        unsafe_syntax_sites: 123,
    },
    CandidateEvidence {
        candidate: Candidate::DlrInPlace,
        crate_name: "dlr-wasm-interpreter",
        version: "0.2.0",
        license: "MIT OR Apache-2.0",
        no_std_alloc: true,
        validates: true,
        interprets: true,
        outer_limits: true,
        engine_structure_limits: false,
        deterministic_fuel: true,
        resumable_out_of_fuel: true,
        audited_release: false,
        safe_address_api: false,
        allocator_oom_recoverable: false,
        panic_abort_compatible: true,
        riscv64_unknown_none_build: true,
        source_lines: 22_880,
        unsafe_syntax_sites: 442,
    },
];

pub const SELECTED_CORE_ENGINE: Candidate = Candidate::Wasmi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontendDecision {
    pub binary_frontend: &'static str,
    pub wit_frontend: &'static str,
    pub component_revision: &'static str,
    pub no_std_alloc: bool,
    pub parser_is_runtime: bool,
    pub policy_is_in_tree: bool,
}

pub const FRONTEND_DECISION: FrontendDecision = FrontendDecision {
    binary_frontend: "wasmparser=0.255.0",
    wit_frontend: "wit-parser=0.255.0",
    component_revision: "component-model-0.255.0-sync",
    no_std_alloc: true,
    parser_is_runtime: false,
    policy_is_in_tree: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatDecision {
    IntegerOnly,
}

pub const FLOAT_DECISION: FloatDecision = FloatDecision::IntegerOnly;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontendError {
    TooLarge,
    NotComponent,
    InvalidComponent,
    Limit,
    InvalidWit,
    MissingWorld,
}

/// Shared pre-decode boundary used for both C0 candidate spikes.
pub fn bounded_core_candidate(bytes: &[u8]) -> Result<&[u8], FrontendError> {
    if bytes.len() > PROFILE_1_LIMITS.max_core_module_bytes {
        return Err(FrontendError::TooLarge);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComponentSummary {
    pub embedded_modules: u32,
    pub component_instances: u32,
    pub aliases: u32,
    pub canonical_functions: u32,
    pub imports: u32,
    pub exports: u32,
}

fn profile_component_features() -> WasmFeatures {
    let mut features = WasmFeatures::empty();
    features.set(WasmFeatures::COMPONENT_MODEL, true);
    features
}

fn checked_add(value: &mut u32, amount: u32, limit: u32) -> Result<(), FrontendError> {
    let next = value.checked_add(amount).ok_or(FrontendError::Limit)?;
    if next > limit {
        return Err(FrontendError::Limit);
    }
    *value = next;
    Ok(())
}

/// Decode and validate one Profile-1 component without instantiating it.
pub fn inspect_component(bytes: &[u8]) -> Result<ComponentSummary, FrontendError> {
    if bytes.len() > PROFILE_1_LIMITS.max_component_bytes {
        return Err(FrontendError::TooLarge);
    }
    let features = profile_component_features();
    Validator::new_with_features(features)
        .validate_all(bytes)
        .map_err(|_| FrontendError::InvalidComponent)?;

    let mut summary = ComponentSummary::default();
    let mut saw_component = false;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|_| FrontendError::InvalidComponent)? {
            Payload::Version { encoding, .. } if !saw_component => {
                if encoding != Encoding::Component {
                    return Err(FrontendError::NotComponent);
                }
                saw_component = true;
            }
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                if unchecked_range.len() > PROFILE_1_LIMITS.max_core_module_bytes {
                    return Err(FrontendError::Limit);
                }
                checked_add(
                    &mut summary.embedded_modules,
                    1,
                    PROFILE_1_LIMITS.max_embedded_modules,
                )?;
            }
            Payload::ComponentSection { .. } => return Err(FrontendError::Limit),
            Payload::ComponentInstanceSection(reader) => checked_add(
                &mut summary.component_instances,
                reader.count(),
                PROFILE_1_LIMITS.max_component_instances,
            )?,
            Payload::ComponentAliasSection(reader) => checked_add(
                &mut summary.aliases,
                reader.count(),
                PROFILE_1_LIMITS.max_aliases,
            )?,
            Payload::ComponentCanonicalSection(reader) => checked_add(
                &mut summary.canonical_functions,
                reader.count(),
                PROFILE_1_LIMITS.max_canonical_functions,
            )?,
            Payload::ComponentImportSection(reader) => checked_add(
                &mut summary.imports,
                reader.count(),
                PROFILE_1_LIMITS.max_imports,
            )?,
            Payload::ComponentExportSection(reader) => checked_add(
                &mut summary.exports,
                reader.count(),
                PROFILE_1_LIMITS.max_exports,
            )?,
            _ => {}
        }
    }
    saw_component
        .then_some(summary)
        .ok_or(FrontendError::NotComponent)
}

/// Parse and resolve an exact WIT world from in-memory, bounded source.
pub fn validate_wit_world(source: &str, world: &str) -> Result<(), FrontendError> {
    if source.len() > PROFILE_1_LIMITS.max_component_bytes || world.len() > 128 {
        return Err(FrontendError::TooLarge);
    }
    let mut resolve = Resolve::default();
    let package = resolve
        .push_source("profile.wit", source)
        .map_err(|_| FrontendError::InvalidWit)?;
    resolve
        .select_world(&[package], Some(world))
        .map_err(|_| FrontendError::MissingWorld)?;
    Ok(())
}

/// Stable, allocation-shape baselines. Timing and throughput are emitted by
/// `c0_baseline`; this type intentionally contains no invented threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocationShape {
    pub wasmi_engine_bytes: usize,
    pub wasmi_store_bytes: usize,
    pub dlr_store_bytes: usize,
    pub component_validator_bytes: usize,
}

pub fn allocation_shape() -> AllocationShape {
    AllocationShape {
        wasmi_engine_bytes: core::mem::size_of::<wasmi::Engine>(),
        wasmi_store_bytes: core::mem::size_of::<wasmi::Store<()>>(),
        dlr_store_bytes: core::mem::size_of::<dlr_wasm_interpreter::Store<()>>(),
        component_validator_bytes: core::mem::size_of::<wasmparser::Validator>(),
    }
}
