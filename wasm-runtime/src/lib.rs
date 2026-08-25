//! Bounded, portable Core WebAssembly execution for Vibe Component Profile 1.
//!
//! Untrusted bytes are counted before either `wasmparser::Validator` or wasmi
//! may reserve storage. Imports are denied by default and can only be linked
//! through an exact, typed allowlist. Calls are metered in resumable quanta
//! while retaining a separate, monotonic total-fuel account.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::{
    cmp::min,
    fmt,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use vibeos_component_format::{
    current_validation_engine_identity, LimitKind, ProfileIdentity, ProfileLimits, TrapCode,
    ValidationEngineIdentity, WasmParserFeatureSelection, WasmiCompilationMode,
    WasmiEnforcedLimits, WasmiFuelCosts, PROFILE_1_LIMITS,
};
use wasmi::{
    errors::HostError, CompilationMode, Config, EnforcedLimits, Engine, Error as WasmiError,
    ExternType, Func, FuncType, Instance, Linker, Memory, Module, ResumableCall,
    ResumableCallHostTrap, ResumableCallOutOfFuel, Store, StoreLimits, StoreLimitsBuilder, Val,
    ValType,
};
use wasmparser::{Encoding, Operator, Parser, Payload, TypeRef, Validator, WasmFeatures};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionDetail {
    Malformed,
    UnsupportedFeature,
    ComponentInsteadOfCore,
    ImportRequiresLinker,
    MissingMaximum,
    Limit(LimitKind),
    AllocationReservation,
    HostImportMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionError {
    pub trap: TrapCode,
    pub detail: AdmissionDetail,
}

impl AdmissionError {
    const fn validation(detail: AdmissionDetail) -> Self {
        Self {
            trap: TrapCode::Validation,
            detail,
        }
    }

    const fn unsupported() -> Self {
        Self {
            trap: TrapCode::UnsupportedFeature,
            detail: AdmissionDetail::UnsupportedFeature,
        }
    }

    const fn limit(kind: LimitKind) -> Self {
        Self {
            trap: TrapCode::LimitExceeded,
            detail: AdmissionDetail::Limit(kind),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreSummary {
    pub bytes: u32,
    pub types: u32,
    pub functions: u32,
    pub max_params: u32,
    pub max_results: u32,
    pub imports: u32,
    pub exports: u32,
    pub globals: u32,
    pub locals: u32,
    pub memories: u32,
    pub tables: u32,
    pub data_segments: u32,
    pub element_segments: u32,
    pub custom_sections: u32,
    pub custom_section_bytes: u32,
    pub max_control_depth: u32,
}

fn checked_add(
    value: &mut u32,
    amount: u32,
    maximum: u32,
    kind: LimitKind,
) -> Result<(), AdmissionError> {
    let next = value
        .checked_add(amount)
        .ok_or_else(|| AdmissionError::limit(kind))?;
    if next > maximum {
        return Err(AdmissionError::limit(kind));
    }
    *value = next;
    Ok(())
}

fn check_memory(ty: wasmparser::MemoryType, limits: &ProfileLimits) -> Result<(), AdmissionError> {
    if ty.memory64 || ty.shared || ty.page_size_log2.is_some() {
        return Err(AdmissionError::unsupported());
    }
    let maximum = ty
        .maximum
        .ok_or_else(|| AdmissionError::validation(AdmissionDetail::MissingMaximum))?;
    if ty.initial > u64::from(limits.max_initial_memory_pages) {
        return Err(AdmissionError::limit(LimitKind::InitialMemoryPages));
    }
    if maximum > u64::from(limits.max_memory_pages) || ty.initial > maximum {
        return Err(AdmissionError::limit(LimitKind::MemoryPages));
    }
    Ok(())
}

fn check_table(ty: wasmparser::TableType, limits: &ProfileLimits) -> Result<(), AdmissionError> {
    if ty.table64 || ty.shared {
        return Err(AdmissionError::unsupported());
    }
    let maximum = ty
        .maximum
        .ok_or_else(|| AdmissionError::validation(AdmissionDetail::MissingMaximum))?;
    if ty.initial > u64::from(limits.max_table_elements)
        || maximum > u64::from(limits.max_table_elements)
        || ty.initial > maximum
    {
        return Err(AdmissionError::limit(LimitKind::TableElements));
    }
    Ok(())
}

fn parser_features(selection: WasmParserFeatureSelection) -> WasmFeatures {
    match selection {
        WasmParserFeatureSelection::Empty => WasmFeatures::empty(),
        WasmParserFeatureSelection::All => WasmFeatures::all(),
        WasmParserFeatureSelection::ComponentModel => {
            let mut features = WasmFeatures::empty();
            features.set(WasmFeatures::COMPONENT_MODEL, true);
            features
        }
        WasmParserFeatureSelection::ComponentModelAsync => {
            let mut features = WasmFeatures::empty();
            features.set(WasmFeatures::COMPONENT_MODEL, true);
            features.set(WasmFeatures::CM_ASYNC, true);
            features
        }
    }
}

mod current_engine_private {
    pub struct Seal;
}

/// Unforgeable proof that a profile was resolved against the validator and
/// runtime identity compiled into this boot. The constructor accepts no
/// caller-supplied engine descriptor and the proof is intentionally not
/// cloneable.
///
/// ```compile_fail
/// use vibeos_wasm_runtime::CurrentCoreValidationEngine;
/// let _forged = CurrentCoreValidationEngine {};
/// ```
///
/// ```compile_fail
/// use vibeos_wasm_runtime::CurrentCoreValidationEngine;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CurrentCoreValidationEngine>();
/// ```
pub struct CurrentCoreValidationEngine {
    identity: &'static ValidationEngineIdentity,
    _sealed: current_engine_private::Seal,
}

impl CurrentCoreValidationEngine {
    pub const fn identity(&self) -> &'static ValidationEngineIdentity {
        self.identity
    }
}

/// Resolve one exact profile to the current Core validator/runtime. Adjacent
/// profile fields fail closed instead of selecting a default engine.
pub fn current_core_validation_engine(
    profile: ProfileIdentity,
) -> Option<CurrentCoreValidationEngine> {
    let identity = current_validation_engine_identity(profile)?;
    Some(CurrentCoreValidationEngine {
        identity,
        _sealed: current_engine_private::Seal,
    })
}

fn read_u32_leb(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<u32, AdmissionError> {
    let mut value = 0_u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .filter(|_| *cursor < end)
            .ok_or_else(|| AdmissionError::validation(AdmissionDetail::Malformed))?;
        *cursor += 1;
        if shift == 28 && byte & 0xf0 != 0 {
            return Err(AdmissionError::validation(AdmissionDetail::Malformed));
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(AdmissionError::validation(AdmissionDetail::Malformed))
}

/// Predecodes the deliberately tiny Profile-1 type grammar. This is separate
/// from `TypeSectionReader`: parsing an explicit GC rec-group would allocate
/// its declared inner vector before the disabled-feature validator rejects it.
fn inspect_function_types(
    bytes: &[u8],
    range: core::ops::Range<usize>,
    count: u32,
    limits: &ProfileLimits,
    summary: &mut CoreSummary,
) -> Result<(), AdmissionError> {
    let mut cursor = range.start;
    let encoded_count = read_u32_leb(bytes, &mut cursor, range.end)?;
    if encoded_count != count {
        return Err(AdmissionError::validation(AdmissionDetail::Malformed));
    }
    for _ in 0..count {
        let form = *bytes
            .get(cursor)
            .filter(|_| cursor < range.end)
            .ok_or_else(|| AdmissionError::validation(AdmissionDetail::Malformed))?;
        cursor += 1;
        if form != 0x60 {
            return Err(AdmissionError::unsupported());
        }
        for (position, maximum, kind) in [
            (0_u8, limits.max_params_per_function, LimitKind::Parameters),
            (1_u8, limits.max_results_per_function, LimitKind::Results),
        ] {
            let arity = read_u32_leb(bytes, &mut cursor, range.end)?;
            if arity > maximum {
                return Err(AdmissionError::limit(kind));
            }
            if position == 0 {
                summary.max_params = summary.max_params.max(arity);
            } else {
                summary.max_results = summary.max_results.max(arity);
            }
            for _ in 0..arity {
                match bytes.get(cursor).filter(|_| cursor < range.end) {
                    Some(0x7f | 0x7e) => cursor += 1,
                    Some(_) => return Err(AdmissionError::unsupported()),
                    None => {
                        return Err(AdmissionError::validation(AdmissionDetail::Malformed));
                    }
                }
            }
        }
    }
    if cursor != range.end {
        return Err(AdmissionError::validation(AdmissionDetail::Malformed));
    }
    Ok(())
}

/// Performs an allocation-light structural pass before invoking a validating
/// frontend.  Section counts and declared storage are rejected at the exact
/// Profile-1 boundary.
pub fn inspect_core(bytes: &[u8]) -> Result<CoreSummary, AdmissionError> {
    inspect_core_with_limits(bytes, &PROFILE_1_LIMITS)
}

pub fn inspect_core_with_limits(
    bytes: &[u8],
    limits: &ProfileLimits,
) -> Result<CoreSummary, AdmissionError> {
    let engine = current_core_validation_engine(ProfileIdentity::PROFILE_1_SYNC)
        .ok_or_else(AdmissionError::unsupported)?;
    inspect_core_with_limits_and_current_engine(bytes, limits, &engine)
}

/// Validate Core bytes under an opaque current-engine proof. This is the
/// admission entrypoint used when durable bytes are freshly revalidated.
pub fn inspect_core_with_current_engine(
    bytes: &[u8],
    engine: &CurrentCoreValidationEngine,
) -> Result<CoreSummary, AdmissionError> {
    inspect_core_with_limits_and_current_engine(bytes, &PROFILE_1_LIMITS, engine)
}

fn inspect_core_with_limits_and_current_engine(
    bytes: &[u8],
    limits: &ProfileLimits,
    engine: &CurrentCoreValidationEngine,
) -> Result<CoreSummary, AdmissionError> {
    if bytes.len() > limits.max_core_module_bytes || bytes.len() > u32::MAX as usize {
        return Err(AdmissionError::limit(LimitKind::CoreModuleBytes));
    }
    let mut summary = CoreSummary {
        bytes: bytes.len() as u32,
        ..CoreSummary::default()
    };
    let mut saw_core = false;
    let validator = engine.identity.core_validator();
    let mut parser = Parser::new(0);
    parser.set_features(parser_features(validator.structural_features()));
    for payload in parser.parse_all(bytes) {
        let payload =
            payload.map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(AdmissionError::validation(
                        AdmissionDetail::ComponentInsteadOfCore,
                    ));
                }
                saw_core = true;
            }
            Payload::TypeSection(reader) => {
                checked_add(
                    &mut summary.types,
                    reader.count(),
                    limits.max_types,
                    LimitKind::Types,
                )?;
                inspect_function_types(
                    bytes,
                    reader.range(),
                    reader.count(),
                    limits,
                    &mut summary,
                )?;
            }
            Payload::ImportSection(reader) => {
                checked_add(
                    &mut summary.imports,
                    reader.count(),
                    limits.max_imports,
                    LimitKind::Imports,
                )?;
                for import in reader.into_imports() {
                    let import = import
                        .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
                    match import.ty {
                        TypeRef::Func(_) => checked_add(
                            &mut summary.functions,
                            1,
                            limits.max_functions,
                            LimitKind::Functions,
                        )?,
                        TypeRef::Memory(ty) => {
                            checked_add(
                                &mut summary.memories,
                                1,
                                limits.max_memories,
                                LimitKind::Memories,
                            )?;
                            check_memory(ty, limits)?;
                        }
                        TypeRef::Table(ty) => {
                            checked_add(
                                &mut summary.tables,
                                1,
                                limits.max_tables,
                                LimitKind::Tables,
                            )?;
                            check_table(ty, limits)?;
                        }
                        TypeRef::Global(_) => checked_add(
                            &mut summary.globals,
                            1,
                            limits.max_globals,
                            LimitKind::Globals,
                        )?,
                        TypeRef::Tag(_) | TypeRef::FuncExact(_) => {
                            return Err(AdmissionError::unsupported())
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => checked_add(
                &mut summary.functions,
                reader.count(),
                limits.max_functions,
                LimitKind::Functions,
            )?,
            Payload::TableSection(reader) => {
                checked_add(
                    &mut summary.tables,
                    reader.count(),
                    limits.max_tables,
                    LimitKind::Tables,
                )?;
                for table in reader {
                    check_table(
                        table
                            .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?
                            .ty,
                        limits,
                    )?;
                }
            }
            Payload::MemorySection(reader) => {
                checked_add(
                    &mut summary.memories,
                    reader.count(),
                    limits.max_memories,
                    LimitKind::Memories,
                )?;
                for memory in reader {
                    check_memory(
                        memory
                            .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?,
                        limits,
                    )?;
                }
            }
            Payload::TagSection(_) => return Err(AdmissionError::unsupported()),
            Payload::GlobalSection(reader) => {
                checked_add(
                    &mut summary.globals,
                    reader.count(),
                    limits.max_globals,
                    LimitKind::Globals,
                )?;
                for global in reader {
                    let global = global
                        .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
                    if global.ty.mutable || global.ty.shared {
                        return Err(AdmissionError::unsupported());
                    }
                }
            }
            Payload::ExportSection(reader) => checked_add(
                &mut summary.exports,
                reader.count(),
                limits.max_exports,
                LimitKind::Exports,
            )?,
            Payload::ElementSection(reader) => checked_add(
                &mut summary.element_segments,
                reader.count(),
                limits.max_element_segments,
                LimitKind::ElementSegments,
            )?,
            Payload::DataCountSection { count, .. } => {
                if count > limits.max_data_segments {
                    return Err(AdmissionError::limit(LimitKind::DataSegments));
                }
            }
            Payload::DataSection(reader) => checked_add(
                &mut summary.data_segments,
                reader.count(),
                limits.max_data_segments,
                LimitKind::DataSegments,
            )?,
            Payload::CodeSectionStart { count, .. } => {
                if count > limits.max_functions {
                    return Err(AdmissionError::limit(LimitKind::Functions));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut locals = 0_u32;
                let reader = body
                    .get_locals_reader()
                    .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
                for local in reader {
                    let (count, _) = local
                        .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
                    checked_add(
                        &mut locals,
                        count,
                        limits.max_locals_per_function,
                        LimitKind::Locals,
                    )?;
                }
                summary.locals = summary.locals.saturating_add(locals);

                let mut depth = 0_u32;
                let operators = body
                    .get_operators_reader()
                    .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
                for operator in operators {
                    match operator
                        .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?
                    {
                        Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                            depth = depth
                                .checked_add(1)
                                .ok_or_else(|| AdmissionError::limit(LimitKind::Functions))?;
                            if depth > limits.max_core_nesting {
                                return Err(AdmissionError::limit(LimitKind::CoreNesting));
                            }
                            summary.max_control_depth = summary.max_control_depth.max(depth);
                        }
                        Operator::End => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
            }
            Payload::CustomSection(reader) => {
                checked_add(
                    &mut summary.custom_sections,
                    1,
                    limits.max_custom_sections,
                    LimitKind::CustomSections,
                )?;
                let amount = u32::try_from(reader.data().len())
                    .map_err(|_| AdmissionError::limit(LimitKind::CustomSectionBytes))?;
                checked_add(
                    &mut summary.custom_section_bytes,
                    amount,
                    limits.max_custom_section_bytes as u32,
                    LimitKind::CustomSectionBytes,
                )?;
            }
            Payload::UnknownSection { .. } => return Err(AdmissionError::unsupported()),
            Payload::StartSection { .. } => return Err(AdmissionError::unsupported()),
            Payload::End(_) => {}
            _ => return Err(AdmissionError::unsupported()),
        }
    }
    if !saw_core {
        return Err(AdmissionError::validation(AdmissionDetail::Malformed));
    }

    if Validator::new_with_features(parser_features(validator.strict_features()))
        .validate_all(bytes)
        .is_err()
    {
        let broadly_valid =
            Validator::new_with_features(parser_features(validator.diagnostic_features()))
                .validate_all(bytes)
                .is_ok();
        return Err(if broadly_valid {
            AdmissionError::unsupported()
        } else {
            AdmissionError::validation(AdmissionDetail::Malformed)
        });
    }
    Ok(summary)
}

fn build_engine(identity: &ValidationEngineIdentity) -> Engine {
    let runtime = identity.runtime();
    let mut config = Config::default();
    config
        .floats(runtime.floats())
        .wasm_mutable_global(runtime.mutable_global())
        .wasm_sign_extension(runtime.sign_extension())
        .wasm_saturating_float_to_int(runtime.saturating_float_to_int())
        .wasm_multi_value(runtime.multi_value())
        .wasm_multi_memory(runtime.multi_memory())
        .wasm_bulk_memory(runtime.bulk_memory())
        .wasm_reference_types(runtime.reference_types())
        .wasm_tail_call(runtime.tail_call())
        .wasm_extended_const(runtime.extended_const())
        .wasm_custom_page_sizes(runtime.custom_page_sizes())
        .wasm_memory64(runtime.memory64())
        .wasm_wide_arithmetic(runtime.wide_arithmetic())
        .consume_fuel(runtime.consume_fuel())
        .ignore_custom_sections(runtime.ignore_custom_sections())
        .compilation_mode(match runtime.compilation_mode() {
            WasmiCompilationMode::Eager => CompilationMode::Eager,
        })
        .set_max_recursion_depth(runtime.max_recursion_depth())
        .set_min_stack_height(runtime.min_stack_height())
        .set_max_stack_height(runtime.max_stack_height())
        .set_max_cached_stacks(runtime.max_cached_stacks())
        .enforced_limits(match runtime.enforced_limits() {
            WasmiEnforcedLimits::Strict => EnforcedLimits::strict(),
        });
    // wasmi's SIMD setters are absent because the exact dependency feature set
    // excludes `simd`. The identity records that build-time fact explicitly.
    assert!(!runtime.simd_compiled() && !runtime.relaxed_simd_compiled());
    match runtime.fuel_costs() {
        WasmiFuelCosts::Wasmi110Default => {}
    }
    Engine::new(&config)
}

/// A clonable engine whose configuration is exactly Profile 1.
///
/// Components use one shared `ProfileEngine` for every embedded Core module,
/// preventing accidental cross-engine handles while retaining deterministic
/// eager compilation.
#[derive(Clone, Debug)]
pub struct ProfileEngine {
    inner: Engine,
    identity: &'static ValidationEngineIdentity,
}

impl ProfileEngine {
    pub fn new() -> Self {
        let identity = current_validation_engine_identity(ProfileIdentity::PROFILE_1_SYNC)
            .expect("the compiled Profile 1 engine identity must exist");
        Self {
            inner: build_engine(identity),
            identity,
        }
    }

    pub fn as_wasmi(&self) -> &Engine {
        &self.inner
    }

    /// Exact validator/runtime identity from which this engine's Config was
    /// constructed. The returned value has no public constructor or fields.
    pub const fn validation_identity(&self) -> &'static ValidationEngineIdentity {
        self.identity
    }
}

impl Default for ProfileEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerAllocationReservation {
    bytes: usize,
}

impl OwnerAllocationReservation {
    /// Creates a reservation already charged to the prospective instance
    /// owner. C4 must enter that owner's allocator scope while compiling.
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    pub const fn profile_default() -> Self {
        Self {
            bytes: PROFILE_1_LIMITS.max_core_module_bytes * 64,
        }
    }

    pub const fn bytes(self) -> usize {
        self.bytes
    }
}

/// Integer value types admitted at the Core/host boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreValueType {
    I32,
    I64,
}

impl CoreValueType {
    const fn into_wasmi(self) -> ValType {
        match self {
            Self::I32 => ValType::I32,
            Self::I64 => ValType::I64,
        }
    }
}

/// One exact Core host import admitted for a single module instantiation.
///
/// The module and field names, signature, and application-assigned identifier
/// are all part of the allowlist. The descriptor is inert: host work is not
/// performed by a Wasmi callback, but is surfaced as [`PollResult::HostCall`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreHostImport<'a> {
    pub id: u32,
    pub module: &'a str,
    pub name: &'a str,
    pub params: &'a [CoreValueType],
    pub results: &'a [CoreValueType],
}

/// One exact module import linked from an already-instantiated Core instance
/// in the same Component principal and Wasmi store.
///
/// `instance` must name a prior entry in [`CoreComponentGroup`]. Only integer
/// functions and memory32 memories are admitted; tables and globals remain
/// closed even if the source instance exports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreInstanceExportImport<'a> {
    pub module: &'a str,
    pub name: &'a str,
    pub instance: usize,
    pub export: &'a str,
}

/// Closed source allowlist for one embedded module import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreModuleImport<'a> {
    Host(CoreHostImport<'a>),
    InstanceExport(CoreInstanceExportImport<'a>),
}

impl<'a> CoreModuleImport<'a> {
    const fn module(&self) -> &'a str {
        match self {
            Self::Host(import) => import.module,
            Self::InstanceExport(import) => import.module,
        }
    }

    const fn name(&self) -> &'a str {
        match self {
            Self::Host(import) => import.name,
            Self::InstanceExport(import) => import.name,
        }
    }
}

/// A suspended Core call requesting one exact host operation.
///
/// The event is move-only and carries private provenance for its dynamic
/// continuation occurrence. Descriptive fields remain readable, but an
/// externally reconstructed description can never acquire termination
/// authority.
///
/// ```compile_fail
/// use vibeos_wasm_runtime::CoreHostCall;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CoreHostCall>();
/// ```
///
/// ```compile_fail
/// use vibeos_wasm_runtime::CoreHostCall;
/// let _ = CoreHostCall {
///     origin_instance: 0,
///     id: 1,
///     arguments: Vec::new(),
/// };
/// ```
pub struct CoreHostCall {
    /// Instance that defined the host import, which can differ from the outer
    /// active continuation when a prior-instance export calls the host.
    pub origin_instance: usize,
    pub id: u32,
    pub arguments: Vec<CoreValue>,
    evidence: Option<CoreHostCallEvidence>,
}

impl CoreHostCall {
    /// Constructs descriptive, explicitly untrusted host-call data.
    ///
    /// This exists for fail-closed validation and fuzz tests which need to
    /// inject malformed descriptions. It carries no continuation provenance
    /// and [`CoreInstance::host_termination_token`] always rejects it.
    pub fn untrusted_description(
        origin_instance: usize,
        id: u32,
        arguments: Vec<CoreValue>,
    ) -> Self {
        Self {
            origin_instance,
            id,
            arguments,
            evidence: None,
        }
    }
}

impl fmt::Debug for CoreHostCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreHostCall")
            .field("origin_instance", &self.origin_instance)
            .field("id", &self.id)
            .field("arguments", &self.arguments)
            .finish()
    }
}

impl PartialEq for CoreHostCall {
    fn eq(&self, other: &Self) -> bool {
        self.origin_instance == other.origin_instance
            && self.id == other.id
            && self.arguments == other.arguments
    }
}

impl Eq for CoreHostCall {}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CoreHostCallEvidence {
    generation: u64,
    occurrence: u64,
}

/// A single-use capability for terminating one exact suspended host call.
///
/// The token is opaque and intentionally neither cloneable nor copyable. It is
/// bound to the instance-independent continuation generation and to the exact
/// host-call occurrence returned by [`CoreInstance::poll_call`].
///
/// ```compile_fail
/// use vibeos_wasm_runtime::CoreHostTerminationToken;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CoreHostTerminationToken>();
/// ```
pub struct CoreHostTerminationToken {
    evidence: CoreHostCallEvidence,
    origin_instance: usize,
    id: u32,
}

impl fmt::Debug for CoreHostTerminationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreHostTerminationToken")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct ValidatedCore {
    engine: Engine,
    module: Module,
    summary: CoreSummary,
    reserved_compile_bytes: usize,
}

impl ValidatedCore {
    pub fn new(
        bytes: &[u8],
        reservation: OwnerAllocationReservation,
    ) -> Result<Self, AdmissionError> {
        Self::new_in(&ProfileEngine::new(), bytes, reservation)
    }

    pub fn new_in(
        profile_engine: &ProfileEngine,
        bytes: &[u8],
        reservation: OwnerAllocationReservation,
    ) -> Result<Self, AdmissionError> {
        let summary = inspect_core(bytes)?;
        // This is a deliberately conservative pre-charge, not a claim that
        // wasmi exposes exact allocation callbacks. The reservation belongs to
        // one owner and is consumed before any engine allocation is attempted.
        let structural = (summary.functions as usize)
            .saturating_mul(64)
            .saturating_add((summary.types as usize).saturating_mul(32))
            .saturating_add((summary.globals as usize).saturating_mul(16));
        let reserved_compile_bytes = bytes.len().saturating_mul(32).saturating_add(structural);
        if reserved_compile_bytes > reservation.bytes() {
            return Err(AdmissionError {
                trap: TrapCode::LimitExceeded,
                detail: AdmissionDetail::AllocationReservation,
            });
        }
        let engine = profile_engine.inner.clone();
        let module = Module::new(&engine, bytes)
            .map_err(|_| AdmissionError::validation(AdmissionDetail::Malformed))?;
        Ok(Self {
            engine,
            module,
            summary,
            reserved_compile_bytes,
        })
    }

    pub const fn summary(&self) -> CoreSummary {
        self.summary
    }

    pub const fn reserved_compile_bytes(&self) -> usize {
        self.reserved_compile_bytes
    }

    /// Controlled seam for the Component runtime. Modules returned here may
    /// only be linked with stores created from the same `engine()`.
    pub fn module(&self) -> &Module {
        &self.module
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn instantiate(&self) -> Result<CoreInstance, AdmissionError> {
        if self.summary.imports != 0 {
            return Err(AdmissionError::validation(
                AdmissionDetail::ImportRequiresLinker,
            ));
        }
        self.instantiate_with_imports(&[])
    }

    /// Instantiates with an exact, closed allowlist of integer host functions.
    ///
    /// Every module import must have one descriptor with the same module name,
    /// field name, parameter types, and result types. Extra descriptors,
    /// duplicate names, duplicate identifiers, and non-function imports are
    /// rejected before the store is made executable.
    pub fn instantiate_with_imports(
        &self,
        imports: &[CoreHostImport<'_>],
    ) -> Result<CoreInstance, AdmissionError> {
        self.check_host_imports(imports)?;
        let limits = profile_store_limits(1);
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits,
                pending_host: None,
            },
        );
        store.limiter(|state| &mut state.limits);
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        for module_import in self.module.imports() {
            let descriptor = imports
                .iter()
                .find(|candidate| {
                    candidate.module == module_import.module()
                        && candidate.name == module_import.name()
                })
                .ok_or_else(host_import_error)?;
            let ty = module_import
                .ty()
                .func()
                .cloned()
                .ok_or_else(host_import_error)?;
            let id = descriptor.id;
            linker
                .func_new(
                    descriptor.module,
                    descriptor.name,
                    ty,
                    move |mut caller, inputs, _outputs| {
                        if caller.data().pending_host.is_some() {
                            return Err(WasmiError::host(HostBridgeError::Busy));
                        }
                        let mut arguments = Vec::new();
                        arguments
                            .try_reserve_exact(inputs.len())
                            .map_err(|_| WasmiError::host(HostBridgeError::Allocation))?;
                        for input in inputs {
                            let value = CoreValue::from_wasmi(input)
                                .ok_or_else(|| WasmiError::host(HostBridgeError::Type))?;
                            arguments.push(value);
                        }
                        caller.data_mut().pending_host = Some(PendingHostCall {
                            origin_instance: 0,
                            id,
                            arguments,
                        });
                        Err(WasmiError::host(HostBridgeError::Yield { id }))
                    },
                )
                .map_err(|_| host_import_error())?;
        }
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|error| AdmissionError {
                trap: map_wasmi_error(&error),
                detail: AdmissionDetail::Malformed,
            })?;
        Ok(CoreInstance {
            store,
            instance,
            active_call: None,
            last_call: None,
        })
    }

    fn check_host_imports(&self, imports: &[CoreHostImport<'_>]) -> Result<(), AdmissionError> {
        if self.module.imports().len() != imports.len()
            || imports.len() > PROFILE_1_LIMITS.max_imports as usize
        {
            return Err(host_import_error());
        }
        for (index, descriptor) in imports.iter().enumerate() {
            if descriptor.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
                || descriptor.results.len() > PROFILE_1_LIMITS.max_results_per_function as usize
                || imports[..index].iter().any(|previous| {
                    previous.id == descriptor.id
                        || (previous.module == descriptor.module
                            && previous.name == descriptor.name)
                })
            {
                return Err(host_import_error());
            }
        }
        for module_import in self.module.imports() {
            let descriptor = imports
                .iter()
                .find(|candidate| {
                    candidate.module == module_import.module()
                        && candidate.name == module_import.name()
                })
                .ok_or_else(host_import_error)?;
            let actual = module_import.ty().func().ok_or_else(host_import_error)?;
            let expected = FuncType::new(
                descriptor
                    .params
                    .iter()
                    .copied()
                    .map(CoreValueType::into_wasmi),
                descriptor
                    .results
                    .iter()
                    .copied()
                    .map(CoreValueType::into_wasmi),
            );
            if actual != &expected {
                return Err(host_import_error());
            }
        }
        Ok(())
    }
}

fn host_import_error() -> AdmissionError {
    AdmissionError::validation(AdmissionDetail::HostImportMismatch)
}

pub fn profile_store_limits(instances: usize) -> StoreLimits {
    profile_store_limits_with_memory(
        instances,
        PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
    )
    .expect("the static Profile-1 memory ceiling is valid")
}

/// Builds the Profile-1 store limiter with an image-selected per-memory
/// ceiling. The caller may tighten the profile limit, but can never widen it
/// or disable it with zero. This is an execution limit enforced by wasmi on
/// both instantiation and `memory.grow`; it is independent of compile-time
/// allocation reservation accounting.
pub fn profile_store_limits_with_memory(
    instances: usize,
    memory_bytes: usize,
) -> Result<StoreLimits, AdmissionError> {
    let profile_memory_bytes = PROFILE_1_LIMITS.max_memory_pages as usize * 65_536;
    if memory_bytes == 0 || memory_bytes > profile_memory_bytes {
        return Err(AdmissionError::limit(LimitKind::MemoryPages));
    }
    Ok(StoreLimitsBuilder::new()
        .memory_size(memory_bytes)
        .table_elements(PROFILE_1_LIMITS.max_table_elements as usize)
        .instances(instances)
        .tables((PROFILE_1_LIMITS.max_tables as usize).saturating_mul(instances))
        .memories((PROFILE_1_LIMITS.max_memories as usize).saturating_mul(instances))
        .trap_on_grow_failure(true)
        .build())
}

#[derive(Debug)]
struct HostState {
    limits: StoreLimits,
    pending_host: Option<PendingHostCall>,
}

#[derive(Debug)]
struct PendingHostCall {
    origin_instance: usize,
    id: u32,
    arguments: Vec<CoreValue>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostBridgeError {
    Yield { id: u32 },
    Busy,
    Allocation,
    Type,
}

impl fmt::Display for HostBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yield { id } => write!(formatter, "host import {id} yielded"),
            Self::Busy => formatter.write_str("host import mailbox is busy"),
            Self::Allocation => formatter.write_str("host import mailbox allocation failed"),
            Self::Type => formatter.write_str("host import received a disabled value type"),
        }
    }
}

impl HostError for HostBridgeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreValue {
    I32(i32),
    I64(i64),
}

/// Maximum number of integer results surfaced by one admitted Core function.
pub const MAX_CORE_RESULTS: usize = PROFILE_1_LIMITS.max_results_per_function as usize;

/// Allocation-free terminal results returned by a reusable Core call slot.
///
/// Only the prefix exposed by [`Self::as_slice`] is initialized with guest
/// results. The fixed backing array keeps the slot's allocation-backed result
/// scratch inside the runtime for the next invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreResults {
    values: [CoreValue; MAX_CORE_RESULTS],
    len: usize,
}

impl CoreResults {
    fn from_slice(values: &[CoreValue]) -> Option<Self> {
        if values.len() > MAX_CORE_RESULTS {
            return None;
        }
        let mut result = Self {
            values: [CoreValue::I32(0); MAX_CORE_RESULTS],
            len: values.len(),
        };
        result.values[..values.len()].copy_from_slice(values);
        Some(result)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[CoreValue] {
        &self.values[..self.len()]
    }
}

impl AsRef<[CoreValue]> for CoreResults {
    fn as_ref(&self) -> &[CoreValue] {
        self.as_slice()
    }
}

impl CoreValue {
    fn into_wasmi(self) -> Val {
        match self {
            Self::I32(value) => Val::I32(value),
            Self::I64(value) => Val::I64(value),
        }
    }

    fn from_wasmi(value: &Val) -> Option<Self> {
        match value {
            Val::I32(value) => Some(Self::I32(*value)),
            Val::I64(value) => Some(Self::I64(*value)),
            _ => None,
        }
    }

    pub const fn value_type(self) -> CoreValueType {
        match self {
            Self::I32(_) => CoreValueType::I32,
            Self::I64(_) => CoreValueType::I64,
        }
    }
}

pub struct CoreInstance {
    store: Store<HostState>,
    instance: Instance,
    active_call: Option<ActiveCall>,
    last_call: Option<CallMetrics>,
}

impl CoreInstance {
    /// Starts one call whose continuation is owned by this instance.
    ///
    /// Unlike [`CoreInstance::begin_call`], this does not borrow the instance
    /// for the lifetime of the call. Component runtimes can therefore keep
    /// their own multi-stage state machine and drive this call with
    /// [`CoreInstance::poll_call`]. Exactly one call may be active per Core
    /// instance.
    pub fn start_call(
        &mut self,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<(), TrapCode> {
        if self.active_call.is_some() {
            return Err(TrapCode::Validation);
        }
        if total_fuel == 0
            || total_fuel > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_fuel
        {
            return Err(TrapCode::LimitExceeded);
        }
        let function = self
            .instance
            .get_func(&self.store, export)
            .ok_or(TrapCode::Validation)?;
        let ty = function.ty(&self.store);
        if ty.params().len() != inputs.len()
            || ty
                .params()
                .iter()
                .any(|ty| !matches!(ty, wasmi::ValType::I32 | wasmi::ValType::I64))
            || ty
                .results()
                .iter()
                .any(|ty| !matches!(ty, wasmi::ValType::I32 | wasmi::ValType::I64))
        {
            return Err(TrapCode::Validation);
        }
        let mut core_inputs = Vec::new();
        core_inputs
            .try_reserve_exact(inputs.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        core_inputs.extend(inputs.iter().copied().map(CoreValue::into_wasmi));
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(ty.results().len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        outputs.extend(ty.results().iter().copied().map(Val::default));
        let mut result_values = Vec::new();
        result_values
            .try_reserve_exact(ty.results().len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        self.last_call = None;
        self.active_call = Some(ActiveCall {
            function,
            inputs: core_inputs,
            outputs,
            result_values,
            continuation: None,
            remaining_fuel: total_fuel,
            poll_quantum,
            consumed_fuel: 0,
            external_debit: 0,
            started: false,
            cancelled: false,
            slot_tag: None,
            host_generation: None,
            next_host_occurrence: 1,
        });
        Ok(())
    }

    /// Polls the active call for at most its configured quantum.
    ///
    /// A terminal result removes the call and its continuation before this
    /// method returns. A subsequent call can then be started immediately.
    pub fn poll_call(&mut self) -> PollResult {
        let Some(call) = self.active_call.as_mut() else {
            return PollResult::Trapped(TrapCode::Validation);
        };
        let result = call.poll(&mut self.store);
        match result {
            ActivePollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => PollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            },
            ActivePollResult::HostCall(call) => PollResult::HostCall(call),
            ActivePollResult::Ready => {
                let mut call = self
                    .active_call
                    .take()
                    .expect("the active call was present before terminal polling");
                self.last_call = Some(call.metrics());
                PollResult::Ready(core::mem::take(&mut call.result_values))
            }
            ActivePollResult::Trapped(trap) => {
                let call = self
                    .active_call
                    .take()
                    .expect("the active call was present before terminal polling");
                self.last_call = Some(call.metrics());
                PollResult::Trapped(trap)
            }
        }
    }

    /// Supplies the exact results for the currently suspended host import.
    ///
    /// This only records validated values. Guest execution resumes on the next
    /// [`CoreInstance::poll_call`], so the caller retains an explicit
    /// scheduling and fuel-accounting boundary around host work.
    pub fn resume_host_call(&mut self, id: u32, results: &[CoreValue]) -> Result<(), TrapCode> {
        if self.store.data().pending_host.is_some() {
            return Err(TrapCode::Validation);
        }
        self.active_call
            .as_mut()
            .ok_or(TrapCode::Validation)?
            .resume_host_call(&self.store, id, results)
    }

    /// Removes reserved fuel from the active continuation without executing
    /// guest instructions. Embedding runtimes use this to charge host or ABI
    /// work to the same ledger as the suspended Core call.
    pub fn debit_call_fuel(&mut self, amount: u64) -> Result<(), TrapCode> {
        self.active_call
            .as_mut()
            .ok_or(TrapCode::Validation)?
            .debit_external_fuel(amount)
    }

    /// Atomically releases unused fuel previously charged by
    /// [`Self::debit_call_fuel`]. Guest-executed fuel cannot be credited.
    pub fn credit_call_fuel(&mut self, amount: u64) -> Result<(), TrapCode> {
        self.active_call
            .as_mut()
            .ok_or(TrapCode::Validation)?
            .credit_external_fuel(amount)
    }

    /// Consumes one exact host-call event and returns its termination token.
    ///
    /// `call` must be the original value returned by the most recent
    /// [`Self::poll_call`] host yield. Values created through
    /// [`CoreHostCall::untrusted_description`] carry no occurrence identity and
    /// are rejected. Failure leaves the active call and continuation untouched.
    pub fn host_termination_token(
        &self,
        call: CoreHostCall,
    ) -> Result<CoreHostTerminationToken, TrapCode> {
        let CoreHostCall {
            origin_instance,
            id,
            arguments: _,
            evidence,
        } = call;
        let evidence = evidence.ok_or(TrapCode::Validation)?;
        self.active_call
            .as_ref()
            .ok_or(TrapCode::Validation)?
            .validate_host_termination_event(origin_instance, id, evidence)?;
        Ok(CoreHostTerminationToken {
            evidence,
            origin_instance,
            id,
        })
    }

    /// Terminates the active call at one exact unresolved host-call boundary.
    ///
    /// This is the non-returning counterpart to [`Self::resume_host_call`], for
    /// imports such as an invocation-scoped exit operation. `token` must have
    /// been obtained by consuming the exact host-call event for the current
    /// dynamic continuation generation. A stale, wrong-instance, non-host, or
    /// already-resolved token is rejected without changing the active call.
    ///
    /// On success no guest instruction after the import is executed: the
    /// resumable continuation and host mailbox are discarded, while the call's
    /// terminal fuel metrics remain available through [`Self::call_metrics`].
    /// This method assigns no meaning to the host operation or its arguments;
    /// the embedding runtime must validate those before terminating the call.
    pub fn terminate_suspended_host_call(
        &mut self,
        token: CoreHostTerminationToken,
    ) -> Result<(), TrapCode> {
        self.active_call
            .as_ref()
            .ok_or(TrapCode::Validation)?
            .validate_host_termination_token(&token)?;

        // The mailbox is normally consumed while creating the suspended host
        // continuation. Clear it defensively in the same terminal transition,
        // so a non-returning import cannot poison the next invocation.
        self.store.data_mut().pending_host = None;
        self.discard_active_call();
        Ok(())
    }

    /// Requests cancellation of the active call. The next poll reports the
    /// stable `Cancelled` trap and drops the continuation without executing
    /// more guest instructions.
    pub fn cancel_call(&mut self) -> Result<(), TrapCode> {
        let call = self.active_call.as_mut().ok_or(TrapCode::Validation)?;
        call.cancelled = true;
        Ok(())
    }

    /// Abandons the active call without polling or executing more guest code.
    ///
    /// This is the teardown counterpart to [`CoreInstance::cancel_call`]. A
    /// caller that remains alive should request cancellation and poll once to
    /// observe the stable `Cancelled` terminal result. An owning component
    /// continuation that is itself being dropped cannot do that safely, so it
    /// uses this method to release the interpreter continuation immediately.
    pub fn discard_call(&mut self) -> Result<(), TrapCode> {
        if self.active_call.is_none() {
            return Err(TrapCode::Validation);
        }
        self.discard_active_call();
        Ok(())
    }

    pub const fn has_active_call(&self) -> bool {
        self.active_call.is_some()
    }

    /// Returns fuel accounting for the active call, or for the most recently
    /// completed call until another call starts.
    pub fn call_metrics(&self) -> Option<CallMetrics> {
        self.active_call
            .as_ref()
            .map(ActiveCall::metrics)
            .or(self.last_call)
    }

    pub fn begin_call<'a>(
        &'a mut self,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<Invocation<'a>, TrapCode> {
        self.start_call(export, inputs, total_fuel, poll_quantum)?;
        Ok(Invocation {
            instance: self,
            consumed_fuel: 0,
            remaining_fuel: total_fuel,
            terminal: false,
        })
    }

    /// Linear-memory accesses copy bytes and never expose a reference into the
    /// store. They are consequently permitted while a call is suspended
    /// between `poll_call` invocations; Rust's `&mut self` discipline prevents
    /// them from racing with an executing poll.
    pub fn read_memory(
        &self,
        export: &str,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), TrapCode> {
        let memory = self.memory(export)?;
        memory
            .read(&self.store, offset, output)
            .map_err(|_| TrapCode::MemoryOutOfBounds)
    }

    pub fn write_memory(
        &mut self,
        export: &str,
        offset: usize,
        input: &[u8],
    ) -> Result<(), TrapCode> {
        let memory = self.memory(export)?;
        memory
            .write(&mut self.store, offset, input)
            .map_err(|_| TrapCode::MemoryOutOfBounds)
    }

    pub fn memory_size(&self, export: &str) -> Result<usize, TrapCode> {
        Ok(self.memory(export)?.data_size(&self.store))
    }

    /// Grows an exported memory to cover `minimum_bytes`, preserving the Core
    /// module's declared maximum and the store's owner limits.
    pub fn grow_memory_to(&mut self, export: &str, minimum_bytes: usize) -> Result<(), TrapCode> {
        let memory = self.memory(export)?;
        let current = memory.data_size(&self.store);
        if minimum_bytes <= current {
            return Ok(());
        }
        let additional_bytes = minimum_bytes
            .checked_sub(current)
            .ok_or(TrapCode::MemoryOutOfBounds)?;
        let additional_pages = additional_bytes
            .checked_add(65_535)
            .ok_or(TrapCode::MemoryOutOfBounds)?
            / 65_536;
        memory
            .grow(&mut self.store, additional_pages as u64)
            .map_err(|_| TrapCode::MemoryOutOfBounds)?;
        Ok(())
    }

    fn memory(&self, export: &str) -> Result<Memory, TrapCode> {
        self.instance
            .get_memory(&self.store, export)
            .ok_or(TrapCode::Validation)
    }

    fn discard_active_call(&mut self) {
        if let Some(call) = self.active_call.take() {
            self.last_call = Some(call.metrics());
        }
    }
}

/// A bounded set of Core instances belonging to one Component principal.
///
/// Every instance uses the same Wasmi engine, store, limits, and host mailbox.
/// Calls still have per-instance continuation and fuel state, which permits an
/// outer guest call to remain suspended on a host import while a distinct,
/// prior provider instance executes a canonical realloc callback.
pub struct CoreComponentGroup {
    reservation_owner: u32,
    engine: Engine,
    store: Store<HostState>,
    instances: Vec<GroupInstance>,
    host_ids: Vec<u32>,
    instance_limit: usize,
    state: ComponentGroupState,
}

/// An opaque capability for one Core memory in a [`CoreComponentGroup`].
///
/// Authorities are issued only after resolving an instance export to its
/// underlying Wasmi memory handle. Imported and re-exported aliases therefore
/// authorize the same memory, and the handle remains valid across memory
/// growth. Every operation verifies the issuing group before using the handle.
#[derive(Clone, Copy)]
pub struct CoreMemoryAuthority {
    owner: u32,
    memory: Memory,
}

impl fmt::Debug for CoreMemoryAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoreMemoryAuthority(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComponentGroupState {
    Building,
    Sealed,
    Poisoned,
}

struct GroupInstance {
    instance: Instance,
    active_call: Option<ActiveCall>,
    last_call: Option<CallMetrics>,
    last_call_slot_tag: Option<CoreCallSlotTag>,
}

/// Allocation-backed storage for one exact group call.
///
/// Reservations are intentionally neither cloneable nor reusable. Creating
/// one performs every fallible allocation needed to construct the active
/// call; [`CoreComponentGroup::start_call_reserved`] consumes it by value.
pub struct CoreCallReservation {
    owner: u32,
    instance: usize,
    export: Vec<u8>,
    function: Func,
    inputs: Vec<Val>,
    outputs: Vec<Val>,
    result_values: Vec<CoreValue>,
}

/// Lifecycle of one reusable, allocation-backed Core call slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreCallSlotState {
    Idle,
    Active,
    Poisoned,
}

/// Allocation-backed storage reusable for repeated calls to one exact export.
///
/// A slot is bound to the group, instance, export, and an unforgeable
/// generation assigned at reservation. While active, its call scratch is
/// owned by the matching runtime call; terminal slot polling returns that
/// storage exactly once.
pub struct CoreCallSlot {
    owner: u32,
    instance: usize,
    export: Vec<u8>,
    generation: u64,
    state: CoreCallSlotState,
    storage: Option<CoreCallStorage>,
}

struct CoreCallStorage {
    function: Func,
    inputs: Vec<Val>,
    outputs: Vec<Val>,
    result_values: Vec<CoreValue>,
}

impl CoreCallSlot {
    pub const fn state(&self) -> CoreCallSlotState {
        self.state
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CoreCallSlotTag {
    owner: u32,
    instance: usize,
    generation: u64,
}

impl CoreComponentGroup {
    pub fn new(engine: &ProfileEngine, instance_limit: usize) -> Result<Self, AdmissionError> {
        Self::new_with_memory_limit(
            engine,
            instance_limit,
            PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
        )
    }

    /// Creates a Component group whose Core memories are constrained by the
    /// exact image/session policy ceiling. The same limiter remains attached
    /// to the shared store for the group's full lifetime.
    pub fn new_with_memory_limit(
        engine: &ProfileEngine,
        instance_limit: usize,
        memory_bytes: usize,
    ) -> Result<Self, AdmissionError> {
        if instance_limit > PROFILE_1_LIMITS.max_component_instances as usize {
            return Err(AdmissionError::limit(LimitKind::ComponentInstances));
        }
        let mut instances = Vec::new();
        instances
            .try_reserve_exact(instance_limit)
            .map_err(|_| allocation_error())?;
        let mut store = Store::new(
            &engine.inner,
            HostState {
                limits: profile_store_limits_with_memory(instance_limit.max(1), memory_bytes)?,
                pending_host: None,
            },
        );
        store.limiter(|state| &mut state.limits);
        Ok(Self {
            reservation_owner: next_group_reservation_owner()?,
            engine: engine.inner.clone(),
            store,
            instances,
            host_ids: Vec::new(),
            instance_limit,
            state: ComponentGroupState::Building,
        })
    }

    pub fn add_instance(
        &mut self,
        validated: &ValidatedCore,
        imports: &[CoreModuleImport<'_>],
    ) -> Result<usize, AdmissionError> {
        if self.state != ComponentGroupState::Building
            || self.any_active_call()
            || self.instances.len() >= self.instance_limit
            || !Engine::same(&self.engine, validated.engine())
        {
            return Err(host_import_error());
        }
        self.check_module_imports(validated, imports)?;
        let origin_instance = self.instances.len();
        let host_count = imports
            .iter()
            .filter(|import| matches!(import, CoreModuleImport::Host(_)))
            .count();
        self.host_ids
            .try_reserve(host_count)
            .map_err(|_| allocation_error())?;
        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        for import in imports {
            match import {
                CoreModuleImport::Host(descriptor) => {
                    let module_import = validated
                        .module
                        .imports()
                        .find(|candidate| {
                            candidate.module() == descriptor.module
                                && candidate.name() == descriptor.name
                        })
                        .ok_or_else(host_import_error)?;
                    let ty = module_import
                        .ty()
                        .func()
                        .cloned()
                        .ok_or_else(host_import_error)?;
                    let id = descriptor.id;
                    linker
                        .func_new(
                            descriptor.module,
                            descriptor.name,
                            ty,
                            move |mut caller, inputs, _outputs| {
                                if caller.data().pending_host.is_some() {
                                    return Err(WasmiError::host(HostBridgeError::Busy));
                                }
                                let mut arguments = Vec::new();
                                arguments
                                    .try_reserve_exact(inputs.len())
                                    .map_err(|_| WasmiError::host(HostBridgeError::Allocation))?;
                                for input in inputs {
                                    let value = CoreValue::from_wasmi(input)
                                        .ok_or_else(|| WasmiError::host(HostBridgeError::Type))?;
                                    arguments.push(value);
                                }
                                caller.data_mut().pending_host = Some(PendingHostCall {
                                    origin_instance,
                                    id,
                                    arguments,
                                });
                                Err(WasmiError::host(HostBridgeError::Yield { id }))
                            },
                        )
                        .map_err(|_| host_import_error())?;
                }
                CoreModuleImport::InstanceExport(descriptor) => {
                    let source = self
                        .instances
                        .get(descriptor.instance)
                        .ok_or_else(host_import_error)?;
                    let export = source
                        .instance
                        .get_export(&self.store, descriptor.export)
                        .ok_or_else(host_import_error)?;
                    linker
                        .define(descriptor.module, descriptor.name, export)
                        .map_err(|_| host_import_error())?;
                }
            }
        }
        self.store.data_mut().pending_host = None;
        let instance = match linker.instantiate_and_start(&mut self.store, validated.module()) {
            Ok(instance) => instance,
            Err(error) => {
                self.store.data_mut().pending_host = None;
                // Instantiation is not assumed to be transactional: active
                // data segments or a start function may already have mutated
                // an imported prior-instance memory before the failure.
                self.state = ComponentGroupState::Poisoned;
                return Err(AdmissionError {
                    trap: map_wasmi_error(&error),
                    detail: AdmissionDetail::Malformed,
                });
            }
        };
        let index = self.instances.len();
        self.instances.push(GroupInstance {
            instance,
            active_call: None,
            last_call: None,
            last_call_slot_tag: None,
        });
        for import in imports {
            if let CoreModuleImport::Host(host) = import {
                self.host_ids.push(host.id);
            }
        }
        Ok(index)
    }

    fn check_module_imports(
        &self,
        validated: &ValidatedCore,
        imports: &[CoreModuleImport<'_>],
    ) -> Result<(), AdmissionError> {
        if validated.module.imports().len() != imports.len()
            || imports.len() > PROFILE_1_LIMITS.max_imports as usize
        {
            return Err(host_import_error());
        }
        for (index, descriptor) in imports.iter().enumerate() {
            if imports[..index].iter().any(|previous| {
                previous.module() == descriptor.module() && previous.name() == descriptor.name()
            }) {
                return Err(host_import_error());
            }
            if let CoreModuleImport::Host(host) = descriptor {
                if host.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
                    || host.results.len() > PROFILE_1_LIMITS.max_results_per_function as usize
                    || self.host_ids.contains(&host.id)
                    || imports[..index]
                        .iter()
                        .any(|previous| matches!(previous, CoreModuleImport::Host(value) if value.id == host.id))
                {
                    return Err(host_import_error());
                }
            }
        }
        for module_import in validated.module.imports() {
            let descriptor = imports
                .iter()
                .find(|candidate| {
                    candidate.module() == module_import.module()
                        && candidate.name() == module_import.name()
                })
                .ok_or_else(host_import_error)?;
            match descriptor {
                CoreModuleImport::Host(host) => {
                    let actual = module_import.ty().func().ok_or_else(host_import_error)?;
                    let expected = FuncType::new(
                        host.params.iter().copied().map(CoreValueType::into_wasmi),
                        host.results.iter().copied().map(CoreValueType::into_wasmi),
                    );
                    if actual != &expected {
                        return Err(host_import_error());
                    }
                }
                CoreModuleImport::InstanceExport(source) => {
                    if source.instance >= self.instances.len() {
                        return Err(host_import_error());
                    }
                    let export = self.instances[source.instance]
                        .instance
                        .get_export(&self.store, source.export)
                        .ok_or_else(host_import_error)?;
                    if !exact_group_export_type(module_import.ty(), &export.ty(&self.store)) {
                        return Err(host_import_error());
                    }
                }
            }
        }
        Ok(())
    }

    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Permanently closes construction. Execution also seals automatically.
    pub fn seal(&mut self) -> Result<(), TrapCode> {
        if self.state == ComponentGroupState::Poisoned || self.any_active_call() {
            return Err(TrapCode::Validation);
        }
        self.state = ComponentGroupState::Sealed;
        Ok(())
    }

    pub fn has_active_call(&self, instance: usize) -> bool {
        self.instances
            .get(instance)
            .is_some_and(|instance| instance.active_call.is_some())
    }

    pub fn any_active_call(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| instance.active_call.is_some())
    }

    pub fn start_call(
        &mut self,
        instance: usize,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<(), TrapCode> {
        let reservation = self.reserve_call(instance, export)?;
        self.start_call_reserved(
            reservation,
            instance,
            export,
            inputs,
            total_fuel,
            poll_quantum,
        )
    }

    /// Preallocates the complete active-call shell for one exact export.
    ///
    /// This method is intended to run before an irreversible host side
    /// effect. The returned opaque value can subsequently be consumed without
    /// allocating, while still revalidating all caller-controlled metadata.
    pub fn reserve_call(
        &self,
        instance: usize,
        export: &str,
    ) -> Result<CoreCallReservation, TrapCode> {
        if self.state == ComponentGroupState::Poisoned {
            return Err(TrapCode::Validation);
        }
        let state = self.instances.get(instance).ok_or(TrapCode::Validation)?;
        if state.active_call.is_some() {
            return Err(TrapCode::Validation);
        }
        let function = state
            .instance
            .get_func(&self.store, export)
            .ok_or(TrapCode::Validation)?;
        let ty = function.ty(&self.store);
        if ty
            .params()
            .iter()
            .chain(ty.results())
            .any(|ty| !matches!(ty, ValType::I32 | ValType::I64))
        {
            return Err(TrapCode::Validation);
        }
        let mut reserved_export = Vec::new();
        reserved_export
            .try_reserve_exact(export.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        reserved_export.extend_from_slice(export.as_bytes());
        let mut reserved_inputs = Vec::new();
        reserved_inputs
            .try_reserve_exact(ty.params().len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        reserved_inputs.extend(ty.params().iter().copied().map(Val::default));
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(ty.results().len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        outputs.extend(ty.results().iter().copied().map(Val::default));
        let mut result_values = Vec::new();
        result_values
            .try_reserve_exact(ty.results().len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        Ok(CoreCallReservation {
            owner: self.reservation_owner,
            instance,
            export: reserved_export,
            function,
            inputs: reserved_inputs,
            outputs,
            result_values,
        })
    }

    /// Preallocates one reusable call slot bound to an exact group export.
    ///
    /// Unlike [`Self::reserve_call`], terminal polling returns the allocation-
    /// backed storage to this linear slot instead of consuming it.
    pub fn reserve_call_slot(
        &self,
        instance: usize,
        export: &str,
    ) -> Result<CoreCallSlot, TrapCode> {
        let reservation = self.reserve_call(instance, export)?;
        let generation = next_core_call_slot_generation()?;
        Ok(CoreCallSlot {
            owner: reservation.owner,
            instance: reservation.instance,
            export: reservation.export,
            generation,
            state: CoreCallSlotState::Idle,
            storage: Some(CoreCallStorage {
                function: reservation.function,
                inputs: reservation.inputs,
                outputs: reservation.outputs,
                result_values: reservation.result_values,
            }),
        })
    }

    /// Starts a call using storage allocated by [`Self::reserve_call`].
    ///
    /// Every validation completes before group or per-instance state changes,
    /// so all failures leave the group with no newly active call.
    pub fn start_call_reserved(
        &mut self,
        mut reservation: CoreCallReservation,
        instance: usize,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<(), TrapCode> {
        if self.state == ComponentGroupState::Poisoned
            || reservation.owner != self.reservation_owner
            || reservation.instance != instance
            || reservation.export.as_slice() != export.as_bytes()
        {
            return Err(TrapCode::Validation);
        }
        let state = self.instances.get(instance).ok_or(TrapCode::Validation)?;
        if state.active_call.is_some()
            || reservation.inputs.len() != inputs.len()
            || reservation
                .inputs
                .iter()
                .zip(inputs)
                .any(|(slot, input)| slot.ty() != input.value_type().into_wasmi())
        {
            return Err(TrapCode::Validation);
        }
        let current = state
            .instance
            .get_func(&self.store, export)
            .ok_or(TrapCode::Validation)?;
        let current_type = current.ty(&self.store);
        if current_type.params().len() != reservation.inputs.len()
            || current_type.results().len() != reservation.outputs.len()
            || !current_type
                .params()
                .iter()
                .zip(&reservation.inputs)
                .all(|(expected, slot)| *expected == slot.ty())
            || !current_type
                .results()
                .iter()
                .zip(&reservation.outputs)
                .all(|(expected, slot)| *expected == slot.ty())
        {
            return Err(TrapCode::Validation);
        }
        if total_fuel == 0
            || total_fuel > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_fuel
        {
            return Err(TrapCode::LimitExceeded);
        }
        for (slot, input) in reservation.inputs.iter_mut().zip(inputs.iter().copied()) {
            *slot = input.into_wasmi();
        }
        let call = ActiveCall {
            function: reservation.function,
            inputs: reservation.inputs,
            outputs: reservation.outputs,
            result_values: reservation.result_values,
            continuation: None,
            remaining_fuel: total_fuel,
            poll_quantum,
            consumed_fuel: 0,
            external_debit: 0,
            started: false,
            cancelled: false,
            slot_tag: None,
            host_generation: None,
            next_host_occurrence: 1,
        };
        let state = self
            .instances
            .get_mut(instance)
            .expect("the validated group instance remains present");
        state.last_call = None;
        state.last_call_slot_tag = None;
        state.active_call = Some(call);
        self.state = ComponentGroupState::Sealed;
        Ok(())
    }

    /// Starts one invocation using an idle reusable slot.
    ///
    /// Every caller-controlled value and all slot provenance are validated
    /// before the slot or group changes. Successful start moves only the call
    /// scratch into the active call and marks the slot active.
    pub fn start_call_slot(
        &mut self,
        slot: &mut CoreCallSlot,
        instance: usize,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<(), TrapCode> {
        if self.state == ComponentGroupState::Poisoned {
            self.discard_all_calls();
            if slot.owner == self.reservation_owner {
                slot.state = CoreCallSlotState::Poisoned;
                slot.storage = None;
            }
            return Err(TrapCode::Validation);
        }
        if slot.owner != self.reservation_owner
            || slot.instance != instance
            || slot.export.as_slice() != export.as_bytes()
            || slot.generation == 0
            || slot.state != CoreCallSlotState::Idle
        {
            return Err(TrapCode::Validation);
        }
        let storage = slot.storage.as_ref().ok_or(TrapCode::Validation)?;
        let state = self.instances.get(instance).ok_or(TrapCode::Validation)?;
        if state.active_call.is_some()
            || storage.inputs.len() != inputs.len()
            || storage
                .inputs
                .iter()
                .zip(inputs)
                .any(|(reserved, input)| reserved.ty() != input.value_type().into_wasmi())
        {
            return Err(TrapCode::Validation);
        }
        let current = state
            .instance
            .get_func(&self.store, export)
            .ok_or(TrapCode::Validation)?;
        let current_type = current.ty(&self.store);
        if current_type.params().len() != storage.inputs.len()
            || current_type.results().len() != storage.outputs.len()
            || current_type
                .params()
                .iter()
                .zip(&storage.inputs)
                .any(|(expected, reserved)| *expected != reserved.ty())
            || current_type
                .results()
                .iter()
                .zip(&storage.outputs)
                .any(|(expected, reserved)| *expected != reserved.ty())
        {
            return Err(TrapCode::Validation);
        }
        if total_fuel == 0
            || total_fuel > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_fuel
        {
            return Err(TrapCode::LimitExceeded);
        }

        let storage = slot
            .storage
            .as_mut()
            .expect("the validated idle slot retains its call storage");
        for (reserved, input) in storage.inputs.iter_mut().zip(inputs.iter().copied()) {
            *reserved = input.into_wasmi();
        }
        let storage = slot
            .storage
            .take()
            .expect("the validated idle slot retains its call storage");
        let tag = CoreCallSlotTag {
            owner: slot.owner,
            instance: slot.instance,
            generation: slot.generation,
        };
        let call = ActiveCall {
            function: storage.function,
            inputs: storage.inputs,
            outputs: storage.outputs,
            result_values: storage.result_values,
            continuation: None,
            remaining_fuel: total_fuel,
            poll_quantum,
            consumed_fuel: 0,
            external_debit: 0,
            started: false,
            cancelled: false,
            slot_tag: Some(tag),
            host_generation: None,
            next_host_occurrence: 1,
        };
        let state = self
            .instances
            .get_mut(instance)
            .expect("the validated group instance remains present");
        state.last_call = None;
        state.last_call_slot_tag = None;
        state.active_call = Some(call);
        slot.state = CoreCallSlotState::Active;
        self.state = ComponentGroupState::Sealed;
        Ok(())
    }

    /// Polls the exact active invocation owned by `slot` for one quantum.
    ///
    /// Ready and trapped terminals both return every allocation-backed call
    /// scratch buffer to the slot before this method returns.
    pub fn poll_call_slot(&mut self, slot: &mut CoreCallSlot) -> CoreSlotPollResult {
        if slot.owner != self.reservation_owner {
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        }
        if self.state == ComponentGroupState::Poisoned {
            self.discard_all_calls();
            slot.state = CoreCallSlotState::Poisoned;
            slot.storage = None;
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        }
        if slot.state != CoreCallSlotState::Active {
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        }
        if slot.storage.is_some() {
            slot.state = CoreCallSlotState::Poisoned;
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        }
        let expected = CoreCallSlotTag {
            owner: slot.owner,
            instance: slot.instance,
            generation: slot.generation,
        };
        let Some(state) = self.instances.get_mut(slot.instance) else {
            slot.state = CoreCallSlotState::Poisoned;
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        };
        let Some(call) = state.active_call.as_mut() else {
            slot.state = CoreCallSlotState::Poisoned;
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        };
        if call.slot_tag != Some(expected) {
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            slot.state = CoreCallSlotState::Poisoned;
            return CoreSlotPollResult::Trapped(TrapCode::Validation);
        }
        let result = call.poll(&mut self.store);
        match result {
            ActivePollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => CoreSlotPollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            },
            ActivePollResult::HostCall(call) => CoreSlotPollResult::HostCall(call),
            ActivePollResult::Ready => {
                let call = state
                    .active_call
                    .take()
                    .expect("the exact slot call remained active until terminal return");
                state.last_call = Some(call.metrics());
                state.last_call_slot_tag = Some(expected);
                let results = CoreResults::from_slice(&call.result_values);
                if !restore_core_call_slot(slot, call) {
                    self.state = ComponentGroupState::Poisoned;
                    self.discard_all_calls();
                    return CoreSlotPollResult::Trapped(TrapCode::Validation);
                }
                match results {
                    Some(results) => CoreSlotPollResult::Ready(results),
                    None => {
                        slot.state = CoreCallSlotState::Poisoned;
                        slot.storage = None;
                        self.state = ComponentGroupState::Poisoned;
                        self.discard_all_calls();
                        CoreSlotPollResult::Trapped(TrapCode::Validation)
                    }
                }
            }
            ActivePollResult::Trapped(trap) => {
                let call = state
                    .active_call
                    .take()
                    .expect("the exact slot call remained active until terminal return");
                state.last_call = Some(call.metrics());
                state.last_call_slot_tag = Some(expected);
                if restore_core_call_slot(slot, call) {
                    CoreSlotPollResult::Trapped(trap)
                } else {
                    self.state = ComponentGroupState::Poisoned;
                    self.discard_all_calls();
                    CoreSlotPollResult::Trapped(TrapCode::Validation)
                }
            }
        }
    }

    /// Polls an ordinary group call.
    ///
    /// Supplying this API for a slot-owned call destroys that call and
    /// permanently poisons the group: without the linear slot argument its
    /// scratch cannot be returned without creating a false reusable state.
    pub fn poll_call(&mut self, instance: usize) -> PollResult {
        if self.state == ComponentGroupState::Poisoned {
            return PollResult::Trapped(TrapCode::Validation);
        }
        let Some(state) = self.instances.get_mut(instance) else {
            return PollResult::Trapped(TrapCode::Validation);
        };
        let Some(call) = state.active_call.as_mut() else {
            return PollResult::Trapped(TrapCode::Validation);
        };
        if call.slot_tag.is_some() {
            self.discard_all_calls();
            return PollResult::Trapped(TrapCode::Validation);
        }
        let result = call.poll(&mut self.store);
        match result {
            ActivePollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => PollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            },
            ActivePollResult::HostCall(call) => PollResult::HostCall(call),
            ActivePollResult::Ready => {
                let mut call = state
                    .active_call
                    .take()
                    .expect("the active group call was present before terminal polling");
                state.last_call = Some(call.metrics());
                state.last_call_slot_tag = None;
                PollResult::Ready(core::mem::take(&mut call.result_values))
            }
            ActivePollResult::Trapped(trap) => {
                let call = state
                    .active_call
                    .take()
                    .expect("the active group call was present before terminal polling");
                state.last_call = Some(call.metrics());
                state.last_call_slot_tag = None;
                PollResult::Trapped(trap)
            }
        }
    }

    /// Supplies host results to an ordinary active call.
    ///
    /// Slot-owned calls require [`Self::resume_host_call_slot`].
    pub fn resume_host_call(
        &mut self,
        instance: usize,
        id: u32,
        results: &[CoreValue],
    ) -> Result<(), TrapCode> {
        self.resume_host_call_tagged(instance, None, id, results)
    }

    /// Supplies host results to the exact active call owned by `slot`.
    pub fn resume_host_call_slot(
        &mut self,
        slot: &CoreCallSlot,
        id: u32,
        results: &[CoreValue],
    ) -> Result<(), TrapCode> {
        let tag = self.active_slot_tag(slot)?;
        self.resume_host_call_tagged(slot.instance, Some(tag), id, results)
    }

    /// Removes reserved fuel from an active continuation without executing
    /// guest instructions. Component runtimes use this when host/canonical
    /// work shares the same top-level ledger as the suspended Core call.
    /// Slot-owned calls require [`Self::debit_call_fuel_slot`].
    pub fn debit_call_fuel(&mut self, instance: usize, amount: u64) -> Result<(), TrapCode> {
        self.debit_call_fuel_tagged(instance, None, amount)
    }

    /// Debits shared host/canonical work from the exact active slot call.
    pub fn debit_call_fuel_slot(
        &mut self,
        slot: &CoreCallSlot,
        amount: u64,
    ) -> Result<(), TrapCode> {
        let tag = self.active_slot_tag(slot)?;
        self.debit_call_fuel_tagged(slot.instance, Some(tag), amount)
    }

    /// Atomically releases unused fuel previously charged by
    /// [`Self::debit_call_fuel`]. Guest-executed fuel cannot be credited.
    /// Slot-owned calls require [`Self::credit_call_fuel_slot`].
    pub fn credit_call_fuel(&mut self, instance: usize, amount: u64) -> Result<(), TrapCode> {
        self.credit_call_fuel_tagged(instance, None, amount)
    }

    /// Credits unused shared work to the exact active slot call.
    pub fn credit_call_fuel_slot(
        &mut self,
        slot: &CoreCallSlot,
        amount: u64,
    ) -> Result<(), TrapCode> {
        let tag = self.active_slot_tag(slot)?;
        self.credit_call_fuel_tagged(slot.instance, Some(tag), amount)
    }

    /// Requests cancellation of an ordinary active call.
    ///
    /// Slot-owned calls require [`Self::cancel_call_slot`].
    pub fn cancel_call(&mut self, instance: usize) -> Result<(), TrapCode> {
        self.cancel_call_tagged(instance, None)
    }

    /// Requests cancellation of the exact active call owned by `slot`.
    pub fn cancel_call_slot(&mut self, slot: &CoreCallSlot) -> Result<(), TrapCode> {
        let tag = self.active_slot_tag(slot)?;
        self.cancel_call_tagged(slot.instance, Some(tag))
    }

    pub fn discard_call(&mut self, instance: usize) -> Result<(), TrapCode> {
        if self.state == ComponentGroupState::Poisoned {
            return Err(TrapCode::Validation);
        }
        let state = self
            .instances
            .get_mut(instance)
            .ok_or(TrapCode::Validation)?;
        if state
            .active_call
            .as_ref()
            .is_some_and(|call| call.slot_tag.is_some())
        {
            return Err(TrapCode::Validation);
        }
        let call = state.active_call.take().ok_or(TrapCode::Validation)?;
        state.last_call = Some(call.metrics());
        state.last_call_slot_tag = None;
        Ok(())
    }

    /// Abandons the exact active slot call and returns its scratch to the slot.
    ///
    /// This does not execute more guest code. The restored slot is idle and
    /// may be started again. Generic [`Self::discard_call`] deliberately
    /// rejects slot-owned calls because it cannot return storage without the
    /// linear slot authority.
    pub fn discard_call_slot(&mut self, slot: &mut CoreCallSlot) -> Result<(), TrapCode> {
        if slot.owner != self.reservation_owner {
            return Err(TrapCode::Validation);
        }
        if self.state == ComponentGroupState::Poisoned {
            self.discard_all_calls();
            slot.state = CoreCallSlotState::Poisoned;
            slot.storage = None;
            return Err(TrapCode::Validation);
        }
        if slot.state != CoreCallSlotState::Active || slot.storage.is_some() {
            return Err(TrapCode::Validation);
        }
        let expected = CoreCallSlotTag {
            owner: slot.owner,
            instance: slot.instance,
            generation: slot.generation,
        };
        let state = self
            .instances
            .get_mut(slot.instance)
            .ok_or(TrapCode::Validation)?;
        if state.active_call.as_ref().and_then(|call| call.slot_tag) != Some(expected) {
            slot.state = CoreCallSlotState::Poisoned;
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            return Err(TrapCode::Validation);
        }
        let call = state
            .active_call
            .take()
            .expect("the exact slot call was validated as active");
        state.last_call = Some(call.metrics());
        state.last_call_slot_tag = Some(expected);
        self.store.data_mut().pending_host = None;
        if restore_core_call_slot(slot, call) {
            Ok(())
        } else {
            self.state = ComponentGroupState::Poisoned;
            self.discard_all_calls();
            Err(TrapCode::Validation)
        }
    }

    /// Discards every suspended continuation in the principal without
    /// executing further guest instructions.
    ///
    /// If this destroys a slot-owned call without its linear slot authority,
    /// the group is permanently poisoned. A later operation with that slot
    /// synchronizes its externally visible state to [`CoreCallSlotState::Poisoned`].
    pub fn discard_all_calls(&mut self) {
        self.store.data_mut().pending_host = None;
        let mut discarded_slot = false;
        for state in &mut self.instances {
            if let Some(call) = state.active_call.take() {
                discarded_slot |= call.slot_tag.is_some();
                state.last_call = Some(call.metrics());
                state.last_call_slot_tag = call.slot_tag;
            }
        }
        if discarded_slot {
            self.state = ComponentGroupState::Poisoned;
        }
    }

    /// Marks every active continuation cancelled. Each can then be polled at
    /// most once to observe the stable cancellation terminal.
    pub fn cancel_all_calls(&mut self) {
        for state in &mut self.instances {
            if let Some(call) = state.active_call.as_mut() {
                call.cancelled = true;
            }
        }
    }

    /// Returns metrics for an ordinary active or most recently terminal call.
    /// Slot-tagged metrics require [`Self::call_metrics_slot`].
    pub fn call_metrics(&self, instance: usize) -> Option<CallMetrics> {
        if self.state == ComponentGroupState::Poisoned {
            return None;
        }
        let state = self.instances.get(instance)?;
        if let Some(call) = state.active_call.as_ref() {
            return (call.slot_tag.is_none()).then(|| call.metrics());
        }
        (state.last_call_slot_tag.is_none())
            .then_some(state.last_call)
            .flatten()
    }

    /// Returns metrics for the exact active or most recently terminal call
    /// owned by `slot`. Metrics from another slot generation are never
    /// surfaced through this authority.
    pub fn call_metrics_slot(&self, slot: &CoreCallSlot) -> Option<CallMetrics> {
        if self.state == ComponentGroupState::Poisoned
            || slot.owner != self.reservation_owner
            || slot.generation == 0
        {
            return None;
        }
        let tag = CoreCallSlotTag {
            owner: slot.owner,
            instance: slot.instance,
            generation: slot.generation,
        };
        let state = self.instances.get(slot.instance)?;
        match slot.state {
            CoreCallSlotState::Active if slot.storage.is_none() => {
                let call = state.active_call.as_ref()?;
                (call.slot_tag == Some(tag)).then(|| call.metrics())
            }
            CoreCallSlotState::Idle if slot.storage.is_some() && state.active_call.is_none() => {
                (state.last_call_slot_tag == Some(tag))
                    .then_some(state.last_call)
                    .flatten()
            }
            CoreCallSlotState::Idle | CoreCallSlotState::Active | CoreCallSlotState::Poisoned => {
                None
            }
        }
    }

    fn active_slot_tag(&self, slot: &CoreCallSlot) -> Result<CoreCallSlotTag, TrapCode> {
        if self.state == ComponentGroupState::Poisoned
            || slot.owner != self.reservation_owner
            || slot.generation == 0
            || slot.state != CoreCallSlotState::Active
            || slot.storage.is_some()
        {
            return Err(TrapCode::Validation);
        }
        let tag = CoreCallSlotTag {
            owner: slot.owner,
            instance: slot.instance,
            generation: slot.generation,
        };
        let call = self
            .instances
            .get(slot.instance)
            .and_then(|state| state.active_call.as_ref())
            .ok_or(TrapCode::Validation)?;
        if call.slot_tag != Some(tag) {
            return Err(TrapCode::Validation);
        }
        Ok(tag)
    }

    fn active_call_mut_tagged(
        &mut self,
        instance: usize,
        tag: Option<CoreCallSlotTag>,
    ) -> Result<&mut ActiveCall, TrapCode> {
        if self.state == ComponentGroupState::Poisoned {
            return Err(TrapCode::Validation);
        }
        let call = self
            .instances
            .get_mut(instance)
            .and_then(|state| state.active_call.as_mut())
            .ok_or(TrapCode::Validation)?;
        if call.slot_tag != tag {
            return Err(TrapCode::Validation);
        }
        Ok(call)
    }

    fn resume_host_call_tagged(
        &mut self,
        instance: usize,
        tag: Option<CoreCallSlotTag>,
        id: u32,
        results: &[CoreValue],
    ) -> Result<(), TrapCode> {
        if self.state == ComponentGroupState::Poisoned || self.store.data().pending_host.is_some() {
            return Err(TrapCode::Validation);
        }
        let call = self
            .instances
            .get_mut(instance)
            .and_then(|state| state.active_call.as_mut())
            .ok_or(TrapCode::Validation)?;
        if call.slot_tag != tag {
            return Err(TrapCode::Validation);
        }
        call.resume_host_call(&self.store, id, results)
    }

    fn debit_call_fuel_tagged(
        &mut self,
        instance: usize,
        tag: Option<CoreCallSlotTag>,
        amount: u64,
    ) -> Result<(), TrapCode> {
        self.active_call_mut_tagged(instance, tag)?
            .debit_external_fuel(amount)
    }

    fn credit_call_fuel_tagged(
        &mut self,
        instance: usize,
        tag: Option<CoreCallSlotTag>,
        amount: u64,
    ) -> Result<(), TrapCode> {
        self.active_call_mut_tagged(instance, tag)?
            .credit_external_fuel(amount)
    }

    fn cancel_call_tagged(
        &mut self,
        instance: usize,
        tag: Option<CoreCallSlotTag>,
    ) -> Result<(), TrapCode> {
        self.active_call_mut_tagged(instance, tag)?.cancelled = true;
        Ok(())
    }

    pub fn read_memory(
        &self,
        instance: usize,
        export: &str,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), TrapCode> {
        let authority = self.memory_authority(instance, export)?;
        self.read_authorized_memory(&authority, offset, output)
    }

    pub fn write_memory(
        &mut self,
        instance: usize,
        export: &str,
        offset: usize,
        input: &[u8],
    ) -> Result<(), TrapCode> {
        let authority = self.memory_authority(instance, export)?;
        self.write_authorized_memory(&authority, offset, input)
    }

    pub fn memory_size(&self, instance: usize, export: &str) -> Result<usize, TrapCode> {
        let authority = self.memory_authority(instance, export)?;
        self.authorized_memory_size(&authority)
    }

    pub fn grow_memory_to(
        &mut self,
        instance: usize,
        export: &str,
        minimum_bytes: usize,
    ) -> Result<(), TrapCode> {
        let authority = self.memory_authority(instance, export)?;
        self.grow_authorized_memory_to(&authority, minimum_bytes)
    }

    /// Resolves a Core memory export and issues an authority bound to this group.
    pub fn memory_authority(
        &self,
        instance: usize,
        export: &str,
    ) -> Result<CoreMemoryAuthority, TrapCode> {
        Ok(CoreMemoryAuthority {
            owner: self.reservation_owner,
            memory: self.memory(instance, export)?,
        })
    }

    /// Reads from the memory named by an authority issued by this group.
    pub fn read_authorized_memory(
        &self,
        authority: &CoreMemoryAuthority,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), TrapCode> {
        self.authorized_memory(authority)?
            .read(&self.store, offset, output)
            .map_err(|_| TrapCode::MemoryOutOfBounds)
    }

    /// Writes to the memory named by an authority issued by this group.
    pub fn write_authorized_memory(
        &mut self,
        authority: &CoreMemoryAuthority,
        offset: usize,
        input: &[u8],
    ) -> Result<(), TrapCode> {
        self.authorized_memory(authority)?
            .write(&mut self.store, offset, input)
            .map_err(|_| TrapCode::MemoryOutOfBounds)
    }

    /// Returns the current byte length of an authorized memory.
    pub fn authorized_memory_size(
        &self,
        authority: &CoreMemoryAuthority,
    ) -> Result<usize, TrapCode> {
        Ok(self.authorized_memory(authority)?.data_size(&self.store))
    }

    /// Grows an authorized memory to contain at least `minimum_bytes` bytes.
    pub fn grow_authorized_memory_to(
        &mut self,
        authority: &CoreMemoryAuthority,
        minimum_bytes: usize,
    ) -> Result<(), TrapCode> {
        let memory = self.authorized_memory(authority)?;
        let current = memory.data_size(&self.store);
        if minimum_bytes <= current {
            return Ok(());
        }
        let additional_pages = minimum_bytes
            .checked_sub(current)
            .and_then(|bytes| bytes.checked_add(65_535))
            .ok_or(TrapCode::MemoryOutOfBounds)?
            / 65_536;
        memory
            .grow(&mut self.store, additional_pages as u64)
            .map_err(|_| TrapCode::MemoryOutOfBounds)?;
        Ok(())
    }

    fn authorized_memory(&self, authority: &CoreMemoryAuthority) -> Result<Memory, TrapCode> {
        if self.state == ComponentGroupState::Poisoned || authority.owner != self.reservation_owner
        {
            return Err(TrapCode::Validation);
        }
        Ok(authority.memory)
    }

    fn memory(&self, instance: usize, export: &str) -> Result<Memory, TrapCode> {
        if self.state == ComponentGroupState::Poisoned {
            return Err(TrapCode::Validation);
        }
        self.instances
            .get(instance)
            .and_then(|instance| instance.instance.get_memory(&self.store, export))
            .ok_or(TrapCode::Validation)
    }
}

fn exact_group_export_type(expected: &ExternType, actual: &ExternType) -> bool {
    match (expected, actual) {
        (ExternType::Func(expected), ExternType::Func(actual)) => {
            expected == actual
                && expected
                    .params()
                    .iter()
                    .chain(expected.results())
                    .all(|ty| matches!(ty, ValType::I32 | ValType::I64))
        }
        (ExternType::Memory(expected), ExternType::Memory(actual)) => expected == actual,
        _ => false,
    }
}

fn allocation_error() -> AdmissionError {
    AdmissionError::validation(AdmissionDetail::AllocationReservation)
}

static NEXT_GROUP_RESERVATION_OWNER: AtomicU32 = AtomicU32::new(1);
static NEXT_CORE_CALL_SLOT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_HOST_CONTINUATION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_group_reservation_owner() -> Result<u32, AdmissionError> {
    NEXT_GROUP_RESERVATION_OWNER
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| allocation_error())
}

fn next_core_call_slot_generation() -> Result<u64, TrapCode> {
    NEXT_CORE_CALL_SLOT_GENERATION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| TrapCode::LimitExceeded)
}

fn next_host_continuation_generation() -> Result<u64, TrapCode> {
    NEXT_HOST_CONTINUATION_GENERATION
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| TrapCode::LimitExceeded)
}

fn restore_core_call_slot(slot: &mut CoreCallSlot, call: ActiveCall) -> bool {
    let expected = CoreCallSlotTag {
        owner: slot.owner,
        instance: slot.instance,
        generation: slot.generation,
    };
    if slot.state != CoreCallSlotState::Active
        || slot.storage.is_some()
        || call.slot_tag != Some(expected)
    {
        slot.state = CoreCallSlotState::Poisoned;
        slot.storage = None;
        return false;
    }
    let ActiveCall {
        function,
        inputs,
        outputs,
        result_values,
        ..
    } = call;
    slot.storage = Some(CoreCallStorage {
        function,
        inputs,
        outputs,
        result_values,
    });
    slot.state = CoreCallSlotState::Idle;
    true
}

struct ActiveCall {
    function: Func,
    inputs: Vec<Val>,
    outputs: Vec<Val>,
    /// Reserved before guest execution; terminal result materialization is
    /// allocation-free even after a host side effect has completed.
    result_values: Vec<CoreValue>,
    continuation: Option<ActiveContinuation>,
    remaining_fuel: u64,
    poll_quantum: u64,
    consumed_fuel: u64,
    /// Fuel explicitly charged by the embedding runtime and therefore
    /// eligible for a later credit if the pre-reserved work was unused.
    external_debit: u64,
    started: bool,
    cancelled: bool,
    slot_tag: Option<CoreCallSlotTag>,
    host_generation: Option<u64>,
    next_host_occurrence: u64,
}

enum ActiveContinuation {
    OutOfFuel(ResumableCallOutOfFuel),
    Host {
        invocation: ResumableCallHostTrap,
        evidence: CoreHostCallEvidence,
        origin_instance: usize,
        id: u32,
        response: Vec<Val>,
        response_ready: bool,
    },
}

enum ActivePollResult {
    Pending {
        consumed_fuel: u64,
        remaining_fuel: u64,
    },
    HostCall(CoreHostCall),
    Ready,
    Trapped(TrapCode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallMetrics {
    pub consumed_fuel: u64,
    pub remaining_fuel: u64,
}

impl ActiveCall {
    const fn metrics(&self) -> CallMetrics {
        CallMetrics {
            consumed_fuel: self.consumed_fuel,
            remaining_fuel: self.remaining_fuel,
        }
    }

    /// Atomically moves fuel from the executable balance into the externally
    /// charged balance. Every checked value is computed before state changes.
    fn debit_external_fuel(&mut self, amount: u64) -> Result<(), TrapCode> {
        let remaining_fuel = self
            .remaining_fuel
            .checked_sub(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        let consumed_fuel = self
            .consumed_fuel
            .checked_add(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        let external_debit = self
            .external_debit
            .checked_add(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        self.remaining_fuel = remaining_fuel;
        self.consumed_fuel = consumed_fuel;
        self.external_debit = external_debit;
        Ok(())
    }

    /// Atomically returns only fuel previously charged by the embedding.
    fn credit_external_fuel(&mut self, amount: u64) -> Result<(), TrapCode> {
        let remaining_fuel = self
            .remaining_fuel
            .checked_add(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        let consumed_fuel = self
            .consumed_fuel
            .checked_sub(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        let external_debit = self
            .external_debit
            .checked_sub(amount)
            .ok_or(TrapCode::FuelExhausted)?;
        self.remaining_fuel = remaining_fuel;
        self.consumed_fuel = consumed_fuel;
        self.external_debit = external_debit;
        Ok(())
    }

    fn validate_host_termination_event(
        &self,
        origin_instance: usize,
        id: u32,
        evidence: CoreHostCallEvidence,
    ) -> Result<(), TrapCode> {
        if self.cancelled {
            return Err(TrapCode::Cancelled);
        }
        let Some(ActiveContinuation::Host {
            invocation,
            evidence: expected_evidence,
            origin_instance: expected_origin_instance,
            id: expected_id,
            response_ready,
            ..
        }) = self.continuation.as_ref()
        else {
            return Err(TrapCode::Validation);
        };
        let marker = invocation
            .host_error()
            .downcast_ref::<HostBridgeError>()
            .ok_or(TrapCode::Validation)?;
        if marker != &(HostBridgeError::Yield { id: *expected_id })
            || id != *expected_id
            || origin_instance != *expected_origin_instance
            || evidence != *expected_evidence
            || *response_ready
        {
            return Err(TrapCode::Validation);
        }
        Ok(())
    }

    fn validate_host_termination_token(
        &self,
        token: &CoreHostTerminationToken,
    ) -> Result<(), TrapCode> {
        self.validate_host_termination_event(token.origin_instance, token.id, token.evidence)
    }

    fn resume_host_call(
        &mut self,
        store: &Store<HostState>,
        id: u32,
        results: &[CoreValue],
    ) -> Result<(), TrapCode> {
        if self.cancelled {
            return Err(TrapCode::Cancelled);
        }
        let Some(ActiveContinuation::Host {
            invocation,
            id: expected_id,
            response,
            response_ready,
            ..
        }) = self.continuation.as_mut()
        else {
            return Err(TrapCode::Validation);
        };
        let marker = invocation
            .host_error()
            .downcast_ref::<HostBridgeError>()
            .ok_or(TrapCode::Validation)?;
        if marker != &(HostBridgeError::Yield { id: *expected_id })
            || id != *expected_id
            || *response_ready
        {
            return Err(TrapCode::Validation);
        }
        let expected = invocation.host_func().ty(store);
        if !core_values_match(results, expected.results()) {
            return Err(TrapCode::Validation);
        }
        if response.len() != results.len() {
            return Err(TrapCode::Validation);
        }
        for (slot, value) in response.iter_mut().zip(results.iter().copied()) {
            *slot = value.into_wasmi();
        }
        *response_ready = true;
        Ok(())
    }

    fn poll(&mut self, store: &mut Store<HostState>) -> ActivePollResult {
        if self.cancelled {
            self.continuation = None;
            store.data_mut().pending_host = None;
            return ActivePollResult::Trapped(TrapCode::Cancelled);
        }
        if store.data().pending_host.is_some() {
            self.continuation = None;
            store.data_mut().pending_host = None;
            return ActivePollResult::Trapped(TrapCode::Validation);
        }
        if self.remaining_fuel == 0 {
            self.continuation = None;
            return ActivePollResult::Trapped(TrapCode::FuelExhausted);
        }

        let grant = min(self.remaining_fuel, self.poll_quantum);
        if store.set_fuel(grant).is_err() {
            return ActivePollResult::Trapped(TrapCode::FuelExhausted);
        }
        let call = if let Some(continuation) = self.continuation.take() {
            match continuation {
                ActiveContinuation::OutOfFuel(continuation) => {
                    if continuation.required_fuel() > grant {
                        return ActivePollResult::Trapped(
                            if continuation.required_fuel() > self.remaining_fuel {
                                TrapCode::FuelExhausted
                            } else {
                                TrapCode::LimitExceeded
                            },
                        );
                    }
                    continuation.resume(&mut *store, &mut self.outputs)
                }
                ActiveContinuation::Host {
                    invocation,
                    evidence: _,
                    origin_instance: _,
                    id,
                    response,
                    response_ready,
                } => {
                    let marker = invocation.host_error().downcast_ref::<HostBridgeError>();
                    if marker != Some(&HostBridgeError::Yield { id }) {
                        return ActivePollResult::Trapped(TrapCode::Validation);
                    }
                    if !response_ready {
                        return ActivePollResult::Trapped(TrapCode::Validation);
                    }
                    invocation.resume(&mut *store, &response, &mut self.outputs)
                }
            }
        } else if !self.started {
            self.started = true;
            self.function
                .call_resumable(&mut *store, &self.inputs, &mut self.outputs)
        } else {
            return ActivePollResult::Trapped(TrapCode::Validation);
        };

        let left = store.get_fuel().unwrap_or(0).min(grant);
        let used = grant - left;
        self.consumed_fuel = self.consumed_fuel.saturating_add(used);
        self.remaining_fuel = self.remaining_fuel.saturating_sub(used);
        match call {
            Ok(ResumableCall::Finished) => {
                self.result_values.clear();
                for value in &self.outputs {
                    let Some(value) = CoreValue::from_wasmi(value) else {
                        return ActivePollResult::Trapped(TrapCode::Validation);
                    };
                    debug_assert!(self.result_values.len() < self.result_values.capacity());
                    self.result_values.push(value);
                }
                ActivePollResult::Ready
            }
            Ok(ResumableCall::OutOfFuel(continuation)) => {
                if self.remaining_fuel == 0 {
                    ActivePollResult::Trapped(TrapCode::FuelExhausted)
                } else if continuation.required_fuel() > self.poll_quantum {
                    ActivePollResult::Trapped(TrapCode::LimitExceeded)
                } else {
                    self.continuation = Some(ActiveContinuation::OutOfFuel(continuation));
                    ActivePollResult::Pending {
                        consumed_fuel: self.consumed_fuel,
                        remaining_fuel: self.remaining_fuel,
                    }
                }
            }
            Ok(ResumableCall::HostTrap(invocation)) => self.suspend_host(store, invocation),
            Err(error) => {
                store.data_mut().pending_host = None;
                ActivePollResult::Trapped(map_wasmi_error(&error))
            }
        }
    }

    fn suspend_host(
        &mut self,
        store: &mut Store<HostState>,
        invocation: ResumableCallHostTrap,
    ) -> ActivePollResult {
        let marker_id = match invocation.host_error().downcast_ref::<HostBridgeError>() {
            Some(HostBridgeError::Yield { id }) => *id,
            _ => {
                store.data_mut().pending_host = None;
                return ActivePollResult::Trapped(TrapCode::Validation);
            }
        };
        let Some(mailbox) = store.data_mut().pending_host.take() else {
            return ActivePollResult::Trapped(TrapCode::Validation);
        };
        let host_type = invocation.host_func().ty(&*store);
        if marker_id != mailbox.id
            || !core_values_match(&mailbox.arguments, host_type.params())
            || host_type
                .results()
                .iter()
                .any(|ty| !matches!(ty, ValType::I32 | ValType::I64))
            || self.remaining_fuel == 0
        {
            return ActivePollResult::Trapped(if self.remaining_fuel == 0 {
                TrapCode::FuelExhausted
            } else {
                TrapCode::Validation
            });
        }
        let mut response = Vec::new();
        if response
            .try_reserve_exact(host_type.results().len())
            .is_err()
        {
            return ActivePollResult::Trapped(TrapCode::LimitExceeded);
        }
        response.extend(host_type.results().iter().copied().map(Val::default));
        let PendingHostCall {
            origin_instance,
            id,
            arguments,
        } = mailbox;
        let generation = match self.host_generation {
            Some(generation) => generation,
            None => match next_host_continuation_generation() {
                Ok(generation) => {
                    self.host_generation = Some(generation);
                    generation
                }
                Err(trap) => return ActivePollResult::Trapped(trap),
            },
        };
        let occurrence = self.next_host_occurrence;
        self.next_host_occurrence = match occurrence.checked_add(1) {
            Some(next) => next,
            None => return ActivePollResult::Trapped(TrapCode::LimitExceeded),
        };
        let evidence = CoreHostCallEvidence {
            generation,
            occurrence,
        };
        self.continuation = Some(ActiveContinuation::Host {
            invocation,
            evidence,
            origin_instance,
            id,
            response,
            response_ready: false,
        });
        ActivePollResult::HostCall(CoreHostCall {
            origin_instance,
            id,
            arguments,
            evidence: Some(evidence),
        })
    }
}

fn core_values_match(values: &[CoreValue], expected: &[ValType]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.value_type().into_wasmi() == *expected)
}

pub struct Invocation<'a> {
    instance: &'a mut CoreInstance,
    consumed_fuel: u64,
    remaining_fuel: u64,
    terminal: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PollResult {
    Pending {
        consumed_fuel: u64,
        remaining_fuel: u64,
    },
    HostCall(CoreHostCall),
    Ready(Vec<CoreValue>),
    Trapped(TrapCode),
}

/// Result of polling one exact reusable [`CoreCallSlot`].
///
/// The large inline ready variant is deliberate: boxing it would reintroduce
/// a fallible allocation at the terminal callback boundary.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum CoreSlotPollResult {
    Pending {
        consumed_fuel: u64,
        remaining_fuel: u64,
    },
    HostCall(CoreHostCall),
    Ready(CoreResults),
    Trapped(TrapCode),
}

impl Invocation<'_> {
    pub fn cancel(&mut self) {
        if !self.terminal {
            let _ = self.instance.cancel_call();
        }
    }

    pub const fn consumed_fuel(&self) -> u64 {
        self.consumed_fuel
    }

    pub const fn remaining_fuel(&self) -> u64 {
        self.remaining_fuel
    }

    pub fn resume_host_call(&mut self, id: u32, results: &[CoreValue]) -> Result<(), TrapCode> {
        if self.terminal {
            return Err(TrapCode::Validation);
        }
        self.instance.resume_host_call(id, results)
    }

    pub fn poll(&mut self) -> PollResult {
        if self.terminal {
            return PollResult::Trapped(TrapCode::Cancelled);
        }
        let result = self.instance.poll_call();
        if let Some(metrics) = self.instance.call_metrics() {
            self.consumed_fuel = metrics.consumed_fuel;
            self.remaining_fuel = metrics.remaining_fuel;
        }
        self.terminal = !matches!(result, PollResult::Pending { .. } | PollResult::HostCall(_));
        result
    }
}

impl Drop for Invocation<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            let _ = self.instance.discard_call();
        }
    }
}

pub fn map_wasmi_error(error: &WasmiError) -> TrapCode {
    use wasmi::TrapCode as W;
    match error.kind().as_trap_code() {
        Some(W::UnreachableCodeReached) => TrapCode::Unreachable,
        Some(W::IntegerDivisionByZero) => TrapCode::IntegerDivisionByZero,
        Some(W::IntegerOverflow) => TrapCode::IntegerOverflow,
        Some(W::MemoryOutOfBounds) => TrapCode::MemoryOutOfBounds,
        Some(W::TableOutOfBounds | W::IndirectCallToNull) => TrapCode::TableOutOfBounds,
        Some(W::BadSignature) => TrapCode::IndirectCallTypeMismatch,
        Some(W::StackOverflow) => TrapCode::CallDepthExceeded,
        Some(W::OutOfFuel) => TrapCode::FuelExhausted,
        Some(W::GrowthOperationLimited) => TrapCode::LimitExceeded,
        Some(W::BadConversionToInteger) | None => TrapCode::Validation,
    }
}
