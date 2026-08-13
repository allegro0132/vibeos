//! Bounded, portable Core WebAssembly execution for Vibe Component Profile 1.
//!
//! Untrusted bytes are counted before either `wasmparser::Validator` or wasmi
//! may reserve storage.  The wrapper exposes no imports and meters each call in
//! resumable quanta while retaining a separate, monotonic total-fuel account.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::min;
use vibeos_component_format::{LimitKind, ProfileLimits, TrapCode, PROFILE_1_LIMITS};
use wasmi::{
    CompilationMode, Config, EnforcedLimits, Engine, Error as WasmiError, Func, Instance, Linker,
    Memory, Module, ResumableCall, ResumableCallOutOfFuel, Store, StoreLimits, StoreLimitsBuilder,
    Val,
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

fn parser_features() -> WasmFeatures {
    WasmFeatures::empty()
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
    if bytes.len() > limits.max_core_module_bytes || bytes.len() > u32::MAX as usize {
        return Err(AdmissionError::limit(LimitKind::CoreModuleBytes));
    }
    let mut summary = CoreSummary {
        bytes: bytes.len() as u32,
        ..CoreSummary::default()
    };
    let mut saw_core = false;
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
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

    if Validator::new_with_features(parser_features())
        .validate_all(bytes)
        .is_err()
    {
        let broadly_valid = Validator::new_with_features(WasmFeatures::all())
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

fn build_engine() -> Engine {
    let mut config = Config::default();
    config
        .floats(false)
        .wasm_mutable_global(false)
        .wasm_sign_extension(false)
        .wasm_saturating_float_to_int(false)
        .wasm_multi_value(false)
        .wasm_multi_memory(false)
        .wasm_bulk_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_memory64(false)
        .wasm_wide_arithmetic(false)
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .set_max_recursion_depth(PROFILE_1_LIMITS.max_call_depth as usize)
        .set_min_stack_height(4 * 1024)
        .set_max_stack_height(128 * 1024)
        .set_max_cached_stacks(0)
        .enforced_limits(EnforcedLimits::strict());
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
}

impl ProfileEngine {
    pub fn new() -> Self {
        Self {
            inner: build_engine(),
        }
    }

    pub fn as_wasmi(&self) -> &Engine {
        &self.inner
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
        let limits = profile_store_limits(1);
        let mut store = Store::new(&self.engine, HostState { limits });
        store.limiter(|state| &mut state.limits);
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|error| AdmissionError {
                trap: map_wasmi_error(&error),
                detail: AdmissionDetail::Malformed,
            })?;
        Ok(CoreInstance { store, instance })
    }
}

pub fn profile_store_limits(instances: usize) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(PROFILE_1_LIMITS.max_memory_pages as usize * 65_536)
        .table_elements(PROFILE_1_LIMITS.max_table_elements as usize)
        .instances(instances)
        .tables(PROFILE_1_LIMITS.max_tables as usize)
        .memories(PROFILE_1_LIMITS.max_memories as usize)
        .trap_on_grow_failure(true)
        .build()
}

#[derive(Debug)]
struct HostState {
    limits: StoreLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreValue {
    I32(i32),
    I64(i64),
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
}

pub struct CoreInstance {
    store: Store<HostState>,
    instance: Instance,
}

impl CoreInstance {
    pub fn begin_call<'a>(
        &'a mut self,
        export: &str,
        inputs: &[CoreValue],
        total_fuel: u64,
        poll_quantum: u64,
    ) -> Result<Invocation<'a>, TrapCode> {
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
        let inputs = inputs.iter().copied().map(CoreValue::into_wasmi).collect();
        let outputs = ty.results().iter().copied().map(Val::default).collect();
        Ok(Invocation {
            instance: self,
            function,
            inputs,
            outputs,
            continuation: None,
            remaining_fuel: total_fuel,
            poll_quantum,
            consumed_fuel: 0,
            started: false,
            cancelled: false,
            terminal: false,
        })
    }

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

    fn memory(&self, export: &str) -> Result<Memory, TrapCode> {
        self.instance
            .get_memory(&self.store, export)
            .ok_or(TrapCode::Validation)
    }
}

pub struct Invocation<'a> {
    instance: &'a mut CoreInstance,
    function: Func,
    inputs: Vec<Val>,
    outputs: Vec<Val>,
    continuation: Option<ResumableCallOutOfFuel>,
    remaining_fuel: u64,
    poll_quantum: u64,
    consumed_fuel: u64,
    started: bool,
    cancelled: bool,
    terminal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollResult {
    Pending {
        consumed_fuel: u64,
        remaining_fuel: u64,
    },
    Ready(Vec<CoreValue>),
    Trapped(TrapCode),
}

impl Invocation<'_> {
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub const fn consumed_fuel(&self) -> u64 {
        self.consumed_fuel
    }

    pub const fn remaining_fuel(&self) -> u64 {
        self.remaining_fuel
    }

    pub fn poll(&mut self) -> PollResult {
        if self.terminal {
            return PollResult::Trapped(TrapCode::Cancelled);
        }
        if self.cancelled {
            self.continuation = None;
            self.terminal = true;
            return PollResult::Trapped(TrapCode::Cancelled);
        }
        if self.remaining_fuel == 0 {
            self.continuation = None;
            self.terminal = true;
            return PollResult::Trapped(TrapCode::FuelExhausted);
        }

        let grant = min(self.remaining_fuel, self.poll_quantum);
        if self.instance.store.set_fuel(grant).is_err() {
            self.terminal = true;
            return PollResult::Trapped(TrapCode::FuelExhausted);
        }
        let call = if let Some(continuation) = self.continuation.take() {
            if continuation.required_fuel() > grant {
                self.terminal = true;
                return PollResult::Trapped(
                    if continuation.required_fuel() > self.remaining_fuel {
                        TrapCode::FuelExhausted
                    } else {
                        TrapCode::LimitExceeded
                    },
                );
            }
            continuation.resume(&mut self.instance.store, &mut self.outputs)
        } else if !self.started {
            self.started = true;
            self.function
                .call_resumable(&mut self.instance.store, &self.inputs, &mut self.outputs)
        } else {
            self.terminal = true;
            return PollResult::Trapped(TrapCode::Validation);
        };

        let left = self.instance.store.get_fuel().unwrap_or(0).min(grant);
        let used = grant - left;
        self.consumed_fuel = self.consumed_fuel.saturating_add(used);
        self.remaining_fuel = self.remaining_fuel.saturating_sub(used);
        match call {
            Ok(ResumableCall::Finished) => {
                self.terminal = true;
                let mut values = Vec::with_capacity(self.outputs.len());
                for value in &self.outputs {
                    let Some(value) = CoreValue::from_wasmi(value) else {
                        return PollResult::Trapped(TrapCode::Validation);
                    };
                    values.push(value);
                }
                PollResult::Ready(values)
            }
            Ok(ResumableCall::OutOfFuel(continuation)) => {
                if self.remaining_fuel == 0 {
                    self.terminal = true;
                    PollResult::Trapped(TrapCode::FuelExhausted)
                } else if continuation.required_fuel() > self.poll_quantum {
                    self.terminal = true;
                    PollResult::Trapped(TrapCode::LimitExceeded)
                } else {
                    self.continuation = Some(continuation);
                    PollResult::Pending {
                        consumed_fuel: self.consumed_fuel,
                        remaining_fuel: self.remaining_fuel,
                    }
                }
            }
            Ok(ResumableCall::HostTrap(_)) => {
                self.terminal = true;
                PollResult::Trapped(TrapCode::Validation)
            }
            Err(error) => {
                self.terminal = true;
                PollResult::Trapped(map_wasmi_error(&error))
            }
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
