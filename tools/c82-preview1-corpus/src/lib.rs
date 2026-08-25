//! Host-only C8.2 sanitizer and Preview1 componentizer.
//!
//! Rust and C linkers emit one synthetic mutable `i32` stack-pointer global
//! even when the compiled program never uses a stack. This crate removes that
//! section only after proving that the module contains exactly one defined
//! global, that it is initialized to `65536`, and that no semantic section can
//! observe it. The resulting Core module must then match the closed C8.2
//! five-import contract and pass the production Profile-1 Core inspector before
//! it is wrapped with the exact C8.1 adapter.
//!
//! This crate has no guest executor, host linker, capability lookup, adapter
//! search path, environment fallback, or network integration.

#![forbid(unsafe_code)]

use std::{fmt, ops::Range, vec::Vec};

use vibeos_c81_preview1_componentizer::{
    derive_output_pins, ADAPTER_BYTES, ADAPTER_IMPORT_NAME, ADAPTER_SHA256,
};
pub use vibeos_c81_preview1_componentizer::{
    hex_sha256, sha256, EmbeddedCoreModulePin, OutputDirection, OutputKind, OutputPins,
    RawOuterEntryPin,
};
use wasmparser::{
    DataKind, ElementItems, ElementKind, Encoding, ExternalKind, Operator, OperatorsReader, Parser,
    Payload, TableInit, TypeRef, ValType, Validator, WasmFeatures,
};
use wit_component::ComponentEncoder;

const STACK_POINTER_VALUE: i32 = 65_536;
const EXPECTED_INITIAL_MEMORY_PAGES: u64 = 2;
const EXPECTED_MAXIMUM_MEMORY_PAGES: u64 = 16;
/// Maximum compiler-produced Core module size accepted by the C8.2 host tool.
///
/// The CLI uses this same ceiling before allocating or reading the input. The
/// library repeats the check so in-process callers cannot bypass it.
pub const MAX_COMPILER_CORE_BYTES: usize = 512 * 1024;

const EXPECTED_PREVIEW1_IMPORTS: [(&str, &[ValType], &[ValType]); 5] = [
    (
        "args_sizes_get",
        &[ValType::I32, ValType::I32],
        &[ValType::I32],
    ),
    ("args_get", &[ValType::I32, ValType::I32], &[ValType::I32]),
    (
        "fd_read",
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[ValType::I32],
    ),
    (
        "fd_write",
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[ValType::I32],
    ),
    ("proc_exit", &[ValType::I32], &[]),
];

const EXPECTED_COMPONENT_IMPORTS: [&str; 10] = [
    "wasi:cli/environment@0.2.12",
    "wasi:cli/exit@0.2.12",
    "wasi:cli/stderr@0.2.12",
    "wasi:cli/stdin@0.2.12",
    "wasi:cli/stdout@0.2.12",
    "wasi:clocks/wall-clock@0.2.12",
    "wasi:filesystem/preopens@0.2.12",
    "wasi:filesystem/types@0.2.12",
    "wasi:io/error@0.2.12",
    "wasi:io/streams@0.2.12",
];
const EXPECTED_COMPONENT_EXPORT: &str = "wasi:cli/run@0.2.12";
const EXPECTED_EMBEDDED_MODULES: u32 = 4;
const EXPECTED_NESTED_COMPONENTS: u32 = 1;
const EXPECTED_CANONICAL_LOWERS: u32 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformError {
    CoreTooLarge,
    MalformedCore,
    NotCoreModule,
    CustomSection,
    InvalidStackPointerProof,
    GlobalReference,
    SanitizedGuestContract,
    RuntimeCoreRejection,
    AdapterLength,
    AdapterDigest,
    Encoding,
    ComponentValidation,
    ComponentInspection,
    ComponentContract,
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CoreTooLarge => "compiler Core module exceeds the C8.2 byte bound",
            Self::MalformedCore => "compiler Core module is malformed",
            Self::NotCoreModule => "input is not exactly one Core WebAssembly module",
            Self::CustomSection => {
                "compiler Core module contains a custom section that could retain stale global metadata"
            }
            Self::InvalidStackPointerProof => {
                "compiler Core module does not contain exactly one private mutable i32 stack pointer initialized to 65536"
            }
            Self::GlobalReference => {
                "compiler Core module semantically references a global, so its global section cannot be removed"
            }
            Self::SanitizedGuestContract => {
                "sanitized Core module does not match the exact C8.2 five-import command contract"
            }
            Self::RuntimeCoreRejection => {
                "production Profile-1 Core inspection rejected the sanitized module"
            }
            Self::AdapterLength => "Preview1 adapter length does not match the reviewed C8.1 asset",
            Self::AdapterDigest => "Preview1 adapter digest does not match the reviewed C8.1 asset",
            Self::Encoding => "wit-component failed to encode the reviewed C8.2 composition",
            Self::ComponentValidation => "fresh validation rejected the encoded Component",
            Self::ComponentInspection => "encoded Component could not be inspected for exact pins",
            Self::ComponentContract => {
                "encoded Component does not match the exact adapter-derived C8.2 surface"
            }
        })
    }
}

impl std::error::Error for TransformError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SanitizationReport {
    pub compiler_core_bytes: usize,
    pub compiler_core_sha256: [u8; 32],
    pub removed_global_section_bytes: usize,
    pub stack_pointer_value: i32,
    pub global_references: u32,
    pub sanitized_core_bytes: usize,
    pub sanitized_core_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedCore {
    bytes: Vec<u8>,
    report: SanitizationReport,
}

impl SanitizedCore {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn report(&self) -> SanitizationReport {
        self.report
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformReport {
    pub sanitization: SanitizationReport,
    pub adapter_bytes: usize,
    pub adapter_sha256: [u8; 32],
    pub component_bytes: usize,
    pub component_sha256: [u8; 32],
    pub outer_imports: u32,
    pub outer_exports: u32,
    pub embedded_core_modules: u32,
    pub nested_components: u32,
    pub canonical_lowers: u32,
    pub runtime_ready: bool,
    pub guest_calls: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformedCorpusComponent {
    sanitized_core: SanitizedCore,
    component: Vec<u8>,
    pins: OutputPins,
    report: TransformReport,
}

impl TransformedCorpusComponent {
    pub fn sanitized_core(&self) -> &SanitizedCore {
        &self.sanitized_core
    }

    pub fn component_bytes(&self) -> &[u8] {
        &self.component
    }

    pub fn pins(&self) -> &OutputPins {
        &self.pins
    }

    pub const fn report(&self) -> TransformReport {
        self.report
    }

    pub fn into_parts(self) -> (SanitizedCore, Vec<u8>, OutputPins) {
        (self.sanitized_core, self.component, self.pins)
    }
}

#[derive(Default)]
struct StackPointerProof {
    saw_module: bool,
    global_sections: u32,
    defined_globals: u32,
    imported_globals: u32,
    exported_globals: u32,
    global_references: u32,
    exact_stack_pointer: bool,
}

fn is_global_reference(operator: &Operator<'_>) -> bool {
    matches!(
        operator,
        Operator::GlobalGet { .. }
            | Operator::GlobalSet { .. }
            | Operator::GlobalAtomicGet { .. }
            | Operator::GlobalAtomicSet { .. }
            | Operator::GlobalAtomicRmwAdd { .. }
            | Operator::GlobalAtomicRmwSub { .. }
            | Operator::GlobalAtomicRmwAnd { .. }
            | Operator::GlobalAtomicRmwOr { .. }
            | Operator::GlobalAtomicRmwXor { .. }
            | Operator::GlobalAtomicRmwXchg { .. }
            | Operator::GlobalAtomicRmwCmpxchg { .. }
    )
}

fn count_global_references(
    reader: OperatorsReader<'_>,
    references: &mut u32,
) -> Result<(), TransformError> {
    for operator in reader {
        let operator = operator.map_err(|_| TransformError::MalformedCore)?;
        if is_global_reference(&operator) {
            *references = references
                .checked_add(1)
                .ok_or(TransformError::InvalidStackPointerProof)?;
        }
    }
    Ok(())
}

fn exact_stack_pointer(global: &wasmparser::Global<'_>) -> Result<bool, TransformError> {
    if global.ty.content_type != ValType::I32 || !global.ty.mutable || global.ty.shared {
        return Ok(false);
    }
    let mut operators = global.init_expr.get_operators_reader();
    if !matches!(
        operators
            .read()
            .map_err(|_| TransformError::MalformedCore)?,
        Operator::I32Const {
            value: STACK_POINTER_VALUE
        }
    ) {
        return Ok(false);
    }
    if !matches!(
        operators
            .read()
            .map_err(|_| TransformError::MalformedCore)?,
        Operator::End
    ) || !operators.eof()
    {
        return Ok(false);
    }
    Ok(true)
}

fn prove_removable_stack_pointer(core: &[u8]) -> Result<StackPointerProof, TransformError> {
    let mut proof = StackPointerProof::default();
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
    for payload in parser.parse_all(core) {
        match payload.map_err(|_| TransformError::MalformedCore)? {
            Payload::Version { encoding, .. } => {
                if proof.saw_module || encoding != Encoding::Module {
                    return Err(TransformError::NotCoreModule);
                }
                proof.saw_module = true;
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|_| TransformError::MalformedCore)?;
                    if matches!(import.ty, TypeRef::Global(_)) {
                        proof.imported_globals = proof
                            .imported_globals
                            .checked_add(1)
                            .ok_or(TransformError::InvalidStackPointerProof)?;
                    }
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table.map_err(|_| TransformError::MalformedCore)?;
                    if let TableInit::Expr(expression) = table.init {
                        count_global_references(
                            expression.get_operators_reader(),
                            &mut proof.global_references,
                        )?;
                    }
                }
            }
            Payload::GlobalSection(reader) => {
                proof.global_sections = proof
                    .global_sections
                    .checked_add(1)
                    .ok_or(TransformError::InvalidStackPointerProof)?;
                proof.defined_globals = proof
                    .defined_globals
                    .checked_add(reader.count())
                    .ok_or(TransformError::InvalidStackPointerProof)?;
                for global in reader {
                    let global = global.map_err(|_| TransformError::MalformedCore)?;
                    count_global_references(
                        global.init_expr.get_operators_reader(),
                        &mut proof.global_references,
                    )?;
                    proof.exact_stack_pointer |= exact_stack_pointer(&global)?;
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|_| TransformError::MalformedCore)?;
                    if matches!(export.kind, ExternalKind::Global) {
                        proof.exported_globals = proof
                            .exported_globals
                            .checked_add(1)
                            .ok_or(TransformError::InvalidStackPointerProof)?;
                    }
                }
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    let element = element.map_err(|_| TransformError::MalformedCore)?;
                    if let ElementKind::Active { offset_expr, .. } = element.kind {
                        count_global_references(
                            offset_expr.get_operators_reader(),
                            &mut proof.global_references,
                        )?;
                    }
                    if let ElementItems::Expressions(_, expressions) = element.items {
                        for expression in expressions {
                            let expression =
                                expression.map_err(|_| TransformError::MalformedCore)?;
                            count_global_references(
                                expression.get_operators_reader(),
                                &mut proof.global_references,
                            )?;
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => count_global_references(
                body.get_operators_reader()
                    .map_err(|_| TransformError::MalformedCore)?,
                &mut proof.global_references,
            )?,
            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(|_| TransformError::MalformedCore)?;
                    if let DataKind::Active { offset_expr, .. } = data.kind {
                        count_global_references(
                            offset_expr.get_operators_reader(),
                            &mut proof.global_references,
                        )?;
                    }
                }
            }
            Payload::CustomSection(_) => return Err(TransformError::CustomSection),
            Payload::End(_) => {}
            _ => {}
        }
    }
    if !proof.saw_module {
        return Err(TransformError::NotCoreModule);
    }
    if proof.global_references != 0 {
        return Err(TransformError::GlobalReference);
    }
    if proof.global_sections != 1
        || proof.defined_globals != 1
        || proof.imported_globals != 0
        || proof.exported_globals != 0
        || !proof.exact_stack_pointer
    {
        return Err(TransformError::InvalidStackPointerProof);
    }
    Ok(proof)
}

fn read_u32_leb(bytes: &[u8], cursor: &mut usize) -> Result<u32, TransformError> {
    let mut value = 0_u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or(TransformError::MalformedCore)?;
        *cursor = cursor.checked_add(1).ok_or(TransformError::MalformedCore)?;
        if shift == 28 && byte & 0xf0 != 0 {
            return Err(TransformError::MalformedCore);
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(TransformError::MalformedCore)
}

fn raw_global_section_range(core: &[u8]) -> Result<Range<usize>, TransformError> {
    if core.get(..8) != Some(b"\0asm\x01\0\0\0") {
        return Err(TransformError::MalformedCore);
    }
    let mut cursor = 8_usize;
    let mut global = None;
    while cursor < core.len() {
        let start = cursor;
        let id = *core.get(cursor).ok_or(TransformError::MalformedCore)?;
        cursor = cursor.checked_add(1).ok_or(TransformError::MalformedCore)?;
        let payload_len = usize::try_from(read_u32_leb(core, &mut cursor)?)
            .map_err(|_| TransformError::MalformedCore)?;
        let end = cursor
            .checked_add(payload_len)
            .filter(|end| *end <= core.len())
            .ok_or(TransformError::MalformedCore)?;
        if id == 6 && global.replace(start..end).is_some() {
            return Err(TransformError::InvalidStackPointerProof);
        }
        cursor = end;
    }
    if cursor != core.len() {
        return Err(TransformError::MalformedCore);
    }
    global.ok_or(TransformError::InvalidStackPointerProof)
}

fn remove_section(core: &[u8], range: Range<usize>) -> Result<Vec<u8>, TransformError> {
    if range.start < 8 || range.start >= range.end || range.end > core.len() {
        return Err(TransformError::MalformedCore);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(core.len() - range.len())
        .map_err(|_| TransformError::CoreTooLarge)?;
    result.extend_from_slice(&core[..range.start]);
    result.extend_from_slice(&core[range.end..]);
    Ok(result)
}

fn expected_import(name: &str) -> Option<usize> {
    EXPECTED_PREVIEW1_IMPORTS
        .iter()
        .position(|expected| expected.0 == name)
}

fn validate_sanitized_guest(core: &[u8]) -> Result<(), TransformError> {
    let mut types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
    let mut function_type_indices = Vec::new();
    let mut seen_imports = [false; EXPECTED_PREVIEW1_IMPORTS.len()];
    let mut import_count = 0_u32;
    let mut memory_count = 0_u32;
    let mut export_count = 0_u32;
    let mut start_export = None;
    let mut memory_export = None;
    let mut saw_module = false;

    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
    for payload in parser.parse_all(core) {
        match payload.map_err(|_| TransformError::SanitizedGuestContract)? {
            Payload::Version { encoding, .. } => {
                if saw_module || encoding != Encoding::Module {
                    return Err(TransformError::SanitizedGuestContract);
                }
                saw_module = true;
            }
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| TransformError::SanitizedGuestContract)?;
                    types.push((ty.params().to_vec(), ty.results().to_vec()));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|_| TransformError::SanitizedGuestContract)?;
                    import_count = import_count
                        .checked_add(1)
                        .ok_or(TransformError::SanitizedGuestContract)?;
                    if import.module != ADAPTER_IMPORT_NAME {
                        return Err(TransformError::SanitizedGuestContract);
                    }
                    let TypeRef::Func(type_index) = import.ty else {
                        return Err(TransformError::SanitizedGuestContract);
                    };
                    let signature = types
                        .get(type_index as usize)
                        .ok_or(TransformError::SanitizedGuestContract)?;
                    let expected_index = expected_import(import.name)
                        .ok_or(TransformError::SanitizedGuestContract)?;
                    let expected = EXPECTED_PREVIEW1_IMPORTS[expected_index];
                    if seen_imports[expected_index]
                        || signature.0.as_slice() != expected.1
                        || signature.1.as_slice() != expected.2
                    {
                        return Err(TransformError::SanitizedGuestContract);
                    }
                    seen_imports[expected_index] = true;
                    function_type_indices.push(type_index);
                }
            }
            Payload::FunctionSection(reader) => {
                for type_index in reader {
                    function_type_indices
                        .push(type_index.map_err(|_| TransformError::SanitizedGuestContract)?);
                }
            }
            Payload::TableSection(_)
            | Payload::GlobalSection(_)
            | Payload::TagSection(_)
            | Payload::StartSection { .. }
            | Payload::UnknownSection { .. }
            | Payload::CustomSection(_) => return Err(TransformError::SanitizedGuestContract),
            Payload::MemorySection(reader) => {
                memory_count = memory_count
                    .checked_add(reader.count())
                    .ok_or(TransformError::SanitizedGuestContract)?;
                for memory in reader {
                    let memory = memory.map_err(|_| TransformError::SanitizedGuestContract)?;
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.initial != EXPECTED_INITIAL_MEMORY_PAGES
                        || memory.maximum != Some(EXPECTED_MAXIMUM_MEMORY_PAGES)
                    {
                        return Err(TransformError::SanitizedGuestContract);
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|_| TransformError::SanitizedGuestContract)?;
                    export_count = export_count
                        .checked_add(1)
                        .ok_or(TransformError::SanitizedGuestContract)?;
                    match (export.name, export.kind) {
                        ("memory", ExternalKind::Memory) if export.index == 0 => {
                            if memory_export.replace(export.index).is_some() {
                                return Err(TransformError::SanitizedGuestContract);
                            }
                        }
                        ("_start", ExternalKind::Func) => {
                            if start_export.replace(export.index).is_some() {
                                return Err(TransformError::SanitizedGuestContract);
                            }
                        }
                        _ => return Err(TransformError::SanitizedGuestContract),
                    }
                }
            }
            Payload::End(_) => {}
            _ => {}
        }
    }

    if !saw_module
        || import_count != EXPECTED_PREVIEW1_IMPORTS.len() as u32
        || seen_imports.iter().any(|seen| !seen)
        || memory_count != 1
        || export_count != 2
        || memory_export != Some(0)
    {
        return Err(TransformError::SanitizedGuestContract);
    }
    let start_index = start_export.ok_or(TransformError::SanitizedGuestContract)?;
    let type_index = *function_type_indices
        .get(start_index as usize)
        .ok_or(TransformError::SanitizedGuestContract)?;
    let signature = types
        .get(type_index as usize)
        .ok_or(TransformError::SanitizedGuestContract)?;
    if !signature.0.is_empty() || !signature.1.is_empty() {
        return Err(TransformError::SanitizedGuestContract);
    }
    Ok(())
}

/// Prove that the compiler-only stack pointer is unobservable, remove its
/// complete raw section, and freshly validate the exact sanitized guest.
pub fn sanitize_compiler_core(core: &[u8]) -> Result<SanitizedCore, TransformError> {
    if core.len() > MAX_COMPILER_CORE_BYTES {
        return Err(TransformError::CoreTooLarge);
    }
    let proof = prove_removable_stack_pointer(core)?;
    let global_range = raw_global_section_range(core)?;
    let removed_global_section_bytes = global_range.len();
    let sanitized = remove_section(core, global_range)?;
    vibeos_wasm_runtime::inspect_core(&sanitized)
        .map_err(|_| TransformError::RuntimeCoreRejection)?;
    // The production inspector performs its allocation-light count/type
    // predecode before validating `sanitized`. Only after that bounded pass is
    // it safe to ask the broad validator to prove that the original module,
    // including the one tiny global section, was itself well formed.
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(core)
        .map_err(|_| TransformError::MalformedCore)?;
    validate_sanitized_guest(&sanitized)?;

    let report = SanitizationReport {
        compiler_core_bytes: core.len(),
        compiler_core_sha256: sha256(core),
        removed_global_section_bytes,
        stack_pointer_value: STACK_POINTER_VALUE,
        global_references: proof.global_references,
        sanitized_core_bytes: sanitized.len(),
        sanitized_core_sha256: sha256(&sanitized),
    };
    Ok(SanitizedCore {
        bytes: sanitized,
        report,
    })
}

fn component_shape(component: &[u8]) -> Result<(u32, u32), TransformError> {
    let mut modules = 0_u32;
    let mut components = 0_u32;
    for payload in Parser::new(0).parse_all(component) {
        match payload.map_err(|_| TransformError::ComponentInspection)? {
            Payload::ModuleSection { .. } => {
                modules = modules
                    .checked_add(1)
                    .ok_or(TransformError::ComponentInspection)?;
            }
            Payload::ComponentSection { .. } => {
                components = components
                    .checked_add(1)
                    .ok_or(TransformError::ComponentInspection)?;
            }
            _ => {}
        }
    }
    Ok((modules, components))
}

fn validate_component_contract(
    pins: &OutputPins,
    modules: u32,
    components: u32,
) -> Result<(), TransformError> {
    if modules != EXPECTED_EMBEDDED_MODULES
        || components != EXPECTED_NESTED_COMPONENTS
        || pins.embedded_core_modules.len() != EXPECTED_EMBEDDED_MODULES as usize
        || pins.canonical_lowers != EXPECTED_CANONICAL_LOWERS
        || pins.entries.len() != EXPECTED_COMPONENT_IMPORTS.len() + 1
    {
        return Err(TransformError::ComponentContract);
    }
    for (entry, name) in pins
        .entries
        .iter()
        .take(EXPECTED_COMPONENT_IMPORTS.len())
        .zip(EXPECTED_COMPONENT_IMPORTS)
    {
        if entry.direction != OutputDirection::Import
            || entry.kind != OutputKind::Instance
            || entry.name != name
        {
            return Err(TransformError::ComponentContract);
        }
    }
    let export = pins
        .entries
        .last()
        .ok_or(TransformError::ComponentContract)?;
    if export.direction != OutputDirection::Export
        || export.kind != OutputKind::Instance
        || export.name != EXPECTED_COMPONENT_EXPORT
    {
        return Err(TransformError::ComponentContract);
    }
    Ok(())
}

/// Sanitize one compiler-produced Core module and wrap it with the exact C8.1
/// adapter. The returned bytes and pins are inert host evidence only.
pub fn componentize_corpus_core(
    compiler_core: &[u8],
    adapter: &[u8],
) -> Result<TransformedCorpusComponent, TransformError> {
    let sanitized_core = sanitize_compiler_core(compiler_core)?;
    if adapter.len() != ADAPTER_BYTES {
        return Err(TransformError::AdapterLength);
    }
    let adapter_sha256 = sha256(adapter);
    if adapter_sha256 != ADAPTER_SHA256 {
        return Err(TransformError::AdapterDigest);
    }
    let component = ComponentEncoder::default()
        .module(sanitized_core.bytes())
        .map_err(|_| TransformError::Encoding)?
        .adapter(ADAPTER_IMPORT_NAME, adapter)
        .map_err(|_| TransformError::Encoding)?
        .validate(true)
        .encode()
        .map_err(|_| TransformError::Encoding)?;
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&component)
        .map_err(|_| TransformError::ComponentValidation)?;
    let pins = derive_output_pins(&component).map_err(|_| TransformError::ComponentInspection)?;
    let (embedded_core_modules, nested_components) = component_shape(&component)?;
    validate_component_contract(&pins, embedded_core_modules, nested_components)?;
    if pins
        .embedded_core_modules
        .first()
        .is_none_or(|module| module.raw_sha256 != sanitized_core.report().sanitized_core_sha256)
    {
        return Err(TransformError::ComponentContract);
    }

    let outer_imports = pins
        .entries
        .iter()
        .filter(|entry| entry.direction == OutputDirection::Import)
        .count() as u32;
    let outer_exports = pins
        .entries
        .iter()
        .filter(|entry| entry.direction == OutputDirection::Export)
        .count() as u32;
    let report = TransformReport {
        sanitization: sanitized_core.report(),
        adapter_bytes: adapter.len(),
        adapter_sha256,
        component_bytes: component.len(),
        component_sha256: sha256(&component),
        outer_imports,
        outer_exports,
        embedded_core_modules,
        nested_components,
        canonical_lowers: pins.canonical_lowers,
        runtime_ready: false,
        guest_calls: 0,
    };
    Ok(TransformedCorpusComponent {
        sanitized_core,
        component,
        pins,
        report,
    })
}
