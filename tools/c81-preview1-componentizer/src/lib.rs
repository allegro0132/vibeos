//! Host-only C8.1 transformer for one closed WASIp1 command shape.
//!
//! This crate validates bytes and constructs inert Component bytes. It has no
//! guest executor, host linker, capability lookup, adapter search path, or
//! network integration.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{fmt, vec::Vec};
use wasmparser::{
    CanonicalFunction, ComponentExternalKind, ComponentTypeRef, Encoding, ExternalKind, Operator,
    Parser, Payload, TypeRef, ValType, Validator, WasmFeatures,
};
use wit_component::ComponentEncoder;

pub const ADAPTER_IMPORT_NAME: &str = "wasi_snapshot_preview1";
pub const ADAPTER_RELEASE: &str = "wasmtime-v48.0.0";
pub const ADAPTER_REVISION: &str =
    "wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm";
pub const ADAPTER_TARGET_WASI: &str = "wasi-0.2.12";
pub const ADAPTER_BYTES: usize = 51_828;
pub const ADAPTER_SHA256: [u8; 32] = [
    0x31, 0x6d, 0xfb, 0xf1, 0x71, 0x59, 0x1d, 0x69, 0xae, 0x41, 0x4e, 0xfd, 0x13, 0xb8, 0x59, 0x33,
    0xca, 0x13, 0x52, 0x6a, 0xf8, 0xd9, 0xe0, 0xa7, 0x35, 0xab, 0x88, 0xae, 0x08, 0xfd, 0x85, 0xf0,
];

pub const FIXTURE_CORE_BYTES: usize = 145;
pub const FIXTURE_CORE_SHA256: [u8; 32] = [
    0x5a, 0xc1, 0xeb, 0x14, 0x87, 0x47, 0x21, 0xc8, 0x35, 0x56, 0x69, 0xfd, 0x91, 0x81, 0x1f, 0x9a,
    0x01, 0x65, 0xd9, 0x6f, 0x13, 0x82, 0xff, 0x82, 0xf0, 0x8f, 0x3d, 0xfc, 0x06, 0x34, 0xbb, 0x0c,
];
pub const FIXTURE_COMPONENT_BYTES: usize = 17_495;
pub const FIXTURE_COMPONENT_SHA256: [u8; 32] = [
    0xb9, 0x10, 0xb4, 0x42, 0x8e, 0x9f, 0xf4, 0x42, 0x64, 0x9f, 0x36, 0xa5, 0x97, 0x07, 0x37, 0x3a,
    0x34, 0xd7, 0x3f, 0x50, 0xf1, 0x1f, 0xc1, 0xae, 0x12, 0x66, 0xcd, 0x9f, 0x19, 0xe9, 0xf4, 0x8e,
];
pub const CANONICAL_LOWERING_DOMAIN: &[u8] = b"vibeos.preview1-wrapped.canonical-lowerings.v1\0";

const MAX_CORE_BYTES: usize = 512 * 1024;
const MAX_TYPES: u32 = 1024;
const MAX_FUNCTIONS: u32 = 1024;
const MAX_PARAMS: usize = 32;
const MAX_RESULTS: usize = 32;
const MAX_INITIAL_MEMORY_PAGES: u64 = 16;
const MAX_MEMORY_PAGES: u64 = 256;
const MAX_TABLES: u32 = 1;
const MAX_GLOBALS: u32 = 256;
const MAX_LOCALS: u32 = 4096;
const MAX_CONTROL_DEPTH: u32 = 128;
const MAX_CUSTOM_SECTIONS: u32 = 1;
const MAX_CUSTOM_SECTION_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformError {
    CoreTooLarge,
    MalformedCore,
    UnsupportedCoreFeature,
    GuestContract,
    AdapterLength,
    AdapterDigest,
    Encoding,
    ComponentValidation,
    ComponentInspection,
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CoreTooLarge => "Core module exceeds the C8.1 byte bound",
            Self::MalformedCore => "Core module is malformed",
            Self::UnsupportedCoreFeature => "Core module uses a feature outside C8.1",
            Self::GuestContract => "Core module does not match the exact C8.1 guest contract",
            Self::AdapterLength => "Preview1 adapter length does not match the reviewed asset",
            Self::AdapterDigest => "Preview1 adapter digest does not match the reviewed asset",
            Self::Encoding => "wit-component failed to encode the reviewed composition",
            Self::ComponentValidation => "fresh validation rejected the encoded Component",
            Self::ComponentInspection => "encoded Component could not be counted",
        })
    }
}

impl std::error::Error for TransformError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransformReport {
    pub core_bytes: usize,
    pub core_sha256: [u8; 32],
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OutputDirection {
    Import = 0,
    Export = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OutputKind {
    Module = 0,
    Function = 1,
    Value = 2,
    Type = 3,
    Component = 4,
    Instance = 5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawOuterEntryPin {
    pub direction: OutputDirection,
    pub kind: OutputKind,
    pub name: String,
    pub raw_bytes: usize,
    pub raw_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedCoreModulePin {
    pub ordinal: u32,
    pub raw_bytes: usize,
    pub raw_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputPins {
    pub entries: Vec<RawOuterEntryPin>,
    pub embedded_core_modules: Vec<EmbeddedCoreModulePin>,
    pub canonical_lowers: u32,
    pub canonical_lowering_sha256: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub struct TransformedComponent {
    bytes: Vec<u8>,
    report: TransformReport,
}

impl TransformedComponent {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn report(&self) -> TransformReport {
        self.report
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Default)]
struct CoreInspection {
    types: Vec<(Vec<ValType>, Vec<ValType>)>,
    function_types: Vec<u32>,
    imports: u32,
    exports: u32,
    memories: u32,
    tables: u32,
    globals: u32,
    data_segments: u32,
    element_segments: u32,
    custom_sections: u32,
    custom_section_bytes: usize,
    defined_functions: u32,
    code_bodies: u32,
    start_function: Option<u32>,
    memory_export: Option<u32>,
    saw_start_section: bool,
    saw_module: bool,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn hex_sha256(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn checked_add(value: &mut u32, amount: u32, maximum: u32) -> Result<(), TransformError> {
    let next = value
        .checked_add(amount)
        .ok_or(TransformError::GuestContract)?;
    if next > maximum {
        return Err(TransformError::GuestContract);
    }
    *value = next;
    Ok(())
}

fn validate_memory(memory: wasmparser::MemoryType) -> Result<(), TransformError> {
    if memory.memory64 || memory.shared || memory.page_size_log2.is_some() {
        return Err(TransformError::UnsupportedCoreFeature);
    }
    if memory.initial > MAX_INITIAL_MEMORY_PAGES {
        return Err(TransformError::GuestContract);
    }
    let maximum = memory.maximum.ok_or(TransformError::GuestContract)?;
    if maximum > MAX_MEMORY_PAGES || memory.initial > maximum {
        return Err(TransformError::GuestContract);
    }
    Ok(())
}

fn inspect_core(core: &[u8]) -> Result<CoreInspection, TransformError> {
    if core.len() > MAX_CORE_BYTES {
        return Err(TransformError::CoreTooLarge);
    }

    Validator::new_with_features(WasmFeatures::all())
        .validate_all(core)
        .map_err(|_| TransformError::MalformedCore)?;

    let mut inspection = CoreInspection::default();
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
    for payload in parser.parse_all(core) {
        let payload = payload.map_err(|_| TransformError::MalformedCore)?;
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module || inspection.saw_module {
                    return Err(TransformError::GuestContract);
                }
                inspection.saw_module = true;
            }
            Payload::TypeSection(reader) => {
                if reader.count() > MAX_TYPES {
                    return Err(TransformError::GuestContract);
                }
                inspection
                    .types
                    .try_reserve_exact(reader.count() as usize)
                    .map_err(|_| TransformError::GuestContract)?;
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| TransformError::UnsupportedCoreFeature)?;
                    if ty.params().len() > MAX_PARAMS || ty.results().len() > MAX_RESULTS {
                        return Err(TransformError::GuestContract);
                    }
                    inspection
                        .types
                        .push((ty.params().to_vec(), ty.results().to_vec()));
                }
            }
            Payload::ImportSection(reader) => {
                checked_add(&mut inspection.imports, reader.count(), 1)?;
                for import in reader.into_imports() {
                    let import = import.map_err(|_| TransformError::MalformedCore)?;
                    if import.module != ADAPTER_IMPORT_NAME || import.name != "fd_write" {
                        return Err(TransformError::GuestContract);
                    }
                    let TypeRef::Func(type_index) = import.ty else {
                        return Err(TransformError::GuestContract);
                    };
                    inspection.function_types.push(type_index);
                }
            }
            Payload::FunctionSection(reader) => {
                let defined = reader.count();
                checked_add(&mut inspection.defined_functions, defined, 1)?;
                let total = u32::try_from(inspection.function_types.len())
                    .ok()
                    .and_then(|current| current.checked_add(defined))
                    .ok_or(TransformError::GuestContract)?;
                if total > MAX_FUNCTIONS {
                    return Err(TransformError::GuestContract);
                }
                inspection
                    .function_types
                    .try_reserve_exact(defined as usize)
                    .map_err(|_| TransformError::GuestContract)?;
                for index in reader {
                    inspection
                        .function_types
                        .push(index.map_err(|_| TransformError::MalformedCore)?);
                }
            }
            Payload::MemorySection(reader) => {
                checked_add(&mut inspection.memories, reader.count(), 1)?;
                for memory in reader {
                    validate_memory(memory.map_err(|_| TransformError::MalformedCore)?)?;
                }
            }
            Payload::TableSection(reader) => {
                checked_add(&mut inspection.tables, reader.count(), MAX_TABLES)?;
                if reader.count() != 0 {
                    return Err(TransformError::GuestContract);
                }
            }
            Payload::GlobalSection(reader) => {
                checked_add(&mut inspection.globals, reader.count(), MAX_GLOBALS)?;
                if reader.count() != 0 {
                    return Err(TransformError::GuestContract);
                }
                for global in reader {
                    let global = global.map_err(|_| TransformError::MalformedCore)?;
                    if global.ty.mutable || global.ty.shared {
                        return Err(TransformError::UnsupportedCoreFeature);
                    }
                }
            }
            Payload::TagSection(_) => return Err(TransformError::UnsupportedCoreFeature),
            Payload::ExportSection(reader) => {
                checked_add(&mut inspection.exports, reader.count(), 2)?;
                for export in reader {
                    let export = export.map_err(|_| TransformError::MalformedCore)?;
                    match (export.name, export.kind) {
                        ("memory", ExternalKind::Memory) => {
                            if inspection.memory_export.replace(export.index).is_some() {
                                return Err(TransformError::GuestContract);
                            }
                        }
                        ("_start", ExternalKind::Func) => {
                            if inspection.start_function.replace(export.index).is_some() {
                                return Err(TransformError::GuestContract);
                            }
                        }
                        _ => return Err(TransformError::GuestContract),
                    }
                }
            }
            Payload::StartSection { .. } => inspection.saw_start_section = true,
            Payload::ElementSection(reader) => {
                checked_add(&mut inspection.element_segments, reader.count(), 0)?
            }
            Payload::DataCountSection { .. } => return Err(TransformError::GuestContract),
            Payload::DataSection(reader) => {
                checked_add(&mut inspection.data_segments, reader.count(), 0)?
            }
            Payload::CodeSectionStart { count, .. } => {
                checked_add(&mut inspection.code_bodies, count, 1)?;
            }
            Payload::CodeSectionEntry(body) => {
                let mut locals = 0_u32;
                for local in body
                    .get_locals_reader()
                    .map_err(|_| TransformError::MalformedCore)?
                {
                    let (amount, _) = local.map_err(|_| TransformError::MalformedCore)?;
                    checked_add(&mut locals, amount, MAX_LOCALS)?;
                }
                let mut depth = 0_u32;
                for operator in body
                    .get_operators_reader()
                    .map_err(|_| TransformError::MalformedCore)?
                {
                    match operator.map_err(|_| TransformError::MalformedCore)? {
                        Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                            depth = depth.checked_add(1).ok_or(TransformError::GuestContract)?;
                            if depth > MAX_CONTROL_DEPTH {
                                return Err(TransformError::GuestContract);
                            }
                        }
                        Operator::End => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
            }
            Payload::CustomSection(reader) => {
                checked_add(&mut inspection.custom_sections, 1, MAX_CUSTOM_SECTIONS)?;
                if reader.name() != "name" {
                    return Err(TransformError::GuestContract);
                }
                inspection.custom_section_bytes = inspection
                    .custom_section_bytes
                    .checked_add(reader.range().len())
                    .ok_or(TransformError::GuestContract)?;
                if inspection.custom_section_bytes > MAX_CUSTOM_SECTION_BYTES {
                    return Err(TransformError::GuestContract);
                }
            }
            Payload::UnknownSection { .. } => return Err(TransformError::UnsupportedCoreFeature),
            Payload::End(_) => {}
            _ => return Err(TransformError::UnsupportedCoreFeature),
        }
    }

    Validator::new_with_features(WasmFeatures::empty())
        .validate_all(core)
        .map_err(|_| TransformError::UnsupportedCoreFeature)?;

    if !inspection.saw_module
        || inspection.imports != 1
        || inspection.exports != 2
        || inspection.memories != 1
        || inspection.types.len() != 2
        || inspection.function_types.len() != 2
        || inspection.defined_functions != 1
        || inspection.code_bodies != 1
        || inspection.tables != 0
        || inspection.globals != 0
        || inspection.data_segments != 0
        || inspection.element_segments != 0
        || inspection.custom_sections > 1
        || inspection.saw_start_section
        || inspection.memory_export != Some(0)
    {
        return Err(TransformError::GuestContract);
    }

    let fd_write_type_index = *inspection
        .function_types
        .first()
        .ok_or(TransformError::GuestContract)?;
    let fd_write = inspection
        .types
        .get(fd_write_type_index as usize)
        .ok_or(TransformError::GuestContract)?;
    if fd_write.0.as_slice() != [ValType::I32; 4] || fd_write.1.as_slice() != [ValType::I32] {
        return Err(TransformError::GuestContract);
    }

    let start_function = inspection
        .start_function
        .ok_or(TransformError::GuestContract)?;
    if start_function == 0 {
        return Err(TransformError::GuestContract);
    }
    let start_type_index = *inspection
        .function_types
        .get(start_function as usize)
        .ok_or(TransformError::GuestContract)?;
    let start = inspection
        .types
        .get(start_type_index as usize)
        .ok_or(TransformError::GuestContract)?;
    if !start.0.is_empty() || !start.1.is_empty() {
        return Err(TransformError::GuestContract);
    }
    Ok(inspection)
}

fn import_kind(reference: ComponentTypeRef) -> OutputKind {
    match reference {
        ComponentTypeRef::Module(_) => OutputKind::Module,
        ComponentTypeRef::Func(_) => OutputKind::Function,
        ComponentTypeRef::Value(_) => OutputKind::Value,
        ComponentTypeRef::Type(_) => OutputKind::Type,
        ComponentTypeRef::Component(_) => OutputKind::Component,
        ComponentTypeRef::Instance(_) => OutputKind::Instance,
    }
}

fn export_kind(kind: ComponentExternalKind) -> OutputKind {
    match kind {
        ComponentExternalKind::Module => OutputKind::Module,
        ComponentExternalKind::Func => OutputKind::Function,
        ComponentExternalKind::Value => OutputKind::Value,
        ComponentExternalKind::Type => OutputKind::Type,
        ComponentExternalKind::Component => OutputKind::Component,
        ComponentExternalKind::Instance => OutputKind::Instance,
    }
}

/// Independently derive the exact raw outer-entry and Canonical-lowering pins
/// consumed by the reviewed admission policy. Entry hashes cover only the raw
/// entry bytes, excluding their section id, section length, and vector count.
pub fn derive_output_pins(component: &[u8]) -> Result<OutputPins, TransformError> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(component)
        .map_err(|_| TransformError::ComponentValidation)?;

    let mut entries = Vec::new();
    let mut embedded_core_modules = Vec::new();
    let mut lower_entries = Vec::<Vec<u8>>::new();
    let mut depth = 0_u32;
    for payload in Parser::new(0).parse_all(component) {
        match payload.map_err(|_| TransformError::ComponentInspection)? {
            Payload::ComponentImportSection(reader) if depth == 0 => {
                let end = reader.range().end;
                let parsed = reader
                    .into_iter_with_offsets()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransformError::ComponentInspection)?;
                for (index, (offset, import)) in parsed.iter().enumerate() {
                    let item_end = parsed.get(index + 1).map_or(end, |(next, _)| *next);
                    let raw = component
                        .get(*offset..item_end)
                        .ok_or(TransformError::ComponentInspection)?;
                    entries.push(RawOuterEntryPin {
                        direction: OutputDirection::Import,
                        kind: import_kind(import.ty),
                        name: import.name.name.to_owned(),
                        raw_bytes: raw.len(),
                        raw_sha256: sha256(raw),
                    });
                }
            }
            Payload::ComponentExportSection(reader) if depth == 0 => {
                let end = reader.range().end;
                let parsed = reader
                    .into_iter_with_offsets()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransformError::ComponentInspection)?;
                for (index, (offset, export)) in parsed.iter().enumerate() {
                    let item_end = parsed.get(index + 1).map_or(end, |(next, _)| *next);
                    let raw = component
                        .get(*offset..item_end)
                        .ok_or(TransformError::ComponentInspection)?;
                    entries.push(RawOuterEntryPin {
                        direction: OutputDirection::Export,
                        kind: export_kind(export.kind),
                        name: export.name.name.to_owned(),
                        raw_bytes: raw.len(),
                        raw_sha256: sha256(raw),
                    });
                }
            }
            Payload::ComponentCanonicalSection(reader) if depth == 0 => {
                let end = reader.range().end;
                let parsed = reader
                    .into_iter_with_offsets()
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransformError::ComponentInspection)?;
                for (index, (offset, function)) in parsed.iter().enumerate() {
                    if matches!(function, CanonicalFunction::Lower { .. }) {
                        let item_end = parsed.get(index + 1).map_or(end, |(next, _)| *next);
                        let raw = component
                            .get(*offset..item_end)
                            .ok_or(TransformError::ComponentInspection)?;
                        lower_entries.push(raw.to_vec());
                    }
                }
            }
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                let raw = component
                    .get(unchecked_range)
                    .ok_or(TransformError::ComponentInspection)?;
                embedded_core_modules.push(EmbeddedCoreModulePin {
                    ordinal: u32::try_from(embedded_core_modules.len())
                        .map_err(|_| TransformError::ComponentInspection)?,
                    raw_bytes: raw.len(),
                    raw_sha256: sha256(raw),
                });
                depth += 1;
            }
            Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    entries.sort_by(|left, right| {
        (left.direction, left.kind, left.name.as_str()).cmp(&(
            right.direction,
            right.kind,
            right.name.as_str(),
        ))
    });

    let mut hasher = Sha256::new();
    hasher.update(CANONICAL_LOWERING_DOMAIN);
    for raw in &lower_entries {
        let length = u64::try_from(raw.len()).map_err(|_| TransformError::ComponentInspection)?;
        hasher.update(length.to_le_bytes());
        hasher.update(raw);
    }
    Ok(OutputPins {
        entries,
        embedded_core_modules,
        canonical_lowers: u32::try_from(lower_entries.len())
            .map_err(|_| TransformError::ComponentInspection)?,
        canonical_lowering_sha256: hasher.finalize().into(),
    })
}

fn inspect_component(component: &[u8]) -> Result<(u32, u32, u32, u32, u32), TransformError> {
    let mut imports = 0_u32;
    let mut exports = 0_u32;
    let mut modules = 0_u32;
    let mut components = 0_u32;
    let mut lowers = 0_u32;
    let mut depth = 0_u32;
    for payload in Parser::new(0).parse_all(component) {
        match payload.map_err(|_| TransformError::ComponentInspection)? {
            Payload::ComponentImportSection(reader) if depth == 0 => {
                imports = imports
                    .checked_add(reader.count())
                    .ok_or(TransformError::ComponentInspection)?;
            }
            Payload::ComponentExportSection(reader) if depth == 0 => {
                exports = exports
                    .checked_add(reader.count())
                    .ok_or(TransformError::ComponentInspection)?;
            }
            Payload::ComponentCanonicalSection(reader) if depth == 0 => {
                for function in reader {
                    if matches!(
                        function.map_err(|_| TransformError::ComponentInspection)?,
                        CanonicalFunction::Lower { .. }
                    ) {
                        lowers = lowers
                            .checked_add(1)
                            .ok_or(TransformError::ComponentInspection)?;
                    }
                }
            }
            Payload::ModuleSection { .. } if depth == 0 => {
                modules = modules
                    .checked_add(1)
                    .ok_or(TransformError::ComponentInspection)?;
                depth += 1;
            }
            Payload::ComponentSection { .. } if depth == 0 => {
                components = components
                    .checked_add(1)
                    .ok_or(TransformError::ComponentInspection)?;
                depth += 1;
            }
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End(_) if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    Ok((imports, exports, modules, components, lowers))
}

/// Validate the exact C8.1 Core/adapter inputs and produce inert Component
/// bytes. This function performs no guest call or instantiation.
pub fn componentize_preview1(
    core: &[u8],
    adapter: &[u8],
) -> Result<TransformedComponent, TransformError> {
    let _inspection = inspect_core(core)?;
    if adapter.len() != ADAPTER_BYTES {
        return Err(TransformError::AdapterLength);
    }
    let adapter_sha256 = sha256(adapter);
    if adapter_sha256 != ADAPTER_SHA256 {
        return Err(TransformError::AdapterDigest);
    }

    let component = ComponentEncoder::default()
        .module(core)
        .map_err(|_| TransformError::Encoding)?
        .adapter(ADAPTER_IMPORT_NAME, adapter)
        .map_err(|_| TransformError::Encoding)?
        .validate(true)
        .encode()
        .map_err(|_| TransformError::Encoding)?;

    Validator::new_with_features(WasmFeatures::all())
        .validate_all(&component)
        .map_err(|_| TransformError::ComponentValidation)?;
    let (outer_imports, outer_exports, embedded_core_modules, nested_components, canonical_lowers) =
        inspect_component(&component)?;
    let report = TransformReport {
        core_bytes: core.len(),
        core_sha256: sha256(core),
        adapter_bytes: adapter.len(),
        adapter_sha256,
        component_bytes: component.len(),
        component_sha256: sha256(&component),
        outer_imports,
        outer_exports,
        embedded_core_modules,
        nested_components,
        canonical_lowers,
        runtime_ready: false,
        guest_calls: 0,
    };
    Ok(TransformedComponent {
        bytes: component,
        report,
    })
}
