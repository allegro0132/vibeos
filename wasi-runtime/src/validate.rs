use super::{WasiError, WasiLimits};
use super::profile::DECLARATIONS as BASE;
use wasmparser::{Encoding, ExternalKind, Parser, Payload, TypeRef, Validator, WasmFeatures};

/// Threads (shared memory, atomics, `memory.atomic.wait/notify`) are admitted
/// only when the embedding executes guests on an engine with shared memory.
pub(crate) fn features(threads: bool) -> WasmFeatures {
    let base = WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SATURATING_FLOAT_TO_INT
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::BULK_MEMORY
        | WasmFeatures::REFERENCE_TYPES
        | WasmFeatures::FLOATS
        | WasmFeatures::GC_TYPES;
    if threads {
        base | WasmFeatures::THREADS
    } else {
        base
    }
}
fn bound(count: u32, max: u32) -> Result<(), WasiError> {
    if count > max {
        Err(WasiError::Limit)
    } else {
        Ok(())
    }
}
/// Bound declarations before the allocating validator/compiler. No guest code runs here.
pub(crate) fn inspect(bytes: &[u8], limits: WasiLimits) -> Result<(), WasiError> {
    if bytes.len() > limits.module_bytes {
        return Err(WasiError::Limit);
    }
    let mut functions = 0u32;
    let mut memories = 0u32;
    let mut tables = 0u32;
    let mut custom_bytes = 0usize;
    let mut custom_count = 0;
    let mut memory_export = false;
    let mut start_export = false;
    let mut thread_start_export = false;
    let mut imports_thread_spawn = false;
    let mut imports_shared_memory = false;
    let mut has_core_start = false;
    let mut elements = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|_| WasiError::Malformed)? {
            Payload::Version { encoding, .. } if encoding != Encoding::Module => {
                return Err(WasiError::Contract)
            }
            Payload::TypeSection(reader) => {
                bound(reader.count(), BASE.max_types)?;
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| WasiError::Unsupported)?;
                    bound(ty.params().len() as u32, BASE.max_params_per_function)?;
                    bound(ty.results().len() as u32, BASE.max_results_per_function)?;
                }
            }
            Payload::ImportSection(reader) => {
                bound(reader.count(), BASE.max_imports)?;
                let mut imports = 0;
                for import in reader.into_imports() {
                    imports += 1;
                    bound(imports, BASE.max_imports)?;
                    let import = import.map_err(|_| WasiError::Malformed)?;
                    match (import.module, import.name, import.ty) {
                        ("wasi_snapshot_preview1", name, TypeRef::Func(_))
                            if super::abi::signature(name).is_some() =>
                        {
                            functions += 1;
                        }
                        // wasi-threads: the guest spawns through this import and
                        // every thread instantiates the module against one
                        // shared, bounded, imported memory.
                        ("wasi", "thread-spawn", TypeRef::Func(_)) if limits.threads => {
                            functions += 1;
                            imports_thread_spawn = true;
                        }
                        ("env", "memory", TypeRef::Memory(memory)) if limits.threads => {
                            if !memory.shared || memory.memory64 || memory.page_size_log2.is_some()
                            {
                                return Err(WasiError::Unsupported);
                            }
                            let Some(maximum) = memory.maximum else {
                                return Err(WasiError::Unsupported);
                            };
                            let pages = (limits.memory_bytes / 65536) as u64;
                            if memory.initial > pages || maximum > pages {
                                return Err(WasiError::Limit);
                            }
                            memories = memories.checked_add(1).ok_or(WasiError::Limit)?;
                            bound(memories, 1)?;
                            imports_shared_memory = true;
                        }
                        _ => return Err(WasiError::Import),
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                functions = functions
                    .checked_add(reader.count())
                    .ok_or(WasiError::Limit)?;
                bound(functions, BASE.max_functions)?;
            }
            Payload::MemorySection(reader) => {
                memories = memories
                    .checked_add(reader.count())
                    .ok_or(WasiError::Limit)?;
                bound(memories, 1)?;
                for memory in reader {
                    let memory = memory.map_err(|_| WasiError::Malformed)?;
                    if memory.memory64 || memory.shared || memory.page_size_log2.is_some() {
                        return Err(WasiError::Unsupported);
                    }
                    if memory.initial > (limits.memory_bytes / 65536) as u64 {
                        return Err(WasiError::Limit);
                    }
                }
            }
            Payload::TableSection(reader) => {
                tables = tables.checked_add(reader.count()).ok_or(WasiError::Limit)?;
                bound(tables, 1)?;
                for table in reader {
                    let table = table.map_err(|_| WasiError::Malformed)?;
                    if table.ty.table64 || table.ty.shared {
                        return Err(WasiError::Unsupported);
                    }
                    if table.ty.initial > BASE.max_table_elements as u64 {
                        return Err(WasiError::Limit);
                    }
                }
            }
            Payload::GlobalSection(reader) => bound(reader.count(), BASE.max_globals)?,
            Payload::ExportSection(reader) => {
                bound(reader.count(), BASE.max_exports)?;
                for export in reader {
                    let export = export.map_err(|_| WasiError::Malformed)?;
                    memory_export |= export.name == "memory" && export.kind == ExternalKind::Memory;
                    start_export |= export.name == "_start" && export.kind == ExternalKind::Func;
                    thread_start_export |=
                        export.name == "wasi_thread_start" && export.kind == ExternalKind::Func;
                }
            }
            // LLD initializes pthread TLS/passive data through a Core start
            // function. The threaded native embedding instantiates under the
            // same fuel, allocation and async execution limits as _start.
            Payload::StartSection { .. } => has_core_start = true,
            Payload::ElementSection(reader) => {
                bound(reader.count(), BASE.max_element_segments)?;
                for element in reader {
                    let element = element.map_err(|_| WasiError::Malformed)?;
                    let count = match element.items {
                        wasmparser::ElementItems::Functions(r) => r.count(),
                        wasmparser::ElementItems::Expressions(_, r) => r.count(),
                    };
                    elements = elements.checked_add(count).ok_or(WasiError::Limit)?;
                    bound(elements, BASE.max_table_elements)?;
                }
            }
            Payload::DataSection(reader) => bound(reader.count(), BASE.max_data_segments)?,
            Payload::DataCountSection { count, .. } => bound(count, BASE.max_data_segments)?,
            Payload::CodeSectionStart { count, .. } => bound(count, BASE.max_functions)?,
            Payload::CodeSectionEntry(body) => {
                let mut locals = 0u32;
                for local in body.get_locals_reader().map_err(|_| WasiError::Malformed)? {
                    locals = locals
                        .checked_add(local.map_err(|_| WasiError::Malformed)?.0)
                        .ok_or(WasiError::Limit)?;
                    bound(locals, BASE.max_locals_per_function)?;
                }
                let mut depth = 0u32;
                for op in body
                    .get_operators_reader()
                    .map_err(|_| WasiError::Malformed)?
                {
                    use wasmparser::Operator;
                    match op.map_err(|_| WasiError::Malformed)? {
                        Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                            depth += 1;
                            bound(depth, BASE.max_core_nesting)?;
                        }
                        Operator::End => depth = depth.saturating_sub(1),
                        _ => (),
                    }
                }
            }
            Payload::CustomSection(reader) => {
                custom_count += 1;
                bound(custom_count, BASE.max_custom_sections)?;
                custom_bytes = custom_bytes
                    .checked_add(reader.range().len())
                    .ok_or(WasiError::Limit)?;
                if custom_bytes > BASE.max_custom_section_bytes {
                    return Err(WasiError::Limit);
                }
            }
            Payload::Version { .. } | Payload::End(_) => (),
            _ => return Err(WasiError::Unsupported),
        }
    }
    if memories != 1 || !memory_export || !start_export {
        return Err(WasiError::Contract);
    }
    // A threaded command imports both halves of the wasi-threads contract and
    // exports the per-thread entry; a single-threaded one imports neither.
    if imports_thread_spawn != imports_shared_memory
        || (imports_thread_spawn && !thread_start_export)
    {
        return Err(WasiError::Contract);
    }
    if has_core_start && !(limits.threads && imports_thread_spawn && imports_shared_memory) {
        return Err(WasiError::Contract);
    }
    Validator::new_with_features(features(limits.threads))
        .validate_all(bytes)
        .map_err(|_| WasiError::Unsupported)?;
    Ok(())
}
