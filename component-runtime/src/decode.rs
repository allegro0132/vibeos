//! Allocation-bounded decoding for Vibe Component Profile 1.

pub use crate::execution::{CanonicalStringEncoding, ExecutableExportInfo};
use crate::{
    abi_value::{flat_signature, MAX_FLAT_PARAMS, MAX_FLAT_RESULTS},
    execution::{
        ComponentExecutionPlan, CoreExportRef, CoreInstancePlan, ExecutableExportPlan, LiftDraft,
        LiftOptionsDraft,
    },
    predecode::{predecode_component, PredecodeError},
    types::TypeBuilder,
    value::ValueType,
    world::{normalize_component_entities, NamedEntityShape, WorldContract, WorldError},
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{LimitKind, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::inspect_core;
use wasmparser::{
    component_types::ComponentEntityType, CanonicalFunction, CanonicalOption, ComponentAlias,
    ComponentDefinedType as RawDefinedType, ComponentExternalKind, ComponentInstance,
    ComponentType as RawComponentType, ComponentTypeRef, Encoding, ExternalKind, Instance,
    InstanceTypeDeclaration, Parser, Payload, PrimitiveValType, ValType, Validator, WasmFeatures,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComponentSummary {
    pub bytes: u32,
    pub embedded_modules: u32,
    pub embedded_module_bytes: u64,
    pub core_instances: u32,
    pub component_instances: u32,
    pub definitions: u32,
    pub aliases: u32,
    pub canonical_functions: u32,
    pub adapters: u32,
    pub resources: u32,
    pub imports: u32,
    pub exports: u32,
    pub custom_sections: u32,
    pub custom_section_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DecodeError {
    NotComponent = 1,
    Malformed = 2,
    Unsupported = 3,
    Limit = 4,
    Allocation = 5,
    InvalidEmbeddedCore = 6,
    DuplicateName = 7,
    TypeGraph = 8,
    InvalidWiring = 9,
}

impl DecodeError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

pub struct ComponentPlan<'a> {
    pub summary: ComponentSummary,
    /// Exact borrowed byte ranges from the validated parent artifact.
    pub embedded_modules: Vec<&'a [u8]>,
    pub imports: Vec<NamedEntityShape>,
    pub exports: Vec<NamedEntityShape>,
    pub(crate) execution: ComponentExecutionPlan,
}

impl ComponentPlan<'_> {
    pub const fn summary(&self) -> ComponentSummary {
        self.summary
    }

    pub fn embedded_modules(&self) -> &[&[u8]] {
        &self.embedded_modules
    }

    pub fn imports(&self) -> &[NamedEntityShape] {
        &self.imports
    }

    pub fn exports(&self) -> &[NamedEntityShape] {
        &self.exports
    }

    pub fn executable_exports(&self) -> impl Iterator<Item = &ExecutableExportInfo> {
        self.execution.exports.iter().map(|export| &export.info)
    }

    pub fn check_world(&self, world: &WorldContract) -> Result<(), WorldError> {
        world.check_component(&self.imports, &self.exports)
    }
}

fn profile_features() -> WasmFeatures {
    let mut features = WasmFeatures::empty();
    features.set(WasmFeatures::COMPONENT_MODEL, true);
    features
}

fn add(value: &mut u32, amount: u32, maximum: u32, _kind: LimitKind) -> Result<(), DecodeError> {
    let next = value.checked_add(amount).ok_or(DecodeError::Limit)?;
    if next > maximum {
        return Err(DecodeError::Limit);
    }
    *value = next;
    Ok(())
}

fn add_u64(value: &mut u64, amount: usize, maximum: usize) -> Result<(), DecodeError> {
    let next = value.checked_add(amount as u64).ok_or(DecodeError::Limit)?;
    if next > maximum as u64 {
        return Err(DecodeError::Limit);
    }
    *value = next;
    Ok(())
}

fn copied(value: &str) -> Result<String, DecodeError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| DecodeError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn record_name(target: &mut Vec<String>, name: &str) -> Result<(), DecodeError> {
    if target.iter().any(|existing| existing == name) {
        return Err(DecodeError::DuplicateName);
    }
    target.try_reserve(1).map_err(|_| DecodeError::Allocation)?;
    target.push(copied(name)?);
    Ok(())
}

/// Performs a structural limit pass before invoking `Validator`, validates all
/// embedded Core modules through C1, and returns an inert typed plan.
pub fn inspect_component(bytes: &[u8]) -> Result<ComponentPlan<'_>, DecodeError> {
    if bytes.len() > PROFILE_1_LIMITS.max_component_bytes || bytes.len() > u32::MAX as usize {
        return Err(DecodeError::Limit);
    }
    predecode_component(bytes).map_err(predecode_error)?;
    let mut summary = ComponentSummary {
        bytes: bytes.len() as u32,
        ..ComponentSummary::default()
    };
    let mut modules = Vec::new();
    let mut core_modules = Vec::new();
    let mut core_instances = Vec::new();
    let mut core_functions: Vec<Option<CoreExportRef>> = Vec::new();
    let mut core_memories: Vec<Option<CoreExportRef>> = Vec::new();
    let mut component_functions: Vec<Option<LiftDraft>> = Vec::new();
    let mut component_instances: Vec<Option<Vec<(String, u32)>>> = Vec::new();
    let mut function_exports = Vec::new();
    let mut instance_exports = Vec::new();
    let mut import_names = Vec::new();
    let mut export_names = Vec::new();
    let mut saw_top = false;
    let mut parser = Parser::new(0);
    // The structural pass recognizes every proposal so it can return the
    // profile's stable `Unsupported` diagnostic itself. The strict validator
    // below receives only the Component Model base feature.
    parser.set_features(WasmFeatures::all());

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|_| DecodeError::Malformed)?;
        match payload {
            Payload::Version { encoding, .. } if !saw_top => {
                if encoding != Encoding::Component {
                    return Err(DecodeError::NotComponent);
                }
                saw_top = true;
            }
            Payload::Version { .. } => {}
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                if unchecked_range.start > unchecked_range.end
                    || unchecked_range.end > bytes.len()
                    || unchecked_range.len() > PROFILE_1_LIMITS.max_core_module_bytes
                {
                    return Err(DecodeError::Limit);
                }
                add(
                    &mut summary.embedded_modules,
                    1,
                    PROFILE_1_LIMITS.max_embedded_modules,
                    LimitKind::EmbeddedModules,
                )?;
                add_u64(
                    &mut summary.embedded_module_bytes,
                    unchecked_range.len(),
                    PROFILE_1_LIMITS.max_component_bytes,
                )?;
                modules
                    .try_reserve(1)
                    .map_err(|_| DecodeError::Allocation)?;
                modules.push(&bytes[unchecked_range]);
                core_modules
                    .try_reserve(1)
                    .map_err(|_| DecodeError::Allocation)?;
                core_modules.push(Some(modules.len() - 1));
            }
            Payload::ComponentSection { .. } | Payload::ComponentStartSection { .. } => {
                return Err(DecodeError::Unsupported);
            }
            Payload::InstanceSection(reader) => {
                add(
                    &mut summary.core_instances,
                    reader.count(),
                    PROFILE_1_LIMITS.max_component_instances,
                    LimitKind::ComponentInstances,
                )?;
                for instance in reader {
                    let instance = instance.map_err(|_| DecodeError::Malformed)?;
                    core_instances
                        .try_reserve(1)
                        .map_err(|_| DecodeError::Allocation)?;
                    core_instances.push(match instance {
                        Instance::Instantiate { module_index, args } if args.is_empty() => {
                            core_modules
                                .get(module_index as usize)
                                .copied()
                                .flatten()
                                .map(|module| CoreInstancePlan { module })
                        }
                        Instance::Instantiate { .. } | Instance::FromExports(_) => None,
                    });
                }
            }
            Payload::ComponentInstanceSection(reader) => {
                add(
                    &mut summary.component_instances,
                    reader.count(),
                    PROFILE_1_LIMITS.max_component_instances,
                    LimitKind::ComponentInstances,
                )?;
                for instance in reader {
                    let instance = instance.map_err(|_| DecodeError::Malformed)?;
                    component_instances
                        .try_reserve(1)
                        .map_err(|_| DecodeError::Allocation)?;
                    component_instances.push(match instance {
                        ComponentInstance::FromExports(exports) => {
                            let mut functions = Vec::new();
                            for export in exports.iter() {
                                if export.kind == ComponentExternalKind::Func {
                                    functions
                                        .try_reserve(1)
                                        .map_err(|_| DecodeError::Allocation)?;
                                    functions.push((copied(export.name.name)?, export.index));
                                }
                            }
                            Some(functions)
                        }
                        ComponentInstance::Instantiate { .. } => None,
                    });
                }
            }
            Payload::CoreTypeSection(reader) => {
                if reader.count() != 0 {
                    return Err(DecodeError::Unsupported);
                }
            }
            Payload::ComponentTypeSection(reader) => {
                add(
                    &mut summary.definitions,
                    reader.count(),
                    PROFILE_1_LIMITS.max_component_definitions,
                    LimitKind::ComponentDefinitions,
                )?;
                for ty in reader {
                    let ty = ty.map_err(|_| DecodeError::Malformed)?;
                    inspect_type(&ty, &mut summary, 1)?;
                }
            }
            Payload::ComponentAliasSection(reader) => {
                add(
                    &mut summary.aliases,
                    reader.count(),
                    PROFILE_1_LIMITS.max_aliases,
                    LimitKind::Aliases,
                )?;
                for alias in reader {
                    match alias.map_err(|_| DecodeError::Malformed)? {
                        ComponentAlias::CoreInstanceExport {
                            kind,
                            instance_index,
                            name,
                        } => match kind {
                            ExternalKind::Func => {
                                push_core_ref(&mut core_functions, instance_index, name)?
                            }
                            ExternalKind::Memory => {
                                push_core_ref(&mut core_memories, instance_index, name)?
                            }
                            ExternalKind::Table
                            | ExternalKind::Global
                            | ExternalKind::Tag
                            | ExternalKind::FuncExact => {}
                        },
                        ComponentAlias::InstanceExport {
                            kind,
                            instance_index,
                            name,
                        } => {
                            if kind == ComponentExternalKind::Func {
                                let source = component_instances
                                    .get(instance_index as usize)
                                    .and_then(Option::as_ref)
                                    .and_then(|members| {
                                        members.iter().find_map(|(member, index)| {
                                            (member == name).then_some(*index)
                                        })
                                    })
                                    .and_then(|index| component_functions.get(index as usize))
                                    .copied()
                                    .flatten();
                                component_functions
                                    .try_reserve(1)
                                    .map_err(|_| DecodeError::Allocation)?;
                                component_functions.push(source);
                            }
                        }
                        ComponentAlias::Outer { .. } => return Err(DecodeError::Unsupported),
                    }
                }
            }
            Payload::ComponentCanonicalSection(reader) => {
                add(
                    &mut summary.canonical_functions,
                    reader.count(),
                    PROFILE_1_LIMITS.max_canonical_functions,
                    LimitKind::CanonicalFunctions,
                )?;
                for function in reader {
                    let function = function.map_err(|_| DecodeError::Malformed)?;
                    if inspect_canonical(function.clone())? {
                        add(
                            &mut summary.adapters,
                            1,
                            PROFILE_1_LIMITS.max_adapters,
                            LimitKind::Adapters,
                        )?;
                    }
                    match function {
                        CanonicalFunction::Lift {
                            core_func_index,
                            options,
                            ..
                        } => {
                            let options = execution_options(&options)?;
                            component_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            component_functions.push(Some(LiftDraft {
                                core_function: core_func_index,
                                string_encoding: options.string_encoding,
                                memory: options.memory,
                                realloc: options.realloc,
                                post_return: options.post_return,
                            }));
                        }
                        CanonicalFunction::Lower { .. }
                        | CanonicalFunction::ResourceNew { .. }
                        | CanonicalFunction::ResourceDrop { .. }
                        | CanonicalFunction::ResourceRep { .. } => {
                            core_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            core_functions.push(None);
                        }
                        _ => return Err(DecodeError::Unsupported),
                    }
                }
            }
            Payload::ComponentImportSection(reader) => {
                add(
                    &mut summary.imports,
                    reader.count(),
                    PROFILE_1_LIMITS.max_imports,
                    LimitKind::Imports,
                )?;
                for import in reader {
                    let import = import.map_err(|_| DecodeError::Malformed)?;
                    record_name(&mut import_names, import.name.name)?;
                    match import.ty {
                        ComponentTypeRef::Module(_) => {
                            core_modules
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            core_modules.push(None);
                        }
                        ComponentTypeRef::Func(_) => {
                            component_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            component_functions.push(None);
                        }
                        ComponentTypeRef::Instance(_) => {
                            component_instances
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            component_instances.push(None);
                        }
                        ComponentTypeRef::Value(_)
                        | ComponentTypeRef::Type(_)
                        | ComponentTypeRef::Component(_) => {}
                    }
                }
            }
            Payload::ComponentExportSection(reader) => {
                add(
                    &mut summary.exports,
                    reader.count(),
                    PROFILE_1_LIMITS.max_exports,
                    LimitKind::Exports,
                )?;
                for export in reader {
                    let export = export.map_err(|_| DecodeError::Malformed)?;
                    record_name(&mut export_names, export.name.name)?;
                    if export.kind == ComponentExternalKind::Func {
                        function_exports
                            .try_reserve(1)
                            .map_err(|_| DecodeError::Allocation)?;
                        function_exports.push((copied(export.name.name)?, export.index));
                    } else if export.kind == ComponentExternalKind::Instance {
                        instance_exports
                            .try_reserve(1)
                            .map_err(|_| DecodeError::Allocation)?;
                        instance_exports.push((copied(export.name.name)?, export.index));
                    }
                }
            }
            Payload::CustomSection(reader) => {
                add(
                    &mut summary.custom_sections,
                    1,
                    PROFILE_1_LIMITS.max_custom_sections,
                    LimitKind::CustomSections,
                )?;
                add_u64(
                    &mut summary.custom_section_bytes,
                    reader.data().len(),
                    PROFILE_1_LIMITS.max_custom_section_bytes,
                )?;
            }
            Payload::UnknownSection { .. } => return Err(DecodeError::Unsupported),
            _ => {}
        }
    }
    if !saw_top {
        return Err(DecodeError::NotComponent);
    }

    for module in &modules {
        inspect_core(module).map_err(|_| DecodeError::InvalidEmbeddedCore)?;
    }

    let types = match Validator::new_with_features(profile_features()).validate_all(bytes) {
        Ok(types) => types,
        Err(_) => {
            if Validator::new_with_features(WasmFeatures::all())
                .validate_all(bytes)
                .is_ok()
            {
                return Err(DecodeError::Unsupported);
            }
            return Err(DecodeError::Malformed);
        }
    };
    let imports = normalize_component_entities(&types, &import_names, true).map_err(shape_error)?;
    let exports =
        normalize_component_entities(&types, &export_names, false).map_err(shape_error)?;
    let mut instances = Vec::new();
    instances
        .try_reserve_exact(core_instances.len())
        .map_err(|_| DecodeError::Allocation)?;
    for instance in core_instances {
        instances.push(instance.ok_or(DecodeError::Unsupported)?);
    }
    let mut executable_exports = Vec::new();
    executable_exports
        .try_reserve_exact(function_exports.len())
        .map_err(|_| DecodeError::Allocation)?;
    let mut type_builder = TypeBuilder::default();
    for (name, function_index) in function_exports {
        let item = types
            .component_item_for_export(&name)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentEntityType::Func(function_type) = item.ty else {
            return Err(DecodeError::InvalidWiring);
        };
        push_executable_export(
            &mut executable_exports,
            name,
            function_index,
            function_type,
            &mut type_builder,
            &types,
            &component_functions,
            &core_functions,
            &core_memories,
            instances.len(),
        )?;
    }
    for (interface_name, instance_index) in instance_exports {
        let members = component_instances
            .get(instance_index as usize)
            .and_then(Option::as_ref)
            .ok_or(DecodeError::InvalidWiring)?;
        let item = types
            .component_item_for_export(&interface_name)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentEntityType::Instance(instance_type) = item.ty else {
            return Err(DecodeError::InvalidWiring);
        };
        let interface = &types[instance_type];
        for (member_name, function_index) in members {
            let member = interface
                .exports
                .get(member_name)
                .ok_or(DecodeError::InvalidWiring)?;
            let ComponentEntityType::Func(function_type) = member.ty else {
                continue;
            };
            let mut qualified = interface_name.clone();
            qualified
                .try_reserve(member_name.len() + 1)
                .map_err(|_| DecodeError::Allocation)?;
            qualified.push('#');
            qualified.push_str(member_name);
            push_executable_export(
                &mut executable_exports,
                qualified,
                *function_index,
                function_type,
                &mut type_builder,
                &types,
                &component_functions,
                &core_functions,
                &core_memories,
                instances.len(),
            )?;
        }
    }
    Ok(ComponentPlan {
        summary,
        embedded_modules: modules,
        imports,
        exports,
        execution: ComponentExecutionPlan {
            instances,
            exports: executable_exports,
        },
    })
}

fn predecode_error(error: PredecodeError) -> DecodeError {
    match error {
        PredecodeError::NotComponent => DecodeError::NotComponent,
        PredecodeError::Malformed => DecodeError::Malformed,
        PredecodeError::Unsupported => DecodeError::Unsupported,
        PredecodeError::Limit => DecodeError::Limit,
    }
}

fn push_core_ref(
    target: &mut Vec<Option<CoreExportRef>>,
    instance_index: u32,
    name: &str,
) -> Result<(), DecodeError> {
    target.try_reserve(1).map_err(|_| DecodeError::Allocation)?;
    target.push(Some(CoreExportRef {
        instance: usize::try_from(instance_index).map_err(|_| DecodeError::InvalidWiring)?,
        name: copied(name)?,
    }));
    Ok(())
}

fn resolve_core_ref(
    refs: &[Option<CoreExportRef>],
    index: u32,
) -> Result<&CoreExportRef, DecodeError> {
    refs.get(index as usize)
        .and_then(Option::as_ref)
        .ok_or(DecodeError::InvalidWiring)
}

#[allow(clippy::too_many_arguments)]
fn push_executable_export(
    target: &mut Vec<ExecutableExportPlan>,
    name: String,
    function_index: u32,
    function_type: wasmparser::component_types::ComponentFuncTypeId,
    type_builder: &mut TypeBuilder,
    types: &wasmparser::types::Types,
    component_functions: &[Option<LiftDraft>],
    core_functions: &[Option<CoreExportRef>],
    core_memories: &[Option<CoreExportRef>],
    instance_count: usize,
) -> Result<(), DecodeError> {
    let lift = component_functions
        .get(function_index as usize)
        .and_then(Option::as_ref)
        .ok_or(DecodeError::InvalidWiring)?;
    let function = resolve_core_ref(core_functions, lift.core_function)?;
    let memory = lift
        .memory
        .map(|index| resolve_core_ref(core_memories, index))
        .transpose()?;
    let realloc = lift
        .realloc
        .map(|index| resolve_core_ref(core_functions, index))
        .transpose()?;
    let post_return = lift
        .post_return
        .map(|index| resolve_core_ref(core_functions, index))
        .transpose()?;
    for option in [memory, realloc, post_return].into_iter().flatten() {
        if option.instance != function.instance {
            return Err(DecodeError::InvalidWiring);
        }
    }
    if function.instance >= instance_count {
        return Err(DecodeError::InvalidWiring);
    }
    let normalized_function = type_builder
        .function(types, function_type)
        .map_err(|_| DecodeError::TypeGraph)?;
    require_canonical_options(&normalized_function, lift)?;
    if target.len() >= PROFILE_1_LIMITS.max_canonical_functions as usize
        || target.iter().any(|export| export.info.name == name)
    {
        return Err(DecodeError::InvalidWiring);
    }
    target.try_reserve(1).map_err(|_| DecodeError::Allocation)?;
    target.push(ExecutableExportPlan {
        info: ExecutableExportInfo {
            name,
            function: normalized_function,
            core_instance: function.instance,
            core_function: copied(&function.name)?,
            string_encoding: lift.string_encoding,
            memory: memory.map(|binding| copied(&binding.name)).transpose()?,
            realloc: realloc.map(|binding| copied(&binding.name)).transpose()?,
            post_return: post_return
                .map(|binding| copied(&binding.name))
                .transpose()?,
        },
        core_instance: function.instance,
        function: copied(&function.name)?,
        memory: memory.map(|binding| copied(&binding.name)).transpose()?,
        realloc: realloc.map(|binding| copied(&binding.name)).transpose()?,
        post_return: post_return
            .map(|binding| copied(&binding.name))
            .transpose()?,
    });
    Ok(())
}

fn require_canonical_options(
    function: &crate::types::FunctionType,
    lift: &LiftDraft,
) -> Result<(), DecodeError> {
    let parameter_flat = flat_count(function.parameters.iter().map(|parameter| &parameter.value))?;
    let result_flat = flat_count(function.result.iter())?;
    let parameter_dynamic = function
        .parameters
        .iter()
        .any(|parameter| uses_memory(&parameter.value));
    let result_dynamic = function.result.as_ref().is_some_and(uses_memory);
    let parameters_need_memory = parameter_dynamic || parameter_flat > MAX_FLAT_PARAMS;
    let result_needs_memory = result_dynamic || result_flat > MAX_FLAT_RESULTS;
    if (parameters_need_memory || result_needs_memory) && lift.memory.is_none()
        || parameters_need_memory && lift.realloc.is_none()
        || result_needs_memory && lift.post_return.is_none()
    {
        return Err(DecodeError::InvalidWiring);
    }
    Ok(())
}

fn flat_count<'a>(values: impl Iterator<Item = &'a ValueType>) -> Result<usize, DecodeError> {
    let mut total = 0_usize;
    for value in values {
        total = total
            .checked_add(
                flat_signature(core::slice::from_ref(value))
                    .map_err(|_| DecodeError::TypeGraph)?
                    .len(),
            )
            .ok_or(DecodeError::Limit)?;
    }
    Ok(total)
}

fn uses_memory(value: &ValueType) -> bool {
    match value {
        ValueType::String | ValueType::List(_) => true,
        ValueType::Tuple(values) | ValueType::Record(values) => values.iter().any(uses_memory),
        ValueType::Option(value) => uses_memory(value),
        ValueType::Result { ok, error } => ok
            .iter()
            .chain(error.iter())
            .any(|value| uses_memory(value)),
        ValueType::Variant(cases) => cases.iter().flatten().any(uses_memory),
        _ => false,
    }
}

fn shape_error(error: WorldError) -> DecodeError {
    match error {
        WorldError::Allocation => DecodeError::Allocation,
        WorldError::UnsupportedType => DecodeError::Unsupported,
        _ => DecodeError::TypeGraph,
    }
}

fn inspect_type(
    ty: &RawComponentType<'_>,
    summary: &mut ComponentSummary,
    depth: u32,
) -> Result<(), DecodeError> {
    if depth > PROFILE_1_LIMITS.max_component_nesting {
        return Err(DecodeError::Limit);
    }
    match ty {
        RawComponentType::Defined(defined) => inspect_defined_type(defined),
        RawComponentType::Func(function) => {
            if function.async_
                || function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize
            {
                return Err(DecodeError::Unsupported);
            }
            for (_, ty) in function.params.iter() {
                inspect_primitive(raw_primitive(*ty))?;
            }
            if let Some(ty) = function.result {
                inspect_primitive(raw_primitive(ty))?;
            }
            Ok(())
        }
        RawComponentType::Component(_) => Err(DecodeError::Unsupported),
        RawComponentType::Instance(declarations) => {
            if declarations.len() > PROFILE_1_LIMITS.max_component_definitions as usize {
                return Err(DecodeError::Limit);
            }
            for declaration in declarations.iter() {
                match declaration {
                    InstanceTypeDeclaration::Type(nested) => {
                        add(
                            &mut summary.definitions,
                            1,
                            PROFILE_1_LIMITS.max_component_definitions,
                            LimitKind::ComponentDefinitions,
                        )?;
                        inspect_type(nested, summary, depth + 1)?;
                    }
                    InstanceTypeDeclaration::Alias(_) => add(
                        &mut summary.aliases,
                        1,
                        PROFILE_1_LIMITS.max_aliases,
                        LimitKind::Aliases,
                    )?,
                    InstanceTypeDeclaration::CoreType(_) => return Err(DecodeError::Unsupported),
                    InstanceTypeDeclaration::Export { .. } => {}
                }
            }
            Ok(())
        }
        RawComponentType::Resource { rep, .. } => {
            if *rep != ValType::I32 {
                return Err(DecodeError::Unsupported);
            }
            add(
                &mut summary.resources,
                1,
                PROFILE_1_LIMITS.max_resources,
                LimitKind::Resources,
            )
        }
    }
}

fn inspect_defined_type(defined: &RawDefinedType<'_>) -> Result<(), DecodeError> {
    match defined {
        RawDefinedType::Primitive(primitive) => inspect_primitive(Some(*primitive)),
        RawDefinedType::Record(fields) => {
            check_shape_len(fields.len())?;
            for (_, ty) in fields.iter() {
                inspect_primitive(raw_primitive(*ty))?;
            }
            Ok(())
        }
        RawDefinedType::Variant(cases) => {
            check_shape_len(cases.len())?;
            for case in cases.iter() {
                if let Some(ty) = case.ty {
                    inspect_primitive(raw_primitive(ty))?;
                }
            }
            Ok(())
        }
        RawDefinedType::List(ty) | RawDefinedType::Option(ty) => {
            inspect_primitive(raw_primitive(*ty))
        }
        RawDefinedType::Tuple(types) => {
            check_shape_len(types.len())?;
            for ty in types.iter() {
                inspect_primitive(raw_primitive(*ty))?;
            }
            Ok(())
        }
        RawDefinedType::Flags(names) | RawDefinedType::Enum(names) => check_shape_len(names.len()),
        RawDefinedType::Result { ok, err } => {
            if let Some(ty) = ok {
                inspect_primitive(raw_primitive(*ty))?;
            }
            if let Some(ty) = err {
                inspect_primitive(raw_primitive(*ty))?;
            }
            Ok(())
        }
        RawDefinedType::Own(_) | RawDefinedType::Borrow(_) => Ok(()),
        RawDefinedType::Map(_, _)
        | RawDefinedType::FixedLengthList(_, _)
        | RawDefinedType::Future(_)
        | RawDefinedType::Stream(_) => Err(DecodeError::Unsupported),
    }
}

fn check_shape_len(length: usize) -> Result<(), DecodeError> {
    if length > PROFILE_1_LIMITS.max_canonical_values as usize {
        Err(DecodeError::Limit)
    } else {
        Ok(())
    }
}

fn inspect_primitive(primitive: Option<PrimitiveValType>) -> Result<(), DecodeError> {
    match primitive {
        Some(PrimitiveValType::F32 | PrimitiveValType::F64 | PrimitiveValType::ErrorContext) => {
            Err(DecodeError::Unsupported)
        }
        _ => Ok(()),
    }
}

fn raw_primitive(ty: wasmparser::ComponentValType) -> Option<PrimitiveValType> {
    match ty {
        wasmparser::ComponentValType::Primitive(primitive) => Some(primitive),
        wasmparser::ComponentValType::Type(_) => None,
    }
}

fn inspect_canonical(function: CanonicalFunction) -> Result<bool, DecodeError> {
    let (options, adapter) = match function {
        CanonicalFunction::Lift { options, .. } => (options, false),
        CanonicalFunction::Lower { options, .. } => (options, true),
        CanonicalFunction::ResourceNew { .. }
        | CanonicalFunction::ResourceDrop { .. }
        | CanonicalFunction::ResourceRep { .. } => return Ok(false),
        _ => return Err(DecodeError::Unsupported),
    };
    let mut utf8 = false;
    let mut memory = false;
    let mut realloc = false;
    let mut post_return = false;
    for option in options.iter() {
        let duplicate = match option {
            CanonicalOption::UTF8 => core::mem::replace(&mut utf8, true),
            CanonicalOption::Memory(_) => core::mem::replace(&mut memory, true),
            CanonicalOption::Realloc(_) => core::mem::replace(&mut realloc, true),
            CanonicalOption::PostReturn(_) => core::mem::replace(&mut post_return, true),
            CanonicalOption::UTF16
            | CanonicalOption::CompactUTF16
            | CanonicalOption::Async
            | CanonicalOption::Callback(_)
            | CanonicalOption::CoreType(_)
            | CanonicalOption::Gc => return Err(DecodeError::Unsupported),
        };
        if duplicate {
            return Err(DecodeError::Malformed);
        }
    }
    Ok(adapter)
}

fn execution_options(options: &[CanonicalOption]) -> Result<LiftOptionsDraft, DecodeError> {
    let mut string_encoding = None;
    let mut memory = None;
    let mut realloc = None;
    let mut post_return = None;
    for option in options {
        let destination = match option {
            CanonicalOption::Memory(_) => &mut memory,
            CanonicalOption::Realloc(_) => &mut realloc,
            CanonicalOption::PostReturn(_) => &mut post_return,
            CanonicalOption::UTF8 => {
                if string_encoding
                    .replace(CanonicalStringEncoding::Utf8)
                    .is_some()
                {
                    return Err(DecodeError::Malformed);
                }
                continue;
            }
            CanonicalOption::UTF16
            | CanonicalOption::CompactUTF16
            | CanonicalOption::Async
            | CanonicalOption::Callback(_)
            | CanonicalOption::CoreType(_)
            | CanonicalOption::Gc => return Err(DecodeError::Unsupported),
        };
        let value = match option {
            CanonicalOption::Memory(index)
            | CanonicalOption::Realloc(index)
            | CanonicalOption::PostReturn(index) => *index,
            _ => unreachable!(),
        };
        if destination.replace(value).is_some() {
            return Err(DecodeError::Malformed);
        }
    }
    Ok(LiftOptionsDraft {
        string_encoding,
        memory,
        realloc,
        post_return,
    })
}
