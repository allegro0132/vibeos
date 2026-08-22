//! Allocation-bounded decoding for Vibe Component Profile 1.

pub use crate::execution::{
    AsyncCanonicalFunctionPlan, AsyncCanonicalOptionsPlan, AsyncCanonicalPlan,
    AsyncComponentFunctionRef, AsyncComponentFunctionSource, AsyncCoreExportRef,
    AsyncCoreFunctionRef, AsyncCoreFunctionSource, AsyncCoreMemoryRef, AsyncCoreValueType,
    AsyncFuturePlan, AsyncStreamPlan, AsyncWaitablePlan, CanonicalStringEncoding,
    ExecutableExportInfo, HostCoreExportInfo, HostImportInfo, NativeAsyncCanonicalFunctionPlan,
    NativeAsyncCanonicalImportBridge, NativeAsyncCanonicalOptionsPlan, NativeAsyncCanonicalPlan,
    NativeAsyncCoreExportRef, NativeAsyncCoreImportPlan, NativeAsyncCoreInstancePlan,
    NativeAsyncCoreSignature, NativeAsyncExecutionPlan, NativeAsyncExportPlan,
    NativeAsyncFuturePlan, NativeAsyncStreamPlan, NativeAsyncWaitablePlan,
};
use crate::{
    abi_value::{flat_signature, MAX_FLAT_PARAMS, MAX_FLAT_RESULTS},
    execution::{
        AsyncCanonicalDraft, AsyncCanonicalFunctionDraft, AsyncComponentValueTypeRef,
        AsyncFutureDraft, AsyncOptionsDraft, AsyncStreamDraft, AsyncWaitableDraft,
        ComponentExecutionPlan, ComponentFunctionDraft, ComponentInstanceDraft, CoreExportRef,
        CoreFunctionDraft, CoreImportPlan, CoreInstanceDraft, CoreInstanceExportDraft,
        CoreInstanceExportItemDraft, CoreInstancePlan, CoreInstantiationArgDraft,
        ExecutableExportPlan, HostImportPlan, ImportedFunctionDraft, LiftDraft, LiftOptionsDraft,
        LowerDraft,
    },
    predecode::{predecode_component_for_profile, PredecodeError},
    types::TypeBuilder,
    value::ValueType,
    world::{normalize_component_world_entities, NamedEntityShape, WorldContract, WorldError},
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{LimitKind, ProfileIdentity, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::inspect_core;
use wasmparser::{
    component_types::{ComponentAnyTypeId, ComponentEntityType},
    CanonicalFunction, CanonicalOption, ComponentAlias, ComponentDefinedType as RawDefinedType,
    ComponentExternalKind, ComponentInstance, ComponentType as RawComponentType, ComponentTypeRef,
    Encoding, ExternalKind, Instance, InstanceTypeDeclaration, Parser, Payload, PrimitiveValType,
    TypeBounds, TypeRef, ValType, Validator, WasmFeatures,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsyncAbiSummary {
    pub async_function_types: u32,
    pub future_types: u32,
    pub stream_types: u32,
    pub async_lifts: u32,
    pub async_lowers: u32,
    pub task_builtins: u32,
    pub context_builtins: u32,
    pub subtask_builtins: u32,
    pub cooperative_yields: u32,
    pub stream_builtins: u32,
    pub future_builtins: u32,
    pub waitable_builtins: u32,
    pub backpressure_builtins: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsyncCanonicalOptions {
    /// `None` is the Canonical ABI UTF-8 default.
    pub string_encoding: Option<CanonicalStringEncoding>,
    pub async_: bool,
    pub memory: Option<u32>,
    pub realloc: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncLiftInfo {
    pub canonical_index: u32,
    pub core_function: u32,
    pub function_type: u32,
    pub callback_core_function: u32,
    pub options: AsyncCanonicalOptions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncLowerInfo {
    pub canonical_index: u32,
    pub component_function: u32,
    pub options: AsyncCanonicalOptions,
}

impl AsyncAbiSummary {
    pub const fn is_empty(self) -> bool {
        self.async_function_types == 0
            && self.future_types == 0
            && self.stream_types == 0
            && self.async_lifts == 0
            && self.async_lowers == 0
            && self.task_builtins == 0
            && self.context_builtins == 0
            && self.subtask_builtins == 0
            && self.cooperative_yields == 0
            && self.stream_builtins == 0
            && self.future_builtins == 0
            && self.waitable_builtins == 0
            && self.backpressure_builtins == 0
    }
}

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
    pub async_abi: AsyncAbiSummary,
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
    InvalidCallbackSignature = 10,
}

impl DecodeError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// Sealed result of complete Component validation. Derived counters and world
/// shapes are read-only so downstream accounting cannot be fed caller-forged
/// validation facts.
///
/// ```compile_fail
/// use vibeos_component_runtime::decode::ComponentPlan;
///
/// fn forge(plan: &mut ComponentPlan<'_>) {
///     plan.summary.adapters = 0;
///     plan.imports.clear();
/// }
/// ```
pub struct ComponentPlan<'a> {
    profile: ProfileIdentity,
    summary: ComponentSummary,
    /// Exact borrowed byte ranges from the validated parent artifact.
    embedded_modules: Vec<&'a [u8]>,
    imports: Vec<NamedEntityShape>,
    exports: Vec<NamedEntityShape>,
    async_lifts: Vec<AsyncLiftInfo>,
    async_lowers: Vec<AsyncLowerInfo>,
    async_canonical: Vec<AsyncCanonicalPlan>,
    native_async_execution: Option<NativeAsyncExecutionPlan>,
    pub(crate) execution: ComponentExecutionPlan,
}

impl ComponentPlan<'_> {
    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

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

    /// Consume the sealed plan and transfer its normalized world shapes to an
    /// owned manifest. The returned vectors no longer carry plan provenance
    /// and cannot be fed back into runtime graph accounting.
    pub fn into_world_shapes(self) -> (Vec<NamedEntityShape>, Vec<NamedEntityShape>) {
        (self.imports, self.exports)
    }

    pub fn async_lifts(&self) -> &[AsyncLiftInfo] {
        &self.async_lifts
    }

    pub fn async_lowers(&self) -> &[AsyncLowerInfo] {
        &self.async_lowers
    }

    /// Validated, typed async Canonical ABI entries. They remain inert in the
    /// current validation-only profile; a separately versioned executor plan
    /// must complete and revalidate its executable wiring.
    pub fn async_canonical_plans(&self) -> &[AsyncCanonicalPlan] {
        &self.async_canonical
    }

    /// Fully resolved, owned executor wiring for the closed resource-free
    /// native async identity. The profile itself remains validation-only, so
    /// the presence of this plan never makes [`Self::runtime_ready`] true.
    pub fn native_async_execution_plan(&self) -> Option<&NativeAsyncExecutionPlan> {
        self.native_async_execution.as_ref()
    }

    pub fn executable_exports(&self) -> impl Iterator<Item = &ExecutableExportInfo> {
        self.execution.exports.iter().map(|export| &export.info)
    }

    /// The pinned async identity is permanently validation-only. Native async
    /// execution requires a separately versioned executable identity, while
    /// every plan containing an async construct remains inert here. This also
    /// rejects a sync-only payload mislabeled with the async descriptor.
    pub fn runtime_ready(&self) -> bool {
        self.profile == ProfileIdentity::PROFILE_1_SYNC && self.summary.async_abi.is_empty()
    }

    /// C5.3 exposes complete native async wiring for review and executor
    /// construction, but its identity remains deliberately inert until the
    /// executor/admission boundary is sealed.
    pub const fn native_async_runtime_ready(&self) -> bool {
        false
    }

    /// Number of Core runtime instances this Component would instantiate.
    /// Admission adapters use this to apply aggregate ceilings which cannot be
    /// safely multiplied once per instance.
    pub fn runtime_instance_count(&self) -> usize {
        self.native_async_execution.as_ref().map_or_else(
            || self.execution.instances().len(),
            |plan| plan.instances.len(),
        )
    }

    pub fn host_imports(&self) -> impl Iterator<Item = &HostImportInfo> {
        self.execution
            .host_imports
            .iter()
            .map(|import| &import.info)
    }

    pub fn check_world(&self, world: &WorldContract) -> Result<(), WorldError> {
        world.check_component(&self.imports, &self.exports)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InspectionMode {
    SyncExecutable,
    AsyncValidation,
    NativeAsyncResourceFree,
}

impl InspectionMode {
    fn for_profile(profile: ProfileIdentity) -> Option<Self> {
        if profile == ProfileIdentity::PROFILE_1_SYNC {
            Some(Self::SyncExecutable)
        } else if profile == ProfileIdentity::PROFILE_1_ASYNC {
            Some(Self::AsyncValidation)
        } else if profile == ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE {
            Some(Self::NativeAsyncResourceFree)
        } else {
            None
        }
    }

    const fn async_enabled(self) -> bool {
        matches!(self, Self::AsyncValidation | Self::NativeAsyncResourceFree)
    }

    const fn is_native_async(self) -> bool {
        matches!(self, Self::NativeAsyncResourceFree)
    }
}

fn profile_features(mode: InspectionMode) -> WasmFeatures {
    let mut features = WasmFeatures::empty();
    features.set(WasmFeatures::COMPONENT_MODEL, true);
    features.set(WasmFeatures::CM_ASYNC, mode.async_enabled());
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

struct CoreModuleImportDraft {
    module: String,
    field: String,
    kind: CoreModuleImportKind,
    signature: Option<NativeAsyncCoreSignature>,
}

#[derive(Clone, Copy)]
enum CanonicalEffectCheck {
    Lift { type_index: u32, async_: bool },
    Lower { function_index: u32, async_: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoreModuleImportKind {
    Function,
    Memory,
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
    inspect_component_for_profile(bytes, ProfileIdentity::PROFILE_1)
}

/// Inspect bytes under an exact trusted profile descriptor. This explicit
/// entrypoint exists for migration/differential tests; admission accepts only
/// the active identity and never derives it from component-controlled bytes.
pub fn inspect_component_for_profile(
    bytes: &[u8],
    profile: ProfileIdentity,
) -> Result<ComponentPlan<'_>, DecodeError> {
    let mode = InspectionMode::for_profile(profile).ok_or(DecodeError::Unsupported)?;
    if bytes.len() > PROFILE_1_LIMITS.max_component_bytes || bytes.len() > u32::MAX as usize {
        return Err(DecodeError::Limit);
    }
    predecode_component_for_profile(bytes, mode.async_enabled()).map_err(predecode_error)?;
    let mut summary = ComponentSummary {
        bytes: bytes.len() as u32,
        ..ComponentSummary::default()
    };
    let mut modules = Vec::new();
    let mut core_modules = Vec::new();
    let mut core_instances: Vec<Option<CoreInstanceDraft>> = Vec::new();
    let mut core_functions: Vec<Option<CoreFunctionDraft>> = Vec::new();
    let mut core_memories: Vec<Option<CoreExportRef>> = Vec::new();
    let mut component_functions: Vec<Option<ComponentFunctionDraft>> = Vec::new();
    let mut component_instances: Vec<Option<ComponentInstanceDraft>> = Vec::new();
    let mut function_exports = Vec::new();
    let mut instance_exports = Vec::new();
    let mut async_lifts = Vec::new();
    let mut async_lowers = Vec::new();
    let mut async_canonical_drafts = Vec::new();
    let mut canonical_effect_checks = Vec::new();
    let mut canonical_index = 0_u32;
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
                        Instance::Instantiate { module_index, args } => {
                            let module = core_modules.get(module_index as usize).copied().flatten();
                            let mut arguments = Vec::new();
                            arguments
                                .try_reserve_exact(args.len())
                                .map_err(|_| DecodeError::Allocation)?;
                            let mut valid = module.is_some();
                            for argument in args.iter() {
                                if arguments
                                    .iter()
                                    .any(|existing: &CoreInstantiationArgDraft| {
                                        existing.name == argument.name
                                    })
                                {
                                    return Err(DecodeError::InvalidWiring);
                                }
                                let instance = usize::try_from(argument.index)
                                    .map_err(|_| DecodeError::InvalidWiring)?;
                                valid &= instance < core_instances.len();
                                arguments.push(CoreInstantiationArgDraft {
                                    name: copied(argument.name)?,
                                    instance,
                                });
                            }
                            module
                                .filter(|_| valid)
                                .map(|module| CoreInstanceDraft::Instantiate { module, arguments })
                        }
                        Instance::FromExports(exports) => {
                            let mut items = Vec::new();
                            items
                                .try_reserve_exact(exports.len())
                                .map_err(|_| DecodeError::Allocation)?;
                            for export in exports.iter() {
                                if items
                                    .iter()
                                    .any(|item: &CoreInstanceExportDraft| item.name == export.name)
                                {
                                    return Err(DecodeError::InvalidWiring);
                                }
                                let item = match export.kind {
                                    ExternalKind::Func => {
                                        CoreInstanceExportItemDraft::Function(export.index)
                                    }
                                    ExternalKind::Memory => {
                                        CoreInstanceExportItemDraft::Memory(export.index)
                                    }
                                    ExternalKind::Table
                                    | ExternalKind::Global
                                    | ExternalKind::Tag
                                    | ExternalKind::FuncExact => {
                                        return Err(DecodeError::InvalidWiring);
                                    }
                                };
                                items.push(CoreInstanceExportDraft {
                                    name: copied(export.name)?,
                                    item,
                                });
                            }
                            Some(CoreInstanceDraft::FromExports(items))
                        }
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
                            Some(ComponentInstanceDraft::FromExports(functions))
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
                    inspect_type(&ty, &mut summary, mode, 1)?;
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
                                push_core_function_ref(&mut core_functions, instance_index, name)?
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
                                let source = resolve_component_instance_function(
                                    &component_instances,
                                    &component_functions,
                                    instance_index,
                                    name,
                                )?;
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
                    let inspection = inspect_canonical(&function, mode)?;
                    record_canonical(&mut summary, inspection)?;
                    if inspection.adapter {
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
                            type_index,
                            options,
                        } => {
                            canonical_effect_checks
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            canonical_effect_checks.push(CanonicalEffectCheck::Lift {
                                type_index,
                                async_: has_async_option(&options),
                            });
                            component_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            if has_async_option(&options) {
                                let (options, callback) = async_plan_options(&options)?;
                                let callback = callback.ok_or(DecodeError::InvalidWiring)?;
                                async_lifts
                                    .try_reserve(1)
                                    .map_err(|_| DecodeError::Allocation)?;
                                async_lifts.push(AsyncLiftInfo {
                                    canonical_index,
                                    core_function: core_func_index,
                                    function_type: type_index,
                                    callback_core_function: callback,
                                    options,
                                });
                                async_canonical_drafts
                                    .try_reserve(1)
                                    .map_err(|_| DecodeError::Allocation)?;
                                async_canonical_drafts.push(AsyncCanonicalDraft {
                                    canonical_index,
                                    function: AsyncCanonicalFunctionDraft::Lift {
                                        core_function: core_func_index,
                                        function_type: type_index,
                                        callback,
                                        options: async_options_draft(options),
                                    },
                                });
                                component_functions.push(Some(ComponentFunctionDraft::AsyncLift {
                                    canonical_index,
                                }));
                            } else {
                                let options = execution_options(&options)?;
                                component_functions.push(Some(ComponentFunctionDraft::Lift(
                                    LiftDraft {
                                        canonical_index,
                                        core_function: core_func_index,
                                        string_encoding: options.string_encoding,
                                        memory: options.memory,
                                        realloc: options.realloc,
                                        post_return: options.post_return,
                                    },
                                )));
                            }
                        }
                        CanonicalFunction::Lower {
                            func_index,
                            options,
                        } => {
                            canonical_effect_checks
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            canonical_effect_checks.push(CanonicalEffectCheck::Lower {
                                function_index: func_index,
                                async_: has_async_option(&options),
                            });
                            core_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            if has_async_option(&options) {
                                let (options, callback) = async_plan_options(&options)?;
                                if callback.is_some() {
                                    return Err(DecodeError::Unsupported);
                                }
                                async_lowers
                                    .try_reserve(1)
                                    .map_err(|_| DecodeError::Allocation)?;
                                async_lowers.push(AsyncLowerInfo {
                                    canonical_index,
                                    component_function: func_index,
                                    options,
                                });
                                push_async_core_draft(
                                    &mut core_functions,
                                    &mut async_canonical_drafts,
                                    canonical_index,
                                    AsyncCanonicalFunctionDraft::Lower {
                                        component_function: func_index,
                                        options: async_options_draft(options),
                                    },
                                )?;
                            } else {
                                let options = execution_options(&options)?;
                                core_functions.push(Some(CoreFunctionDraft::Lower(LowerDraft {
                                    canonical_index,
                                    component_function: func_index,
                                    string_encoding: options.string_encoding,
                                    memory: options.memory,
                                    realloc: options.realloc,
                                    post_return: options.post_return,
                                })));
                            }
                        }
                        CanonicalFunction::ResourceNew { .. }
                        | CanonicalFunction::ResourceDrop { .. }
                        | CanonicalFunction::ResourceRep { .. } => {
                            core_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            core_functions
                                .push(Some(CoreFunctionDraft::SyncCanonical { canonical_index }));
                        }
                        CanonicalFunction::TaskReturn { result, options } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::TaskReturn {
                                result: result.map(async_value_type_ref).transpose()?,
                                options: async_options_draft(async_plan_options(&options)?.0),
                            },
                        )?,
                        CanonicalFunction::TaskCancel => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::TaskCancel,
                        )?,
                        CanonicalFunction::ContextGet { ty, slot } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::ContextGet {
                                value_type: async_core_value_type(ty)?,
                                slot,
                            },
                        )?,
                        CanonicalFunction::ContextSet { ty, slot } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::ContextSet {
                                value_type: async_core_value_type(ty)?,
                                slot,
                            },
                        )?,
                        CanonicalFunction::ThreadYield { cancellable } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::ThreadYield { cancellable },
                        )?,
                        CanonicalFunction::SubtaskDrop => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::SubtaskDrop,
                        )?,
                        CanonicalFunction::SubtaskCancel { async_ } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::SubtaskCancel { async_ },
                        )?,
                        CanonicalFunction::StreamNew { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::New {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::StreamRead { ty, options } => {
                            let options = async_plan_options(&options)?.0;
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::Read {
                                    type_index: ty,
                                    options: async_options_draft(options),
                                }),
                            )?;
                        }
                        CanonicalFunction::StreamWrite { ty, options } => {
                            let options = async_plan_options(&options)?.0;
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::Write {
                                    type_index: ty,
                                    options: async_options_draft(options),
                                }),
                            )?;
                        }
                        CanonicalFunction::StreamCancelRead { ty, async_ } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::CancelRead {
                                    type_index: ty,
                                    async_,
                                }),
                            )?
                        }
                        CanonicalFunction::StreamCancelWrite { ty, async_ } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Stream(
                                    AsyncStreamDraft::CancelWrite {
                                        type_index: ty,
                                        async_,
                                    },
                                ),
                            )?
                        }
                        CanonicalFunction::StreamDropReadable { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::DropReadable {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::StreamDropWritable { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Stream(AsyncStreamDraft::DropWritable {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::FutureNew { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::New {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::FutureRead { ty, options } => {
                            let options = async_plan_options(&options)?.0;
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::Read {
                                    type_index: ty,
                                    options: async_options_draft(options),
                                }),
                            )?;
                        }
                        CanonicalFunction::FutureWrite { ty, options } => {
                            let options = async_plan_options(&options)?.0;
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::Write {
                                    type_index: ty,
                                    options: async_options_draft(options),
                                }),
                            )?;
                        }
                        CanonicalFunction::FutureCancelRead { ty, async_ } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::CancelRead {
                                    type_index: ty,
                                    async_,
                                }),
                            )?
                        }
                        CanonicalFunction::FutureCancelWrite { ty, async_ } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Future(
                                    AsyncFutureDraft::CancelWrite {
                                        type_index: ty,
                                        async_,
                                    },
                                ),
                            )?
                        }
                        CanonicalFunction::FutureDropReadable { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::DropReadable {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::FutureDropWritable { ty } => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Future(AsyncFutureDraft::DropWritable {
                                type_index: ty,
                            }),
                        )?,
                        CanonicalFunction::WaitableSetNew => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetNew),
                        )?,
                        CanonicalFunction::WaitableSetWait {
                            cancellable,
                            memory,
                        } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Waitable(
                                    AsyncWaitableDraft::SetWait {
                                        cancellable,
                                        memory,
                                    },
                                ),
                            )?;
                        }
                        CanonicalFunction::WaitableSetPoll {
                            cancellable,
                            memory,
                        } => {
                            push_async_core_draft(
                                &mut core_functions,
                                &mut async_canonical_drafts,
                                canonical_index,
                                AsyncCanonicalFunctionDraft::Waitable(
                                    AsyncWaitableDraft::SetPoll {
                                        cancellable,
                                        memory,
                                    },
                                ),
                            )?;
                        }
                        CanonicalFunction::WaitableSetDrop => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetDrop),
                        )?,
                        CanonicalFunction::WaitableJoin => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::Join),
                        )?,
                        CanonicalFunction::BackpressureInc => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::BackpressureInc,
                        )?,
                        CanonicalFunction::BackpressureDec => push_async_core_draft(
                            &mut core_functions,
                            &mut async_canonical_drafts,
                            canonical_index,
                            AsyncCanonicalFunctionDraft::BackpressureDec,
                        )?,
                        CanonicalFunction::ErrorContextNew { .. }
                        | CanonicalFunction::ErrorContextDebugMessage { .. }
                        | CanonicalFunction::ErrorContextDrop
                        | CanonicalFunction::ThreadIndex
                        | CanonicalFunction::ThreadNewIndirect { .. }
                        | CanonicalFunction::ThreadResumeLater
                        | CanonicalFunction::ThreadSuspend { .. }
                        | CanonicalFunction::ThreadSuspendThenResume { .. }
                        | CanonicalFunction::ThreadYieldThenResume { .. }
                        | CanonicalFunction::ThreadSuspendThenPromote { .. }
                        | CanonicalFunction::ThreadYieldThenPromote { .. }
                        | CanonicalFunction::ThreadSpawnRef { .. }
                        | CanonicalFunction::ThreadSpawnIndirect { .. }
                        | CanonicalFunction::ThreadAvailableParallelism => {
                            return Err(DecodeError::Unsupported);
                        }
                    }
                    canonical_index = canonical_index.checked_add(1).ok_or(DecodeError::Limit)?;
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
                        ComponentTypeRef::Module(_) => return Err(DecodeError::Unsupported),
                        ComponentTypeRef::Func(_) => {
                            if mode.is_native_async() {
                                return Err(DecodeError::Unsupported);
                            }
                            component_functions
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            component_functions.push(Some(ComponentFunctionDraft::Import(
                                ImportedFunctionDraft {
                                    interface: None,
                                    function: copied(import.name.name)?,
                                },
                            )));
                        }
                        ComponentTypeRef::Instance(_) => {
                            if mode.is_native_async() {
                                return Err(DecodeError::Unsupported);
                            }
                            component_instances
                                .try_reserve(1)
                                .map_err(|_| DecodeError::Allocation)?;
                            component_instances.push(Some(ComponentInstanceDraft::Import {
                                name: copied(import.name.name)?,
                            }));
                        }
                        ComponentTypeRef::Type(bounds) => {
                            // World-level named value types are inert imports:
                            // they establish the nominal identities used by an
                            // exported async function but bind no runtime host
                            // authority. The final validator and normalized
                            // world graph retain and check their exact shape.
                            require_async(mode)?;
                            if mode.is_native_async() && !matches!(bounds, TypeBounds::Eq(_)) {
                                return Err(DecodeError::Unsupported);
                            }
                        }
                        ComponentTypeRef::Value(_) | ComponentTypeRef::Component(_) => {
                            return Err(DecodeError::Unsupported);
                        }
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

    let types = match Validator::new_with_features(profile_features(mode)).validate_all(bytes) {
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
    check_canonical_effects(&types, &canonical_effect_checks)?;
    check_async_callback_signatures(&types, &async_canonical_drafts)?;
    let mut type_builder = TypeBuilder::default();
    let async_canonical = build_async_canonical_plans(
        &async_canonical_drafts,
        &component_functions,
        &core_functions,
        &core_memories,
        &types,
        &mut type_builder,
    )?;
    let (imports, exports) =
        normalize_component_world_entities(&types, &import_names, &export_names)
            .map_err(shape_error)?;
    let native_async_execution = if mode.is_native_async() {
        Some(build_native_async_execution_plan(
            &modules,
            &core_instances,
            &core_functions,
            &core_memories,
            &component_functions,
            &component_instances,
            &function_exports,
            &instance_exports,
            &async_canonical_drafts,
            summary,
            &types,
            &mut type_builder,
        )?)
    } else {
        None
    };
    let build_runtime = matches!(mode, InspectionMode::SyncExecutable);
    let (instances, component_to_runtime, host_imports) = if build_runtime {
        build_execution_instances(
            &modules,
            &core_instances,
            &core_functions,
            &core_memories,
            &component_functions,
            &types,
            &mut type_builder,
        )?
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    let mut executable_exports = Vec::new();
    executable_exports
        .try_reserve_exact(function_exports.len())
        .map_err(|_| DecodeError::Allocation)?;
    for (name, function_index) in function_exports {
        if !build_runtime {
            continue;
        }
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
            &component_to_runtime,
        )?;
    }
    for (interface_name, instance_index) in instance_exports {
        if !build_runtime {
            continue;
        }
        let instance = component_instances
            .get(instance_index as usize)
            .and_then(Option::as_ref)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentInstanceDraft::FromExports(members) = instance else {
            return Err(DecodeError::InvalidWiring);
        };
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
                &component_to_runtime,
            )?;
        }
    }
    Ok(ComponentPlan {
        profile,
        summary,
        embedded_modules: modules,
        imports,
        exports,
        async_lifts,
        async_lowers,
        async_canonical,
        native_async_execution,
        execution: ComponentExecutionPlan {
            instances,
            exports: executable_exports,
            host_imports,
        },
    })
}

fn check_canonical_effects(
    types: &wasmparser::types::Types,
    checks: &[CanonicalEffectCheck],
) -> Result<(), DecodeError> {
    for check in checks {
        let (declared_async, canonical_async) = match *check {
            CanonicalEffectCheck::Lift { type_index, async_ } => {
                if type_index >= types.as_ref().component_type_count() {
                    return Err(DecodeError::InvalidWiring);
                }
                let ComponentAnyTypeId::Func(function_type) =
                    types.component_any_type_at(type_index)
                else {
                    return Err(DecodeError::InvalidWiring);
                };
                (types[function_type].async_, async_)
            }
            CanonicalEffectCheck::Lower {
                function_index,
                async_,
            } => {
                if function_index >= types.component_function_count() {
                    return Err(DecodeError::InvalidWiring);
                }
                let function_type = types.component_function_at(function_index);
                (types[function_type].async_, async_)
            }
        };
        if declared_async != canonical_async {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(())
}

fn push_async_core_draft(
    core_functions: &mut Vec<Option<CoreFunctionDraft>>,
    drafts: &mut Vec<AsyncCanonicalDraft>,
    canonical_index: u32,
    function: AsyncCanonicalFunctionDraft,
) -> Result<(), DecodeError> {
    core_functions
        .try_reserve(1)
        .map_err(|_| DecodeError::Allocation)?;
    drafts.try_reserve(1).map_err(|_| DecodeError::Allocation)?;
    core_functions.push(Some(CoreFunctionDraft::AsyncCanonical { canonical_index }));
    drafts.push(AsyncCanonicalDraft {
        canonical_index,
        function,
    });
    Ok(())
}

fn check_async_callback_signatures(
    types: &wasmparser::types::Types,
    drafts: &[AsyncCanonicalDraft],
) -> Result<(), DecodeError> {
    for draft in drafts {
        let AsyncCanonicalFunctionDraft::Lift { callback, .. } = draft.function else {
            continue;
        };
        if callback >= types.as_ref().function_count() {
            return Err(DecodeError::InvalidWiring);
        }
        let ty = types[types.as_ref().core_function_at(callback)].unwrap_func();
        if ty.params() != [ValType::I32; 3] || ty.results() != [ValType::I32] {
            return Err(DecodeError::InvalidCallbackSignature);
        }
    }
    Ok(())
}

fn async_options_draft(options: AsyncCanonicalOptions) -> AsyncOptionsDraft {
    AsyncOptionsDraft {
        string_encoding: options.string_encoding,
        async_: options.async_,
        memory: options.memory,
        realloc: options.realloc,
    }
}

fn async_core_value_type(ty: ValType) -> Result<AsyncCoreValueType, DecodeError> {
    match ty {
        ValType::I32 => Ok(AsyncCoreValueType::I32),
        ValType::I64 => Ok(AsyncCoreValueType::I64),
        _ => Err(DecodeError::Unsupported),
    }
}

fn async_value_type_ref(
    ty: wasmparser::ComponentValType,
) -> Result<AsyncComponentValueTypeRef, DecodeError> {
    Ok(match ty {
        wasmparser::ComponentValType::Primitive(ty) => match ty {
            PrimitiveValType::Bool => AsyncComponentValueTypeRef::Bool,
            PrimitiveValType::U8 => AsyncComponentValueTypeRef::U8,
            PrimitiveValType::U16 => AsyncComponentValueTypeRef::U16,
            PrimitiveValType::U32 => AsyncComponentValueTypeRef::U32,
            PrimitiveValType::U64 => AsyncComponentValueTypeRef::U64,
            PrimitiveValType::S8 => AsyncComponentValueTypeRef::S8,
            PrimitiveValType::S16 => AsyncComponentValueTypeRef::S16,
            PrimitiveValType::S32 => AsyncComponentValueTypeRef::S32,
            PrimitiveValType::S64 => AsyncComponentValueTypeRef::S64,
            PrimitiveValType::Char => AsyncComponentValueTypeRef::Char,
            PrimitiveValType::String => AsyncComponentValueTypeRef::String,
            PrimitiveValType::F32 | PrimitiveValType::F64 | PrimitiveValType::ErrorContext => {
                return Err(DecodeError::Unsupported);
            }
        },
        wasmparser::ComponentValType::Type(index) => AsyncComponentValueTypeRef::Defined(index),
    })
}

fn build_async_canonical_plans(
    drafts: &[AsyncCanonicalDraft],
    component_functions: &[Option<ComponentFunctionDraft>],
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<Vec<AsyncCanonicalPlan>, DecodeError> {
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    for draft in drafts {
        let function = match &draft.function {
            AsyncCanonicalFunctionDraft::Lift {
                core_function,
                function_type,
                callback,
                options,
            } => AsyncCanonicalFunctionPlan::Lift {
                core_function: async_core_function_ref(core_functions, *core_function)?,
                function_type: normalize_function_type(types, type_builder, *function_type)?,
                callback: async_core_function_ref(core_functions, *callback)?,
                options: build_async_options(options, core_functions, core_memories)?,
            },
            AsyncCanonicalFunctionDraft::Lower {
                component_function,
                options,
            } => AsyncCanonicalFunctionPlan::Lower {
                component_function: async_component_function_ref(
                    component_functions,
                    *component_function,
                )?,
                function_type: normalize_component_function(
                    types,
                    type_builder,
                    *component_function,
                )?,
                options: build_async_options(options, core_functions, core_memories)?,
            },
            AsyncCanonicalFunctionDraft::TaskReturn { result, options } => {
                AsyncCanonicalFunctionPlan::TaskReturn {
                    result: result
                        .map(|value| async_value_type(types, value))
                        .map(|value| {
                            type_builder
                                .component_value(types, value)
                                .map_err(type_error)
                        })
                        .transpose()?,
                    options: build_async_options(options, core_functions, core_memories)?,
                }
            }
            AsyncCanonicalFunctionDraft::TaskCancel => AsyncCanonicalFunctionPlan::TaskCancel,
            AsyncCanonicalFunctionDraft::ContextGet { value_type, slot } => {
                AsyncCanonicalFunctionPlan::ContextGet {
                    value_type: *value_type,
                    slot: *slot,
                }
            }
            AsyncCanonicalFunctionDraft::ContextSet { value_type, slot } => {
                AsyncCanonicalFunctionPlan::ContextSet {
                    value_type: *value_type,
                    slot: *slot,
                }
            }
            AsyncCanonicalFunctionDraft::SubtaskDrop => AsyncCanonicalFunctionPlan::SubtaskDrop,
            AsyncCanonicalFunctionDraft::SubtaskCancel { async_ } => {
                AsyncCanonicalFunctionPlan::SubtaskCancel { async_: *async_ }
            }
            AsyncCanonicalFunctionDraft::ThreadYield { cancellable } => {
                AsyncCanonicalFunctionPlan::ThreadYield {
                    cancellable: *cancellable,
                }
            }
            AsyncCanonicalFunctionDraft::Stream(stream) => {
                AsyncCanonicalFunctionPlan::Stream(build_async_stream_plan(
                    stream,
                    core_functions,
                    core_memories,
                    types,
                    type_builder,
                )?)
            }
            AsyncCanonicalFunctionDraft::Future(future) => {
                AsyncCanonicalFunctionPlan::Future(build_async_future_plan(
                    future,
                    core_functions,
                    core_memories,
                    types,
                    type_builder,
                )?)
            }
            AsyncCanonicalFunctionDraft::Waitable(waitable) => {
                AsyncCanonicalFunctionPlan::Waitable(build_async_waitable_plan(
                    waitable,
                    core_memories,
                )?)
            }
            AsyncCanonicalFunctionDraft::BackpressureInc => {
                AsyncCanonicalFunctionPlan::BackpressureInc
            }
            AsyncCanonicalFunctionDraft::BackpressureDec => {
                AsyncCanonicalFunctionPlan::BackpressureDec
            }
        };
        plans.push(AsyncCanonicalPlan {
            canonical_index: draft.canonical_index,
            function,
        });
    }
    Ok(plans)
}

fn type_error(error: crate::types::TypeError) -> DecodeError {
    match error {
        crate::types::TypeError::Unsupported => DecodeError::Unsupported,
        crate::types::TypeError::NestingLimit | crate::types::TypeError::DefinitionLimit => {
            DecodeError::Limit
        }
        crate::types::TypeError::Allocation => DecodeError::Allocation,
        crate::types::TypeError::InvalidFunction => DecodeError::InvalidWiring,
    }
}

fn normalize_function_type(
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
    type_index: u32,
) -> Result<crate::types::FunctionType, DecodeError> {
    if type_index >= types.as_ref().component_type_count() {
        return Err(DecodeError::InvalidWiring);
    }
    let ComponentAnyTypeId::Func(function) = types.component_any_type_at(type_index) else {
        return Err(DecodeError::InvalidWiring);
    };
    type_builder.function(types, function).map_err(type_error)
}

fn normalize_component_function(
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
    function_index: u32,
) -> Result<crate::types::FunctionType, DecodeError> {
    if function_index >= types.component_function_count() {
        return Err(DecodeError::InvalidWiring);
    }
    type_builder
        .function(types, types.component_function_at(function_index))
        .map_err(type_error)
}

fn async_value_type(
    types: &wasmparser::types::Types,
    value: AsyncComponentValueTypeRef,
) -> wasmparser::component_types::ComponentValType {
    use wasmparser::component_types::ComponentValType;
    ComponentValType::Primitive(match value {
        AsyncComponentValueTypeRef::Bool => PrimitiveValType::Bool,
        AsyncComponentValueTypeRef::U8 => PrimitiveValType::U8,
        AsyncComponentValueTypeRef::U16 => PrimitiveValType::U16,
        AsyncComponentValueTypeRef::U32 => PrimitiveValType::U32,
        AsyncComponentValueTypeRef::U64 => PrimitiveValType::U64,
        AsyncComponentValueTypeRef::S8 => PrimitiveValType::S8,
        AsyncComponentValueTypeRef::S16 => PrimitiveValType::S16,
        AsyncComponentValueTypeRef::S32 => PrimitiveValType::S32,
        AsyncComponentValueTypeRef::S64 => PrimitiveValType::S64,
        AsyncComponentValueTypeRef::Char => PrimitiveValType::Char,
        AsyncComponentValueTypeRef::String => PrimitiveValType::String,
        AsyncComponentValueTypeRef::Defined(index) => {
            return ComponentValType::Type(types.component_defined_type_at(index));
        }
    })
}

fn normalize_async_defined_type(
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
    type_index: u32,
    stream: bool,
) -> Result<ValueType, DecodeError> {
    if type_index >= types.as_ref().component_type_count() {
        return Err(DecodeError::InvalidWiring);
    }
    let value = type_builder
        .defined_value(types, types.component_defined_type_at(type_index))
        .map_err(type_error)?;
    if matches!(
        (&value, stream),
        (ValueType::Stream { .. }, true) | (ValueType::Future { .. }, false)
    ) {
        Ok(value)
    } else {
        Err(DecodeError::InvalidWiring)
    }
}

fn async_component_function_ref(
    functions: &[Option<ComponentFunctionDraft>],
    index: u32,
) -> Result<AsyncComponentFunctionRef, DecodeError> {
    let source = match functions.get(index as usize).and_then(Option::as_ref) {
        Some(ComponentFunctionDraft::Import(import)) => AsyncComponentFunctionSource::Import {
            interface: import.interface.as_deref().map(copied).transpose()?,
            function: copied(&import.function)?,
        },
        Some(ComponentFunctionDraft::Lift(lift)) => AsyncComponentFunctionSource::Lift {
            canonical_index: lift.canonical_index,
            core_function: lift.core_function,
        },
        Some(ComponentFunctionDraft::AsyncLift { canonical_index }) => {
            AsyncComponentFunctionSource::AsyncLift {
                canonical_index: *canonical_index,
            }
        }
        None => return Err(DecodeError::InvalidWiring),
    };
    Ok(AsyncComponentFunctionRef {
        component_function: index,
        source,
    })
}

fn async_core_function_ref(
    functions: &[Option<CoreFunctionDraft>],
    index: u32,
) -> Result<AsyncCoreFunctionRef, DecodeError> {
    let source = match functions.get(index as usize).and_then(Option::as_ref) {
        Some(CoreFunctionDraft::Export(reference)) => {
            AsyncCoreFunctionSource::Export(async_core_export_ref(reference)?)
        }
        Some(CoreFunctionDraft::Lower(lower)) => AsyncCoreFunctionSource::Lower {
            canonical_index: lower.canonical_index,
            component_function: lower.component_function,
        },
        Some(CoreFunctionDraft::SyncCanonical { canonical_index }) => {
            AsyncCoreFunctionSource::SyncCanonical {
                canonical_index: *canonical_index,
            }
        }
        Some(CoreFunctionDraft::AsyncCanonical { canonical_index }) => {
            AsyncCoreFunctionSource::AsyncCanonical {
                canonical_index: *canonical_index,
            }
        }
        None => return Err(DecodeError::InvalidWiring),
    };
    Ok(AsyncCoreFunctionRef {
        core_function: index,
        source,
    })
}

fn async_core_export_ref(reference: &CoreExportRef) -> Result<AsyncCoreExportRef, DecodeError> {
    Ok(AsyncCoreExportRef {
        core_instance: u32::try_from(reference.instance).map_err(|_| DecodeError::Limit)?,
        export: copied(&reference.name)?,
    })
}

fn async_core_memory_ref(
    memories: &[Option<CoreExportRef>],
    index: u32,
) -> Result<AsyncCoreMemoryRef, DecodeError> {
    Ok(AsyncCoreMemoryRef {
        core_memory: index,
        source: async_core_export_ref(resolve_core_ref(memories, index)?)?,
    })
}

fn build_async_options(
    options: &AsyncOptionsDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
) -> Result<AsyncCanonicalOptionsPlan, DecodeError> {
    Ok(AsyncCanonicalOptionsPlan {
        string_encoding: options.string_encoding,
        async_: options.async_,
        memory: options
            .memory
            .map(|index| async_core_memory_ref(core_memories, index))
            .transpose()?,
        realloc: options
            .realloc
            .map(|index| async_core_function_ref(core_functions, index))
            .transpose()?,
    })
}

fn build_async_stream_plan(
    draft: &AsyncStreamDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<AsyncStreamPlan, DecodeError> {
    Ok(match draft {
        AsyncStreamDraft::New { type_index } => AsyncStreamPlan::New {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
        AsyncStreamDraft::Read {
            type_index,
            options,
        } => AsyncStreamPlan::Read {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            options: build_async_options(options, core_functions, core_memories)?,
        },
        AsyncStreamDraft::Write {
            type_index,
            options,
        } => AsyncStreamPlan::Write {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            options: build_async_options(options, core_functions, core_memories)?,
        },
        AsyncStreamDraft::CancelRead { type_index, async_ } => AsyncStreamPlan::CancelRead {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            async_: *async_,
        },
        AsyncStreamDraft::CancelWrite { type_index, async_ } => AsyncStreamPlan::CancelWrite {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            async_: *async_,
        },
        AsyncStreamDraft::DropReadable { type_index } => AsyncStreamPlan::DropReadable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
        AsyncStreamDraft::DropWritable { type_index } => AsyncStreamPlan::DropWritable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
    })
}

fn build_async_future_plan(
    draft: &AsyncFutureDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<AsyncFuturePlan, DecodeError> {
    Ok(match draft {
        AsyncFutureDraft::New { type_index } => AsyncFuturePlan::New {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
        AsyncFutureDraft::Read {
            type_index,
            options,
        } => AsyncFuturePlan::Read {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            options: build_async_options(options, core_functions, core_memories)?,
        },
        AsyncFutureDraft::Write {
            type_index,
            options,
        } => AsyncFuturePlan::Write {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            options: build_async_options(options, core_functions, core_memories)?,
        },
        AsyncFutureDraft::CancelRead { type_index, async_ } => AsyncFuturePlan::CancelRead {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            async_: *async_,
        },
        AsyncFutureDraft::CancelWrite { type_index, async_ } => AsyncFuturePlan::CancelWrite {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            async_: *async_,
        },
        AsyncFutureDraft::DropReadable { type_index } => AsyncFuturePlan::DropReadable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
        AsyncFutureDraft::DropWritable { type_index } => AsyncFuturePlan::DropWritable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
    })
}

fn build_async_waitable_plan(
    draft: &AsyncWaitableDraft,
    core_memories: &[Option<CoreExportRef>],
) -> Result<AsyncWaitablePlan, DecodeError> {
    Ok(match draft {
        AsyncWaitableDraft::SetNew => AsyncWaitablePlan::SetNew,
        AsyncWaitableDraft::SetWait {
            cancellable,
            memory,
        } => AsyncWaitablePlan::SetWait {
            cancellable: *cancellable,
            memory: async_core_memory_ref(core_memories, *memory)?,
        },
        AsyncWaitableDraft::SetPoll {
            cancellable,
            memory,
        } => AsyncWaitablePlan::SetPoll {
            cancellable: *cancellable,
            memory: async_core_memory_ref(core_memories, *memory)?,
        },
        AsyncWaitableDraft::SetDrop => AsyncWaitablePlan::SetDrop,
        AsyncWaitableDraft::Join => AsyncWaitablePlan::Join,
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

type NativeExecutionInstances = (
    Vec<NativeAsyncCoreInstancePlan>,
    Vec<Option<usize>>,
    Vec<NativeAsyncCanonicalImportBridge>,
);

fn native_canonical_position(
    drafts: &[AsyncCanonicalDraft],
    canonical_index: u32,
) -> Result<u32, DecodeError> {
    let position = drafts
        .iter()
        .position(|draft| draft.canonical_index == canonical_index)
        .ok_or(DecodeError::InvalidWiring)?;
    u32::try_from(position).map_err(|_| DecodeError::Limit)
}

fn native_builtin_draft(draft: &AsyncCanonicalFunctionDraft) -> bool {
    matches!(
        draft,
        AsyncCanonicalFunctionDraft::TaskReturn { .. }
            | AsyncCanonicalFunctionDraft::TaskCancel
            | AsyncCanonicalFunctionDraft::Stream(_)
            | AsyncCanonicalFunctionDraft::Future(_)
            | AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetNew)
            | AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetDrop)
            | AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::Join)
    )
}

fn validate_native_synthetic_instance(
    exports: &[CoreInstanceExportDraft],
    core_functions: &[Option<CoreFunctionDraft>],
    canonical_drafts: &[AsyncCanonicalDraft],
) -> Result<(), DecodeError> {
    for export in exports {
        let CoreInstanceExportItemDraft::Function(index) = &export.item else {
            return Err(DecodeError::Unsupported);
        };
        let function = core_functions
            .get(*index as usize)
            .and_then(Option::as_ref)
            .ok_or(DecodeError::InvalidWiring)?;
        let CoreFunctionDraft::AsyncCanonical { canonical_index } = function else {
            return Err(DecodeError::Unsupported);
        };
        let canonical = native_canonical_position(canonical_drafts, *canonical_index)?;
        if !native_builtin_draft(
            &canonical_drafts
                .get(canonical as usize)
                .ok_or(DecodeError::InvalidWiring)?
                .function,
        ) {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(())
}

fn build_native_async_instances(
    modules: &[&[u8]],
    drafts: &[Option<CoreInstanceDraft>],
    core_functions: &[Option<CoreFunctionDraft>],
    canonical_drafts: &[AsyncCanonicalDraft],
) -> Result<NativeExecutionInstances, DecodeError> {
    let mut instances = Vec::new();
    instances
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    let mut component_to_runtime = Vec::new();
    component_to_runtime
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    for draft in drafts {
        match draft.as_ref().ok_or(DecodeError::InvalidWiring)? {
            CoreInstanceDraft::Instantiate { module, .. } => {
                if *module >= modules.len() {
                    return Err(DecodeError::InvalidWiring);
                }
                let runtime = instances.len();
                component_to_runtime.push(Some(runtime));
                instances.push(NativeAsyncCoreInstancePlan {
                    module: *module,
                    imports: Vec::new(),
                });
            }
            CoreInstanceDraft::FromExports(exports) => {
                validate_native_synthetic_instance(exports, core_functions, canonical_drafts)?;
                component_to_runtime.push(None);
            }
        }
    }

    let mut bridges = Vec::new();
    for (component_instance, draft) in drafts.iter().enumerate() {
        let Some(CoreInstanceDraft::Instantiate { module, arguments }) = draft.as_ref() else {
            continue;
        };
        let runtime_instance = component_to_runtime
            .get(component_instance)
            .copied()
            .flatten()
            .ok_or(DecodeError::InvalidWiring)?;
        let module_imports = core_module_imports(modules[*module])?;
        for argument in arguments {
            if argument.instance >= component_instance
                || !module_imports
                    .iter()
                    .any(|import| import.module == argument.name)
            {
                return Err(DecodeError::InvalidWiring);
            }
            let source = drafts
                .get(argument.instance)
                .and_then(Option::as_ref)
                .ok_or(DecodeError::InvalidWiring)?;
            match source {
                CoreInstanceDraft::Instantiate { .. } => {
                    let source_runtime = component_to_runtime
                        .get(argument.instance)
                        .copied()
                        .flatten()
                        .ok_or(DecodeError::InvalidWiring)?;
                    if source_runtime >= runtime_instance {
                        return Err(DecodeError::InvalidWiring);
                    }
                }
                CoreInstanceDraft::FromExports(exports) => {
                    for export in exports {
                        let import = module_imports
                            .iter()
                            .find(|import| {
                                import.module == argument.name && import.field == export.name
                            })
                            .ok_or(DecodeError::InvalidWiring)?;
                        if !core_export_kind_matches(import.kind, &export.item) {
                            return Err(DecodeError::InvalidWiring);
                        }
                    }
                }
            }
        }

        instances
            .get_mut(runtime_instance)
            .ok_or(DecodeError::InvalidWiring)?
            .imports
            .try_reserve_exact(module_imports.len())
            .map_err(|_| DecodeError::Allocation)?;
        for module_import in module_imports {
            let argument = arguments
                .iter()
                .find(|argument| argument.name == module_import.module)
                .ok_or(DecodeError::InvalidWiring)?;
            let source = drafts
                .get(argument.instance)
                .and_then(Option::as_ref)
                .ok_or(DecodeError::InvalidWiring)?;
            let import_plan = match source {
                CoreInstanceDraft::Instantiate { .. } => {
                    let source_runtime = component_to_runtime
                        .get(argument.instance)
                        .copied()
                        .flatten()
                        .ok_or(DecodeError::InvalidWiring)?;
                    if source_runtime >= runtime_instance {
                        return Err(DecodeError::InvalidWiring);
                    }
                    NativeAsyncCoreImportPlan::InstanceExport {
                        module: module_import.module,
                        field: copied(&module_import.field)?,
                        core_instance: source_runtime,
                        export: module_import.field,
                    }
                }
                CoreInstanceDraft::FromExports(exports) => {
                    let export = exports
                        .iter()
                        .find(|export| export.name == module_import.field)
                        .ok_or(DecodeError::InvalidWiring)?;
                    if !core_export_kind_matches(module_import.kind, &export.item) {
                        return Err(DecodeError::InvalidWiring);
                    }
                    match &export.item {
                        CoreInstanceExportItemDraft::Function(index) => {
                            let function = core_functions
                                .get(*index as usize)
                                .and_then(Option::as_ref)
                                .ok_or(DecodeError::InvalidWiring)?;
                            match function {
                                CoreFunctionDraft::Export(_) => {
                                    return Err(DecodeError::Unsupported);
                                }
                                CoreFunctionDraft::AsyncCanonical { canonical_index } => {
                                    let canonical = native_canonical_position(
                                        canonical_drafts,
                                        *canonical_index,
                                    )?;
                                    let draft = canonical_drafts
                                        .get(canonical as usize)
                                        .ok_or(DecodeError::InvalidWiring)?;
                                    if !native_builtin_draft(&draft.function) {
                                        return Err(DecodeError::InvalidWiring);
                                    }
                                    if bridges.len() >= PROFILE_1_LIMITS.max_imports as usize {
                                        return Err(DecodeError::Limit);
                                    }
                                    let bridge = u32::try_from(bridges.len())
                                        .map_err(|_| DecodeError::Limit)?;
                                    let signature = module_import
                                        .signature
                                        .ok_or(DecodeError::InvalidWiring)?;
                                    bridges
                                        .try_reserve(1)
                                        .map_err(|_| DecodeError::Allocation)?;
                                    bridges.push(NativeAsyncCanonicalImportBridge {
                                        core_instance: runtime_instance,
                                        core_module: module_import.module,
                                        core_field: module_import.field,
                                        canonical,
                                        signature,
                                    });
                                    NativeAsyncCoreImportPlan::Canonical { bridge }
                                }
                                CoreFunctionDraft::Lower(_)
                                | CoreFunctionDraft::SyncCanonical { .. } => {
                                    return Err(DecodeError::Unsupported);
                                }
                            }
                        }
                        CoreInstanceExportItemDraft::Memory(_) => {
                            return Err(DecodeError::Unsupported);
                        }
                    }
                }
            };
            instances[runtime_instance].imports.push(import_plan);
        }
    }

    let canonical_imports = instances
        .iter()
        .flat_map(|instance| instance.imports.iter())
        .filter(|import| matches!(import, NativeAsyncCoreImportPlan::Canonical { .. }))
        .count();
    if canonical_imports != bridges.len() {
        return Err(DecodeError::InvalidWiring);
    }
    for (position, bridge) in bridges.iter().enumerate() {
        let expected = u32::try_from(position).map_err(|_| DecodeError::Limit)?;
        let matching = instances
            .get(bridge.core_instance)
            .ok_or(DecodeError::InvalidWiring)?
            .imports
            .iter()
            .filter(|import| {
                matches!(import, NativeAsyncCoreImportPlan::Canonical { bridge } if *bridge == expected)
            })
            .count();
        if matching != 1 {
            return Err(DecodeError::InvalidWiring);
        }
    }
    Ok((instances, component_to_runtime, bridges))
}

#[allow(clippy::too_many_arguments)]
fn build_native_async_execution_plan(
    modules: &[&[u8]],
    core_instance_drafts: &[Option<CoreInstanceDraft>],
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_functions: &[Option<ComponentFunctionDraft>],
    component_instances: &[Option<ComponentInstanceDraft>],
    function_exports: &[(String, u32)],
    instance_exports: &[(String, u32)],
    canonical_drafts: &[AsyncCanonicalDraft],
    summary: ComponentSummary,
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<NativeAsyncExecutionPlan, DecodeError> {
    if summary.resources != 0
        || summary.async_abi.async_lowers != 0
        || summary.async_abi.context_builtins != 0
        || summary.async_abi.subtask_builtins != 0
        || summary.async_abi.cooperative_yields != 0
        || summary.async_abi.backpressure_builtins != 0
        || canonical_drafts.len() != summary.canonical_functions as usize
    {
        return Err(DecodeError::Unsupported);
    }
    let (instances, component_to_runtime, canonical_import_bridges) = build_native_async_instances(
        modules,
        core_instance_drafts,
        core_functions,
        canonical_drafts,
    )?;
    let canonical = build_native_async_canonical_plans(
        canonical_drafts,
        core_functions,
        core_memories,
        &component_to_runtime,
        types,
        type_builder,
    )?;
    if canonical.len() != summary.canonical_functions as usize {
        return Err(DecodeError::InvalidWiring);
    }
    for bridge in &canonical_import_bridges {
        if matches!(
            canonical.get(bridge.canonical as usize),
            Some(NativeAsyncCanonicalPlan {
                function: NativeAsyncCanonicalFunctionPlan::Lift { .. },
                ..
            })
        ) || canonical.get(bridge.canonical as usize).is_none()
        {
            return Err(DecodeError::InvalidWiring);
        }
    }
    let exports = build_native_async_exports(
        function_exports,
        instance_exports,
        component_instances,
        component_functions,
        canonical_drafts,
        &canonical,
        types,
    )?;
    Ok(NativeAsyncExecutionPlan {
        instances,
        canonical,
        canonical_import_bridges,
        exports,
    })
}

fn native_core_export_ref(
    reference: &CoreExportRef,
    component_to_runtime: &[Option<usize>],
) -> Result<NativeAsyncCoreExportRef, DecodeError> {
    let core_instance = component_to_runtime
        .get(reference.instance)
        .copied()
        .flatten()
        .ok_or(DecodeError::InvalidWiring)?;
    Ok(NativeAsyncCoreExportRef {
        core_instance,
        export: copied(&reference.name)?,
    })
}

fn native_core_function_export(
    functions: &[Option<CoreFunctionDraft>],
    index: u32,
    component_to_runtime: &[Option<usize>],
) -> Result<NativeAsyncCoreExportRef, DecodeError> {
    let Some(CoreFunctionDraft::Export(reference)) =
        functions.get(index as usize).and_then(Option::as_ref)
    else {
        return Err(DecodeError::InvalidWiring);
    };
    native_core_export_ref(reference, component_to_runtime)
}

fn native_async_options(
    options: &AsyncOptionsDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_to_runtime: &[Option<usize>],
) -> Result<NativeAsyncCanonicalOptionsPlan, DecodeError> {
    Ok(NativeAsyncCanonicalOptionsPlan {
        string_encoding: options.string_encoding,
        async_: options.async_,
        memory: options
            .memory
            .map(|index| {
                native_core_export_ref(
                    resolve_core_ref(core_memories, index)?,
                    component_to_runtime,
                )
            })
            .transpose()?,
        realloc: options
            .realloc
            .map(|index| native_core_function_export(core_functions, index, component_to_runtime))
            .transpose()?,
    })
}

fn build_native_async_canonical_plans(
    drafts: &[AsyncCanonicalDraft],
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_to_runtime: &[Option<usize>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<Vec<NativeAsyncCanonicalPlan>, DecodeError> {
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    for (position, draft) in drafts.iter().enumerate() {
        if draft.canonical_index != u32::try_from(position).map_err(|_| DecodeError::Limit)? {
            return Err(DecodeError::InvalidWiring);
        }
        let function = match &draft.function {
            AsyncCanonicalFunctionDraft::Lift {
                core_function,
                function_type,
                callback,
                options,
            } => NativeAsyncCanonicalFunctionPlan::Lift {
                core_function: native_core_function_export(
                    core_functions,
                    *core_function,
                    component_to_runtime,
                )?,
                function_type: normalize_function_type(types, type_builder, *function_type)?,
                callback: native_core_function_export(
                    core_functions,
                    *callback,
                    component_to_runtime,
                )?,
                options: native_async_options(
                    options,
                    core_functions,
                    core_memories,
                    component_to_runtime,
                )?,
            },
            AsyncCanonicalFunctionDraft::TaskReturn { result, options } => {
                NativeAsyncCanonicalFunctionPlan::TaskReturn {
                    result: result
                        .map(|value| async_value_type(types, value))
                        .map(|value| {
                            type_builder
                                .component_value(types, value)
                                .map_err(type_error)
                        })
                        .transpose()?,
                    options: native_async_options(
                        options,
                        core_functions,
                        core_memories,
                        component_to_runtime,
                    )?,
                }
            }
            AsyncCanonicalFunctionDraft::TaskCancel => NativeAsyncCanonicalFunctionPlan::TaskCancel,
            AsyncCanonicalFunctionDraft::Stream(stream) => {
                NativeAsyncCanonicalFunctionPlan::Stream(build_native_async_stream_plan(
                    stream,
                    core_functions,
                    core_memories,
                    component_to_runtime,
                    types,
                    type_builder,
                )?)
            }
            AsyncCanonicalFunctionDraft::Future(future) => {
                NativeAsyncCanonicalFunctionPlan::Future(build_native_async_future_plan(
                    future,
                    core_functions,
                    core_memories,
                    component_to_runtime,
                    types,
                    type_builder,
                )?)
            }
            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetNew) => {
                NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetNew)
            }
            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetDrop) => {
                NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetDrop)
            }
            AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::Join) => {
                NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::Join)
            }
            AsyncCanonicalFunctionDraft::Lower { .. }
            | AsyncCanonicalFunctionDraft::ContextGet { .. }
            | AsyncCanonicalFunctionDraft::ContextSet { .. }
            | AsyncCanonicalFunctionDraft::SubtaskDrop
            | AsyncCanonicalFunctionDraft::SubtaskCancel { .. }
            | AsyncCanonicalFunctionDraft::ThreadYield { .. }
            | AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetWait { .. })
            | AsyncCanonicalFunctionDraft::Waitable(AsyncWaitableDraft::SetPoll { .. })
            | AsyncCanonicalFunctionDraft::BackpressureInc
            | AsyncCanonicalFunctionDraft::BackpressureDec => {
                return Err(DecodeError::Unsupported);
            }
        };
        plans.push(NativeAsyncCanonicalPlan {
            canonical_index: draft.canonical_index,
            function,
        });
    }
    Ok(plans)
}

fn build_native_async_stream_plan(
    draft: &AsyncStreamDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_to_runtime: &[Option<usize>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<NativeAsyncStreamPlan, DecodeError> {
    Ok(match draft {
        AsyncStreamDraft::New { type_index } => NativeAsyncStreamPlan::New {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
        AsyncStreamDraft::Read {
            type_index,
            options,
        } => NativeAsyncStreamPlan::Read {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            options: native_async_options(
                options,
                core_functions,
                core_memories,
                component_to_runtime,
            )?,
        },
        AsyncStreamDraft::Write {
            type_index,
            options,
        } => NativeAsyncStreamPlan::Write {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            options: native_async_options(
                options,
                core_functions,
                core_memories,
                component_to_runtime,
            )?,
        },
        AsyncStreamDraft::CancelRead { type_index, async_ } => {
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            NativeAsyncStreamPlan::CancelRead {
                type_index: *type_index,
                value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            }
        }
        AsyncStreamDraft::CancelWrite { type_index, async_ } => {
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            NativeAsyncStreamPlan::CancelWrite {
                type_index: *type_index,
                value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
            }
        }
        AsyncStreamDraft::DropReadable { type_index } => NativeAsyncStreamPlan::DropReadable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
        AsyncStreamDraft::DropWritable { type_index } => NativeAsyncStreamPlan::DropWritable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, true)?,
        },
    })
}

fn build_native_async_future_plan(
    draft: &AsyncFutureDraft,
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_to_runtime: &[Option<usize>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<NativeAsyncFuturePlan, DecodeError> {
    Ok(match draft {
        AsyncFutureDraft::New { type_index } => NativeAsyncFuturePlan::New {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
        AsyncFutureDraft::Read {
            type_index,
            options,
        } => NativeAsyncFuturePlan::Read {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            options: native_async_options(
                options,
                core_functions,
                core_memories,
                component_to_runtime,
            )?,
        },
        AsyncFutureDraft::Write {
            type_index,
            options,
        } => NativeAsyncFuturePlan::Write {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            options: native_async_options(
                options,
                core_functions,
                core_memories,
                component_to_runtime,
            )?,
        },
        AsyncFutureDraft::CancelRead { type_index, async_ } => {
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            NativeAsyncFuturePlan::CancelRead {
                type_index: *type_index,
                value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            }
        }
        AsyncFutureDraft::CancelWrite { type_index, async_ } => {
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            NativeAsyncFuturePlan::CancelWrite {
                type_index: *type_index,
                value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
            }
        }
        AsyncFutureDraft::DropReadable { type_index } => NativeAsyncFuturePlan::DropReadable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
        AsyncFutureDraft::DropWritable { type_index } => NativeAsyncFuturePlan::DropWritable {
            type_index: *type_index,
            value_type: normalize_async_defined_type(types, type_builder, *type_index, false)?,
        },
    })
}

fn build_native_async_exports(
    function_exports: &[(String, u32)],
    instance_exports: &[(String, u32)],
    component_instances: &[Option<ComponentInstanceDraft>],
    component_functions: &[Option<ComponentFunctionDraft>],
    canonical_drafts: &[AsyncCanonicalDraft],
    canonical: &[NativeAsyncCanonicalPlan],
    types: &wasmparser::types::Types,
) -> Result<Vec<NativeAsyncExportPlan>, DecodeError> {
    let mut exports = Vec::new();
    exports
        .try_reserve_exact(function_exports.len())
        .map_err(|_| DecodeError::Allocation)?;
    for (name, function_index) in function_exports {
        push_native_async_export(
            &mut exports,
            name,
            *function_index,
            component_functions,
            canonical_drafts,
            canonical,
        )?;
    }
    for (interface_name, instance_index) in instance_exports {
        let instance = component_instances
            .get(*instance_index as usize)
            .and_then(Option::as_ref)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentInstanceDraft::FromExports(members) = instance else {
            return Err(DecodeError::InvalidWiring);
        };
        let item = types
            .component_item_for_export(interface_name)
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
            if !matches!(member.ty, ComponentEntityType::Func(_)) {
                continue;
            }
            let mut qualified = copied(interface_name)?;
            qualified
                .try_reserve(member_name.len() + 1)
                .map_err(|_| DecodeError::Allocation)?;
            qualified.push('#');
            qualified.push_str(member_name);
            push_native_async_export(
                &mut exports,
                &qualified,
                *function_index,
                component_functions,
                canonical_drafts,
                canonical,
            )?;
        }
    }
    Ok(exports)
}

fn push_native_async_export(
    exports: &mut Vec<NativeAsyncExportPlan>,
    name: &str,
    function_index: u32,
    component_functions: &[Option<ComponentFunctionDraft>],
    canonical_drafts: &[AsyncCanonicalDraft],
    canonical: &[NativeAsyncCanonicalPlan],
) -> Result<(), DecodeError> {
    let Some(ComponentFunctionDraft::AsyncLift { canonical_index }) = component_functions
        .get(function_index as usize)
        .and_then(Option::as_ref)
    else {
        return Err(DecodeError::InvalidWiring);
    };
    let canonical_position = native_canonical_position(canonical_drafts, *canonical_index)?;
    if !matches!(
        canonical.get(canonical_position as usize),
        Some(NativeAsyncCanonicalPlan {
            function: NativeAsyncCanonicalFunctionPlan::Lift { .. },
            ..
        })
    ) {
        return Err(DecodeError::InvalidWiring);
    }
    if exports.len() >= PROFILE_1_LIMITS.max_canonical_functions as usize
        || exports.iter().any(|export| export.name == name)
    {
        return Err(DecodeError::InvalidWiring);
    }
    exports
        .try_reserve(1)
        .map_err(|_| DecodeError::Allocation)?;
    exports.push(NativeAsyncExportPlan {
        name: copied(name)?,
        canonical: canonical_position,
    });
    Ok(())
}

type ExecutionInstances = (
    Vec<CoreInstancePlan>,
    Vec<Option<usize>>,
    Vec<HostImportPlan>,
);

#[allow(clippy::too_many_arguments)]
fn build_execution_instances(
    modules: &[&[u8]],
    drafts: &[Option<CoreInstanceDraft>],
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_functions: &[Option<ComponentFunctionDraft>],
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
) -> Result<ExecutionInstances, DecodeError> {
    let mut instances = Vec::new();
    instances
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    let mut component_to_runtime = Vec::new();
    component_to_runtime
        .try_reserve_exact(drafts.len())
        .map_err(|_| DecodeError::Allocation)?;
    for draft in drafts {
        match draft.as_ref().ok_or(DecodeError::InvalidWiring)? {
            CoreInstanceDraft::Instantiate { module, .. } => {
                if *module >= modules.len() {
                    return Err(DecodeError::InvalidWiring);
                }
                let runtime = instances.len();
                component_to_runtime.push(Some(runtime));
                instances.push(CoreInstancePlan {
                    module: *module,
                    imports: Vec::new(),
                });
            }
            CoreInstanceDraft::FromExports(_) => component_to_runtime.push(None),
        }
    }

    let mut host_imports = Vec::new();
    for (component_instance, draft) in drafts.iter().enumerate() {
        let Some(CoreInstanceDraft::Instantiate { module, arguments }) = draft.as_ref() else {
            continue;
        };
        let runtime_instance = component_to_runtime
            .get(component_instance)
            .copied()
            .flatten()
            .ok_or(DecodeError::InvalidWiring)?;
        let module_imports = core_module_imports(modules[*module])?;
        for argument in arguments {
            if argument.instance >= component_instance
                || !module_imports
                    .iter()
                    .any(|import| import.module == argument.name)
            {
                return Err(DecodeError::InvalidWiring);
            }
            let source = drafts
                .get(argument.instance)
                .and_then(Option::as_ref)
                .ok_or(DecodeError::InvalidWiring)?;
            match source {
                CoreInstanceDraft::Instantiate { .. } => {
                    let source_runtime = component_to_runtime
                        .get(argument.instance)
                        .copied()
                        .flatten()
                        .ok_or(DecodeError::InvalidWiring)?;
                    if source_runtime >= runtime_instance {
                        return Err(DecodeError::InvalidWiring);
                    }
                }
                CoreInstanceDraft::FromExports(exports) => {
                    for export in exports {
                        let import = module_imports
                            .iter()
                            .find(|import| {
                                import.module == argument.name && import.field == export.name
                            })
                            .ok_or(DecodeError::InvalidWiring)?;
                        if !core_export_kind_matches(import.kind, &export.item) {
                            return Err(DecodeError::InvalidWiring);
                        }
                    }
                }
            }
        }

        instances
            .get_mut(runtime_instance)
            .ok_or(DecodeError::InvalidWiring)?
            .imports
            .try_reserve_exact(module_imports.len())
            .map_err(|_| DecodeError::Allocation)?;
        for module_import in module_imports {
            let argument = arguments
                .iter()
                .find(|argument| argument.name == module_import.module)
                .ok_or(DecodeError::InvalidWiring)?;
            let source = drafts
                .get(argument.instance)
                .and_then(Option::as_ref)
                .ok_or(DecodeError::InvalidWiring)?;
            let import_plan = match source {
                CoreInstanceDraft::Instantiate { .. } => {
                    let source_runtime = component_to_runtime
                        .get(argument.instance)
                        .copied()
                        .flatten()
                        .ok_or(DecodeError::InvalidWiring)?;
                    if source_runtime >= runtime_instance {
                        return Err(DecodeError::InvalidWiring);
                    }
                    CoreImportPlan::InstanceExport {
                        module: module_import.module,
                        field: copied(&module_import.field)?,
                        core_instance: source_runtime,
                        export: module_import.field,
                    }
                }
                CoreInstanceDraft::FromExports(exports) => {
                    let export = exports
                        .iter()
                        .find(|export| export.name == module_import.field)
                        .ok_or(DecodeError::InvalidWiring)?;
                    if !core_export_kind_matches(module_import.kind, &export.item) {
                        return Err(DecodeError::InvalidWiring);
                    }
                    match &export.item {
                        CoreInstanceExportItemDraft::Function(index) => {
                            let function = core_functions
                                .get(*index as usize)
                                .and_then(Option::as_ref)
                                .ok_or(DecodeError::InvalidWiring)?;
                            match function {
                                CoreFunctionDraft::Export(reference) => {
                                    let source =
                                        host_core_export(reference, &component_to_runtime)?;
                                    if source.core_instance >= runtime_instance {
                                        return Err(DecodeError::InvalidWiring);
                                    }
                                    CoreImportPlan::InstanceExport {
                                        module: module_import.module,
                                        field: module_import.field,
                                        core_instance: source.core_instance,
                                        export: source.export,
                                    }
                                }
                                CoreFunctionDraft::Lower(lower) => {
                                    let imported =
                                        imported_component_function(component_functions, *lower)?;
                                    let function_type =
                                        imported_function_type(types, type_builder, imported)?;
                                    require_lower_options(&function_type, lower)?;
                                    let memory = lower
                                        .memory
                                        .map(|index| {
                                            resolve_core_ref(core_memories, index).and_then(
                                                |reference| {
                                                    host_core_export(
                                                        reference,
                                                        &component_to_runtime,
                                                    )
                                                },
                                            )
                                        })
                                        .transpose()?;
                                    let realloc = lower
                                        .realloc
                                        .map(|index| {
                                            resolve_core_function_ref(core_functions, index)
                                                .and_then(|reference| {
                                                    host_core_export(
                                                        reference,
                                                        &component_to_runtime,
                                                    )
                                                })
                                        })
                                        .transpose()?;
                                    if memory
                                        .as_ref()
                                        .into_iter()
                                        .chain(realloc.as_ref())
                                        .any(|binding| binding.core_instance >= runtime_instance)
                                        || memory.as_ref().zip(realloc.as_ref()).is_some_and(
                                            |(memory, realloc)| {
                                                memory.core_instance != realloc.core_instance
                                            },
                                        )
                                    {
                                        return Err(DecodeError::InvalidWiring);
                                    }
                                    if host_imports.len() >= PROFILE_1_LIMITS.max_imports as usize {
                                        return Err(DecodeError::Limit);
                                    }
                                    let host_import = host_imports.len();
                                    host_imports
                                        .try_reserve(1)
                                        .map_err(|_| DecodeError::Allocation)?;
                                    host_imports.push(HostImportPlan {
                                        info: HostImportInfo {
                                            interface: copied(
                                                imported
                                                    .interface
                                                    .as_deref()
                                                    .unwrap_or(&imported.function),
                                            )?,
                                            function: copied(&imported.function)?,
                                            function_type,
                                            core_instance: runtime_instance,
                                            core_module: copied(&module_import.module)?,
                                            core_field: copied(&module_import.field)?,
                                            string_encoding: lower.string_encoding,
                                            memory,
                                            realloc,
                                        },
                                    });
                                    CoreImportPlan::Host {
                                        module: module_import.module,
                                        field: module_import.field,
                                        host_import,
                                    }
                                }
                                CoreFunctionDraft::SyncCanonical { .. }
                                | CoreFunctionDraft::AsyncCanonical { .. } => {
                                    return Err(DecodeError::InvalidWiring);
                                }
                            }
                        }
                        CoreInstanceExportItemDraft::Memory(index) => {
                            let source = host_core_export(
                                resolve_core_ref(core_memories, *index)?,
                                &component_to_runtime,
                            )?;
                            if source.core_instance >= runtime_instance {
                                return Err(DecodeError::InvalidWiring);
                            }
                            CoreImportPlan::InstanceExport {
                                module: module_import.module,
                                field: module_import.field,
                                core_instance: source.core_instance,
                                export: source.export,
                            }
                        }
                    }
                }
            };
            instances[runtime_instance].imports.push(import_plan);
        }
    }
    Ok((instances, component_to_runtime, host_imports))
}

fn core_module_imports(bytes: &[u8]) -> Result<Vec<CoreModuleImportDraft>, DecodeError> {
    let mut imports = Vec::new();
    let mut function_types = Vec::new();
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|_| DecodeError::InvalidEmbeddedCore)?;
        match payload {
            Payload::TypeSection(reader) => {
                function_types
                    .try_reserve_exact(reader.count() as usize)
                    .map_err(|_| DecodeError::Allocation)?;
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| DecodeError::InvalidEmbeddedCore)?;
                    function_types.push(native_core_signature(ty.params(), ty.results())?);
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|_| DecodeError::InvalidEmbeddedCore)?;
                    let (kind, signature) = match import.ty {
                        TypeRef::Func(index) => (
                            CoreModuleImportKind::Function,
                            Some(copy_native_core_signature(
                                function_types
                                    .get(index as usize)
                                    .ok_or(DecodeError::InvalidWiring)?,
                            )?),
                        ),
                        TypeRef::Memory(_) => (CoreModuleImportKind::Memory, None),
                        TypeRef::Table(_)
                        | TypeRef::Global(_)
                        | TypeRef::Tag(_)
                        | TypeRef::FuncExact(_) => return Err(DecodeError::InvalidWiring),
                    };
                    if imports.len() >= PROFILE_1_LIMITS.max_imports as usize {
                        return Err(DecodeError::Limit);
                    }
                    if imports.iter().any(|existing: &CoreModuleImportDraft| {
                        existing.module == import.module && existing.field == import.name
                    }) {
                        return Err(DecodeError::InvalidWiring);
                    }
                    imports
                        .try_reserve(1)
                        .map_err(|_| DecodeError::Allocation)?;
                    imports.push(CoreModuleImportDraft {
                        module: copied(import.module)?,
                        field: copied(import.name)?,
                        kind,
                        signature,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(imports)
}

fn native_core_signature(
    parameters: &[ValType],
    results: &[ValType],
) -> Result<NativeAsyncCoreSignature, DecodeError> {
    let mut normalized_parameters = Vec::new();
    normalized_parameters
        .try_reserve_exact(parameters.len())
        .map_err(|_| DecodeError::Allocation)?;
    for value in parameters {
        normalized_parameters.push(async_core_value_type(*value)?);
    }
    let mut normalized_results = Vec::new();
    normalized_results
        .try_reserve_exact(results.len())
        .map_err(|_| DecodeError::Allocation)?;
    for value in results {
        normalized_results.push(async_core_value_type(*value)?);
    }
    Ok(NativeAsyncCoreSignature {
        parameters: normalized_parameters,
        results: normalized_results,
    })
}

fn copy_native_core_signature(
    signature: &NativeAsyncCoreSignature,
) -> Result<NativeAsyncCoreSignature, DecodeError> {
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(signature.parameters.len())
        .map_err(|_| DecodeError::Allocation)?;
    parameters.extend_from_slice(&signature.parameters);
    let mut results = Vec::new();
    results
        .try_reserve_exact(signature.results.len())
        .map_err(|_| DecodeError::Allocation)?;
    results.extend_from_slice(&signature.results);
    Ok(NativeAsyncCoreSignature {
        parameters,
        results,
    })
}

fn core_export_kind_matches(
    import: CoreModuleImportKind,
    export: &CoreInstanceExportItemDraft,
) -> bool {
    matches!(
        (import, export),
        (
            CoreModuleImportKind::Function,
            CoreInstanceExportItemDraft::Function(_)
        ) | (
            CoreModuleImportKind::Memory,
            CoreInstanceExportItemDraft::Memory(_)
        )
    )
}

fn imported_component_function(
    functions: &[Option<ComponentFunctionDraft>],
    lower: LowerDraft,
) -> Result<&ImportedFunctionDraft, DecodeError> {
    let Some(ComponentFunctionDraft::Import(imported)) = functions
        .get(lower.component_function as usize)
        .and_then(Option::as_ref)
    else {
        return Err(DecodeError::InvalidWiring);
    };
    Ok(imported)
}

fn imported_function_type(
    types: &wasmparser::types::Types,
    type_builder: &mut TypeBuilder,
    imported: &ImportedFunctionDraft,
) -> Result<crate::types::FunctionType, DecodeError> {
    let function_type = if let Some(interface_name) = imported.interface.as_deref() {
        let item = types
            .component_item_for_import(interface_name)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentEntityType::Instance(instance_type) = item.ty else {
            return Err(DecodeError::InvalidWiring);
        };
        let member = types[instance_type]
            .exports
            .get(&imported.function)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentEntityType::Func(function_type) = member.ty else {
            return Err(DecodeError::InvalidWiring);
        };
        function_type
    } else {
        let item = types
            .component_item_for_import(&imported.function)
            .ok_or(DecodeError::InvalidWiring)?;
        let ComponentEntityType::Func(function_type) = item.ty else {
            return Err(DecodeError::InvalidWiring);
        };
        function_type
    };
    type_builder
        .function(types, function_type)
        .map_err(|error| match error {
            crate::types::TypeError::Unsupported => DecodeError::Unsupported,
            crate::types::TypeError::NestingLimit | crate::types::TypeError::DefinitionLimit => {
                DecodeError::Limit
            }
            crate::types::TypeError::Allocation => DecodeError::Allocation,
            crate::types::TypeError::InvalidFunction => DecodeError::InvalidWiring,
        })
}

fn host_core_export(
    reference: &CoreExportRef,
    component_to_runtime: &[Option<usize>],
) -> Result<HostCoreExportInfo, DecodeError> {
    let core_instance = component_to_runtime
        .get(reference.instance)
        .copied()
        .flatten()
        .ok_or(DecodeError::InvalidWiring)?;
    Ok(HostCoreExportInfo {
        core_instance,
        export: copied(&reference.name)?,
    })
}

fn require_lower_options(
    function: &crate::types::FunctionType,
    lower: &LowerDraft,
) -> Result<(), DecodeError> {
    let parameter_flat = flat_count(function.parameters.iter().map(|parameter| &parameter.value))?;
    let result_flat = flat_count(function.result.iter())?;
    let parameter_needs_memory = function
        .parameters
        .iter()
        .any(|parameter| uses_memory(&parameter.value))
        || parameter_flat > MAX_FLAT_PARAMS;
    let result_dynamic = function.result.as_ref().is_some_and(uses_memory);
    let result_needs_memory = result_dynamic || result_flat > MAX_FLAT_RESULTS;
    if (parameter_needs_memory || result_needs_memory) && lower.memory.is_none()
        || result_dynamic && lower.realloc.is_none()
        || lower.post_return.is_some()
    {
        return Err(DecodeError::InvalidWiring);
    }
    Ok(())
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

fn push_core_function_ref(
    target: &mut Vec<Option<CoreFunctionDraft>>,
    instance_index: u32,
    name: &str,
) -> Result<(), DecodeError> {
    target.try_reserve(1).map_err(|_| DecodeError::Allocation)?;
    target.push(Some(CoreFunctionDraft::Export(CoreExportRef {
        instance: usize::try_from(instance_index).map_err(|_| DecodeError::InvalidWiring)?,
        name: copied(name)?,
    })));
    Ok(())
}

fn resolve_component_instance_function(
    instances: &[Option<ComponentInstanceDraft>],
    functions: &[Option<ComponentFunctionDraft>],
    instance_index: u32,
    member: &str,
) -> Result<Option<ComponentFunctionDraft>, DecodeError> {
    let instance = instances
        .get(instance_index as usize)
        .and_then(Option::as_ref)
        .ok_or(DecodeError::InvalidWiring)?;
    let source = match instance {
        ComponentInstanceDraft::Import { name } => {
            ComponentFunctionDraft::Import(ImportedFunctionDraft {
                interface: Some(copied(name)?),
                function: copied(member)?,
            })
        }
        ComponentInstanceDraft::FromExports(members) => {
            let function_index = members
                .iter()
                .find_map(|(name, index)| (name == member).then_some(*index))
                .ok_or(DecodeError::InvalidWiring)?;
            functions
                .get(function_index as usize)
                .and_then(Option::as_ref)
                .cloned()
                .ok_or(DecodeError::InvalidWiring)?
        }
    };
    Ok(Some(source))
}

fn resolve_core_ref(
    refs: &[Option<CoreExportRef>],
    index: u32,
) -> Result<&CoreExportRef, DecodeError> {
    refs.get(index as usize)
        .and_then(Option::as_ref)
        .ok_or(DecodeError::InvalidWiring)
}

fn resolve_core_function_ref(
    refs: &[Option<CoreFunctionDraft>],
    index: u32,
) -> Result<&CoreExportRef, DecodeError> {
    let Some(CoreFunctionDraft::Export(reference)) =
        refs.get(index as usize).and_then(Option::as_ref)
    else {
        return Err(DecodeError::InvalidWiring);
    };
    Ok(reference)
}

#[allow(clippy::too_many_arguments)]
fn push_executable_export(
    target: &mut Vec<ExecutableExportPlan>,
    name: String,
    function_index: u32,
    function_type: wasmparser::component_types::ComponentFuncTypeId,
    type_builder: &mut TypeBuilder,
    types: &wasmparser::types::Types,
    component_functions: &[Option<ComponentFunctionDraft>],
    core_functions: &[Option<CoreFunctionDraft>],
    core_memories: &[Option<CoreExportRef>],
    component_to_runtime: &[Option<usize>],
) -> Result<(), DecodeError> {
    let Some(ComponentFunctionDraft::Lift(lift)) = component_functions
        .get(function_index as usize)
        .and_then(Option::as_ref)
    else {
        return Err(DecodeError::InvalidWiring);
    };
    let function = resolve_core_function_ref(core_functions, lift.core_function)?;
    let memory = lift
        .memory
        .map(|index| resolve_core_ref(core_memories, index))
        .transpose()?;
    let realloc = lift
        .realloc
        .map(|index| resolve_core_function_ref(core_functions, index))
        .transpose()?;
    let post_return = lift
        .post_return
        .map(|index| resolve_core_function_ref(core_functions, index))
        .transpose()?;
    for option in [memory, realloc, post_return].into_iter().flatten() {
        if option.instance != function.instance {
            return Err(DecodeError::InvalidWiring);
        }
    }
    let runtime_instance = component_to_runtime
        .get(function.instance)
        .copied()
        .flatten()
        .ok_or(DecodeError::InvalidWiring)?;
    let normalized_function = type_builder
        .function(types, function_type)
        .map_err(|error| match error {
            crate::types::TypeError::Unsupported => DecodeError::Unsupported,
            crate::types::TypeError::NestingLimit | crate::types::TypeError::DefinitionLimit => {
                DecodeError::Limit
            }
            crate::types::TypeError::Allocation => DecodeError::Allocation,
            crate::types::TypeError::InvalidFunction => DecodeError::InvalidWiring,
        })?;
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
            core_instance: runtime_instance,
            core_function: copied(&function.name)?,
            string_encoding: lift.string_encoding,
            memory: memory.map(|binding| copied(&binding.name)).transpose()?,
            realloc: realloc.map(|binding| copied(&binding.name)).transpose()?,
            post_return: post_return
                .map(|binding| copied(&binding.name))
                .transpose()?,
        },
        core_instance: runtime_instance,
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
        WorldError::TypeGraphLimit => DecodeError::Limit,
        WorldError::TypeMismatch => DecodeError::InvalidWiring,
        _ => DecodeError::TypeGraph,
    }
}

fn inspect_type(
    ty: &RawComponentType<'_>,
    summary: &mut ComponentSummary,
    mode: InspectionMode,
    depth: u32,
) -> Result<(), DecodeError> {
    if depth > PROFILE_1_LIMITS.max_component_nesting {
        return Err(DecodeError::Limit);
    }
    match ty {
        RawComponentType::Defined(defined) => inspect_defined_type(defined, summary, mode),
        RawComponentType::Func(function) => {
            if function.params.len() > PROFILE_1_LIMITS.max_params_per_function as usize {
                return Err(DecodeError::Limit);
            }
            if function.async_ {
                require_async(mode)?;
                add(
                    &mut summary.async_abi.async_function_types,
                    1,
                    PROFILE_1_LIMITS.max_async_functions,
                    LimitKind::AsyncFunctions,
                )?;
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
                        inspect_type(nested, summary, mode, depth + 1)?;
                    }
                    InstanceTypeDeclaration::Alias(_) => add(
                        &mut summary.aliases,
                        1,
                        PROFILE_1_LIMITS.max_aliases,
                        LimitKind::Aliases,
                    )?,
                    InstanceTypeDeclaration::CoreType(_) => return Err(DecodeError::Unsupported),
                    InstanceTypeDeclaration::Export { ty, .. } => {
                        if mode.is_native_async()
                            && matches!(ty, ComponentTypeRef::Type(TypeBounds::SubResource))
                        {
                            return Err(DecodeError::Unsupported);
                        }
                    }
                }
            }
            Ok(())
        }
        RawComponentType::Resource { rep, .. } => {
            if mode.is_native_async() {
                return Err(DecodeError::Unsupported);
            }
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

fn inspect_defined_type(
    defined: &RawDefinedType<'_>,
    summary: &mut ComponentSummary,
    mode: InspectionMode,
) -> Result<(), DecodeError> {
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
        RawDefinedType::Own(_) | RawDefinedType::Borrow(_) => {
            if mode.is_native_async() {
                Err(DecodeError::Unsupported)
            } else {
                Ok(())
            }
        }
        RawDefinedType::Future(payload) => {
            require_async(mode)?;
            if let Some(payload) = payload {
                inspect_primitive(raw_primitive(*payload))?;
            }
            add(
                &mut summary.async_abi.future_types,
                1,
                PROFILE_1_LIMITS.max_future_types,
                LimitKind::FutureTypes,
            )
        }
        RawDefinedType::Stream(payload) => {
            require_async(mode)?;
            if let Some(payload) = payload {
                inspect_primitive(raw_primitive(*payload))?;
            }
            add(
                &mut summary.async_abi.stream_types,
                1,
                PROFILE_1_LIMITS.max_stream_types,
                LimitKind::StreamTypes,
            )
        }
        RawDefinedType::Map(_, _) | RawDefinedType::FixedLengthList(_, _) => {
            Err(DecodeError::Unsupported)
        }
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

#[derive(Clone, Copy)]
enum CanonicalClass {
    Sync,
    AsyncLift,
    AsyncLower,
    Task,
    Context,
    Subtask,
    CooperativeYield,
    Stream,
    Future,
    Waitable,
    Backpressure,
}

#[derive(Clone, Copy)]
struct CanonicalInspection {
    class: CanonicalClass,
    adapter: bool,
}

#[derive(Default)]
struct InspectedOptions {
    async_: bool,
    callback: bool,
}

fn inspect_canonical(
    function: &CanonicalFunction,
    mode: InspectionMode,
) -> Result<CanonicalInspection, DecodeError> {
    let inspected = match function {
        CanonicalFunction::Lift { options, .. } => {
            let options = inspect_options(options, mode)?;
            if options.async_ {
                if !options.callback {
                    // Callback-free lift is the disabled stackful ABI.
                    return Err(DecodeError::Unsupported);
                }
                CanonicalInspection {
                    class: CanonicalClass::AsyncLift,
                    adapter: false,
                }
            } else {
                if options.callback {
                    return Err(DecodeError::Unsupported);
                }
                CanonicalInspection {
                    class: CanonicalClass::Sync,
                    adapter: false,
                }
            }
        }
        CanonicalFunction::Lower { options, .. } => {
            let options = inspect_options(options, mode)?;
            if options.callback {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: if options.async_ {
                    CanonicalClass::AsyncLower
                } else {
                    CanonicalClass::Sync
                },
                adapter: true,
            }
        }
        CanonicalFunction::ResourceNew { .. }
        | CanonicalFunction::ResourceDrop { .. }
        | CanonicalFunction::ResourceRep { .. } => CanonicalInspection {
            class: CanonicalClass::Sync,
            adapter: false,
        },
        CanonicalFunction::TaskReturn { options, .. } => {
            require_async(mode)?;
            let options = inspect_options(options, mode)?;
            if options.async_ || options.callback {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: CanonicalClass::Task,
                adapter: false,
            }
        }
        CanonicalFunction::TaskCancel => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Task,
                adapter: false,
            }
        }
        CanonicalFunction::ContextGet { ty, slot } | CanonicalFunction::ContextSet { ty, slot } => {
            require_async(mode)?;
            if *ty != ValType::I32 || *slot != 0 {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: CanonicalClass::Context,
                adapter: false,
            }
        }
        CanonicalFunction::SubtaskDrop => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Subtask,
                adapter: false,
            }
        }
        CanonicalFunction::SubtaskCancel { async_ } => {
            require_async(mode)?;
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: CanonicalClass::Subtask,
                adapter: false,
            }
        }
        CanonicalFunction::ThreadYield { .. } => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::CooperativeYield,
                adapter: false,
            }
        }
        CanonicalFunction::StreamNew { .. }
        | CanonicalFunction::StreamDropReadable { .. }
        | CanonicalFunction::StreamDropWritable { .. } => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Stream,
                adapter: false,
            }
        }
        CanonicalFunction::StreamRead { options, .. }
        | CanonicalFunction::StreamWrite { options, .. } => {
            require_async_transfer(options, mode)?;
            CanonicalInspection {
                class: CanonicalClass::Stream,
                adapter: false,
            }
        }
        CanonicalFunction::StreamCancelRead { async_, .. }
        | CanonicalFunction::StreamCancelWrite { async_, .. } => {
            require_async(mode)?;
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: CanonicalClass::Stream,
                adapter: false,
            }
        }
        CanonicalFunction::FutureNew { .. }
        | CanonicalFunction::FutureDropReadable { .. }
        | CanonicalFunction::FutureDropWritable { .. } => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Future,
                adapter: false,
            }
        }
        CanonicalFunction::FutureRead { options, .. }
        | CanonicalFunction::FutureWrite { options, .. } => {
            require_async_transfer(options, mode)?;
            CanonicalInspection {
                class: CanonicalClass::Future,
                adapter: false,
            }
        }
        CanonicalFunction::FutureCancelRead { async_, .. }
        | CanonicalFunction::FutureCancelWrite { async_, .. } => {
            require_async(mode)?;
            if *async_ {
                return Err(DecodeError::Unsupported);
            }
            CanonicalInspection {
                class: CanonicalClass::Future,
                adapter: false,
            }
        }
        CanonicalFunction::WaitableSetNew
        | CanonicalFunction::WaitableSetWait { .. }
        | CanonicalFunction::WaitableSetPoll { .. }
        | CanonicalFunction::WaitableSetDrop
        | CanonicalFunction::WaitableJoin => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Waitable,
                adapter: false,
            }
        }
        CanonicalFunction::BackpressureInc | CanonicalFunction::BackpressureDec => {
            require_async(mode)?;
            CanonicalInspection {
                class: CanonicalClass::Backpressure,
                adapter: false,
            }
        }
        CanonicalFunction::ErrorContextNew { .. }
        | CanonicalFunction::ErrorContextDebugMessage { .. }
        | CanonicalFunction::ErrorContextDrop
        | CanonicalFunction::ThreadIndex
        | CanonicalFunction::ThreadNewIndirect { .. }
        | CanonicalFunction::ThreadResumeLater
        | CanonicalFunction::ThreadSuspend { .. }
        | CanonicalFunction::ThreadSuspendThenResume { .. }
        | CanonicalFunction::ThreadYieldThenResume { .. }
        | CanonicalFunction::ThreadSuspendThenPromote { .. }
        | CanonicalFunction::ThreadYieldThenPromote { .. }
        | CanonicalFunction::ThreadSpawnRef { .. }
        | CanonicalFunction::ThreadSpawnIndirect { .. }
        | CanonicalFunction::ThreadAvailableParallelism => return Err(DecodeError::Unsupported),
    };
    if mode.is_native_async() && !native_async_canonical_allowed(function, inspected.class) {
        return Err(DecodeError::Unsupported);
    }
    Ok(inspected)
}

fn native_async_canonical_allowed(function: &CanonicalFunction, class: CanonicalClass) -> bool {
    match (function, class) {
        (CanonicalFunction::Lift { .. }, CanonicalClass::AsyncLift)
        | (CanonicalFunction::TaskReturn { .. }, CanonicalClass::Task)
        | (CanonicalFunction::TaskCancel, CanonicalClass::Task)
        | (CanonicalFunction::StreamNew { .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamRead { .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamWrite { .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamCancelRead { async_: false, .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamCancelWrite { async_: false, .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamDropReadable { .. }, CanonicalClass::Stream)
        | (CanonicalFunction::StreamDropWritable { .. }, CanonicalClass::Stream)
        | (CanonicalFunction::FutureNew { .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureRead { .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureWrite { .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureCancelRead { async_: false, .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureCancelWrite { async_: false, .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureDropReadable { .. }, CanonicalClass::Future)
        | (CanonicalFunction::FutureDropWritable { .. }, CanonicalClass::Future)
        | (CanonicalFunction::WaitableSetNew, CanonicalClass::Waitable)
        | (CanonicalFunction::WaitableSetDrop, CanonicalClass::Waitable)
        | (CanonicalFunction::WaitableJoin, CanonicalClass::Waitable) => true,
        _ => false,
    }
}

fn require_async(mode: InspectionMode) -> Result<(), DecodeError> {
    if mode.async_enabled() {
        Ok(())
    } else {
        Err(DecodeError::Unsupported)
    }
}

fn require_async_transfer(
    options: &[CanonicalOption],
    mode: InspectionMode,
) -> Result<(), DecodeError> {
    require_async(mode)?;
    let options = inspect_options(options, mode)?;
    if !options.async_ || options.callback {
        Err(DecodeError::Unsupported)
    } else {
        Ok(())
    }
}

fn inspect_options(
    options: &[CanonicalOption],
    mode: InspectionMode,
) -> Result<InspectedOptions, DecodeError> {
    if options.len() > PROFILE_1_LIMITS.max_canonical_options_per_function as usize {
        return Err(DecodeError::Limit);
    }
    let mut result = InspectedOptions::default();
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
            CanonicalOption::Async => {
                require_async(mode)?;
                core::mem::replace(&mut result.async_, true)
            }
            CanonicalOption::Callback(_) => {
                require_async(mode)?;
                core::mem::replace(&mut result.callback, true)
            }
            CanonicalOption::UTF16
            | CanonicalOption::CompactUTF16
            | CanonicalOption::CoreType(_)
            | CanonicalOption::Gc => return Err(DecodeError::Unsupported),
        };
        if duplicate {
            return Err(DecodeError::Malformed);
        }
    }
    Ok(result)
}

fn has_async_option(options: &[CanonicalOption]) -> bool {
    options
        .iter()
        .any(|option| matches!(option, CanonicalOption::Async))
}

fn record_canonical(
    summary: &mut ComponentSummary,
    inspection: CanonicalInspection,
) -> Result<(), DecodeError> {
    let counter = match inspection.class {
        CanonicalClass::Sync => return Ok(()),
        CanonicalClass::AsyncLift => &mut summary.async_abi.async_lifts,
        CanonicalClass::AsyncLower => &mut summary.async_abi.async_lowers,
        CanonicalClass::Task => &mut summary.async_abi.task_builtins,
        CanonicalClass::Context => &mut summary.async_abi.context_builtins,
        CanonicalClass::Subtask => &mut summary.async_abi.subtask_builtins,
        CanonicalClass::CooperativeYield => &mut summary.async_abi.cooperative_yields,
        CanonicalClass::Stream => &mut summary.async_abi.stream_builtins,
        CanonicalClass::Future => &mut summary.async_abi.future_builtins,
        CanonicalClass::Waitable => &mut summary.async_abi.waitable_builtins,
        CanonicalClass::Backpressure => &mut summary.async_abi.backpressure_builtins,
    };
    add(
        counter,
        1,
        PROFILE_1_LIMITS.max_canonical_functions,
        LimitKind::CanonicalFunctions,
    )
}

fn async_plan_options(
    options: &[CanonicalOption],
) -> Result<(AsyncCanonicalOptions, Option<u32>), DecodeError> {
    let mut plan = AsyncCanonicalOptions::default();
    let mut callback = None;
    for option in options {
        match option {
            CanonicalOption::UTF8 => {
                if plan
                    .string_encoding
                    .replace(CanonicalStringEncoding::Utf8)
                    .is_some()
                {
                    return Err(DecodeError::Malformed);
                }
            }
            CanonicalOption::Memory(index) => {
                if plan.memory.replace(*index).is_some() {
                    return Err(DecodeError::Malformed);
                }
            }
            CanonicalOption::Realloc(index) => {
                if plan.realloc.replace(*index).is_some() {
                    return Err(DecodeError::Malformed);
                }
            }
            CanonicalOption::Async => plan.async_ = true,
            CanonicalOption::Callback(index) => {
                if callback.replace(*index).is_some() {
                    return Err(DecodeError::Malformed);
                }
            }
            CanonicalOption::UTF16
            | CanonicalOption::CompactUTF16
            | CanonicalOption::PostReturn(_)
            | CanonicalOption::CoreType(_)
            | CanonicalOption::Gc => return Err(DecodeError::Unsupported),
        }
    }
    Ok((plan, callback))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn native_lift(canonical_index: u32) -> NativeAsyncCanonicalPlan {
        NativeAsyncCanonicalPlan {
            canonical_index,
            function: NativeAsyncCanonicalFunctionPlan::Lift {
                core_function: NativeAsyncCoreExportRef {
                    core_instance: 0,
                    export: String::new(),
                },
                function_type: crate::types::FunctionType {
                    effect: crate::world::FunctionEffect::Async,
                    parameters: Vec::new(),
                    result: None,
                },
                callback: NativeAsyncCoreExportRef {
                    core_instance: 0,
                    export: String::new(),
                },
                options: NativeAsyncCanonicalOptionsPlan {
                    string_encoding: None,
                    async_: true,
                    memory: None,
                    realloc: None,
                },
            },
        }
    }

    #[test]
    fn native_top_level_export_cannot_collide_with_flattened_interface_member() {
        let component_functions = [
            Some(ComponentFunctionDraft::AsyncLift { canonical_index: 0 }),
            Some(ComponentFunctionDraft::AsyncLift { canonical_index: 1 }),
        ];
        let canonical_drafts = [
            AsyncCanonicalDraft {
                canonical_index: 0,
                function: AsyncCanonicalFunctionDraft::Lift {
                    core_function: 0,
                    function_type: 0,
                    callback: 1,
                    options: AsyncOptionsDraft {
                        string_encoding: None,
                        async_: true,
                        memory: None,
                        realloc: None,
                    },
                },
            },
            AsyncCanonicalDraft {
                canonical_index: 1,
                function: AsyncCanonicalFunctionDraft::Lift {
                    core_function: 2,
                    function_type: 0,
                    callback: 3,
                    options: AsyncOptionsDraft {
                        string_encoding: None,
                        async_: true,
                        memory: None,
                        realloc: None,
                    },
                },
            },
        ];
        let canonical = [native_lift(0), native_lift(1)];
        let mut exports = Vec::new();

        push_native_async_export(
            &mut exports,
            "api#member",
            0,
            &component_functions,
            &canonical_drafts,
            &canonical,
        )
        .unwrap();
        assert_eq!(exports[0].canonical, 0);

        assert_eq!(
            push_native_async_export(
                &mut exports,
                "api#member",
                1,
                &component_functions,
                &canonical_drafts,
                &canonical,
            ),
            Err(DecodeError::InvalidWiring)
        );
        assert_eq!(exports.len(), 1);
    }
}
