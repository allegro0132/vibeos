//! Atomic construction and bounded synchronous execution of one validated
//! Component Model principal.

use crate::{
    abi_value::{
        flat_signature, lift_parameters, lift_results, lower_flat_results_prepared,
        lower_parameters, lower_results_into_prepared, CodecError, CodecUsage, FlatKind,
        LoweredParameters, LoweringJournal, PayloadAllocator, PreparedFlatResults, ResourceBinder,
        MAX_FLAT_PARAMS, MAX_FLAT_RESULTS,
    },
    decode::ComponentPlan,
    execution::{
        CoreImportPlan, ExecutableExportPlan, HostCoreExportInfo, HostImportInfo, HostImportPlan,
    },
    host::{
        HostDispatch, HostDispatcher, HostError, HostOperationToken, HostPrepared, HostRequest,
        HostWakeToken,
    },
    memory::{AbiError, GuestMemory},
    resource::{GuestCallResources, ResourceTable, ResourceToken, ResourceTypeId},
    types::FunctionType,
    value::{
        validate_value_with_resources, CanonicalValue, ResourceOwnership, ValuePosition, ValueType,
    },
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreCallReservation, CoreComponentGroup, CoreHostCall, CoreHostImport,
    CoreInstanceExportImport, CoreModuleImport, CoreValue, CoreValueType,
    OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SyncError {
    Allocation = 1,
    CoreAdmission = 2,
    CoreInstantiation = 3,
    MissingModule = 4,
    InvalidBudget = 5,
    MissingExport = 6,
    InvalidWiring = 7,
    Memory = 8,
    Codec = 9,
    Busy = 10,
    Trapped = 11,
    Value = 12,
    Resource = 13,
    Poisoned = 14,
    AsyncUnavailable = 15,
}

impl SyncError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// One principal's validated Core instances and immutable Component wiring.
pub struct SynchronousComponent {
    modules: CoreComponentGroup,
    exports: Vec<RuntimeExport>,
    host_imports: Vec<HostImportInfo>,
    poisoned: bool,
}

struct RuntimeExport {
    name: String,
    function_type: FunctionType,
    core_instance: usize,
    function: String,
    memory: Option<String>,
    realloc: Option<String>,
    post_return: Option<String>,
}

struct OwnedCoreHostImport {
    id: u32,
    module: String,
    name: String,
    parameters: Vec<CoreValueType>,
    results: Vec<CoreValueType>,
}

enum OwnedCoreModuleImport {
    Host(OwnedCoreHostImport),
    InstanceExport {
        module: String,
        name: String,
        instance: usize,
        export: String,
    },
}

impl OwnedCoreModuleImport {
    fn descriptor(&self) -> CoreModuleImport<'_> {
        match self {
            Self::Host(import) => CoreModuleImport::Host(import.descriptor()),
            Self::InstanceExport {
                module,
                name,
                instance,
                export,
            } => CoreModuleImport::InstanceExport(CoreInstanceExportImport {
                module,
                name,
                instance: *instance,
                export,
            }),
        }
    }
}

impl OwnedCoreHostImport {
    fn descriptor(&self) -> CoreHostImport<'_> {
        CoreHostImport {
            id: self.id,
            module: &self.module,
            name: &self.name,
            params: &self.parameters,
            results: &self.results,
        }
    }
}

impl SynchronousComponent {
    pub fn instantiate(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
    ) -> Result<Self, SyncError> {
        Self::instantiate_with_memory_limit(
            plan,
            engine,
            reservation_per_module,
            PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
        )
    }

    /// Instantiates with a policy-selected execution-time memory ceiling.
    /// This ceiling is installed in the wasmi store and therefore constrains
    /// initial memory and every later `memory.grow`; it is not merely an
    /// allocation estimate used while compiling embedded modules.
    pub fn instantiate_with_memory_limit(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
        memory_bytes: usize,
    ) -> Result<Self, SyncError> {
        if !plan.runtime_ready() {
            return Err(SyncError::AsyncUnavailable);
        }
        let execution = &plan.execution;
        if execution
            .host_imports()
            .iter()
            .any(|import| host_function_requires_resource_transfer(&import.info.function_type))
        {
            // C3 host imports deliberately expose borrow-only input authority.
            // Owning parameters need an explicit dispatcher consumption API,
            // while any resource result would create or escape authority after
            // the backend effect. Both remain fail-closed for this milestone.
            return Err(SyncError::InvalidWiring);
        }
        let mut modules = CoreComponentGroup::new_with_memory_limit(
            engine,
            execution.instances().len(),
            memory_bytes,
        )
        .map_err(|_| SyncError::CoreInstantiation)?;
        for (runtime_instance, instance) in execution.instances().iter().enumerate() {
            let bytes = plan
                .embedded_modules()
                .get(instance.module())
                .ok_or(SyncError::MissingModule)?;
            let validated = ValidatedCore::new_in(engine, bytes, reservation_per_module)
                .map_err(|_| SyncError::CoreAdmission)?;
            let owned_imports = owned_core_module_imports(
                runtime_instance,
                instance.imports(),
                execution.host_imports(),
            )?;
            let mut imports = Vec::new();
            imports
                .try_reserve_exact(owned_imports.len())
                .map_err(|_| SyncError::Allocation)?;
            for import in &owned_imports {
                imports.push(import.descriptor());
            }
            if modules
                .add_instance(&validated, &imports)
                .map_err(|_| SyncError::CoreInstantiation)?
                != runtime_instance
            {
                return Err(SyncError::InvalidWiring);
            }
        }
        modules.seal().map_err(|_| SyncError::CoreInstantiation)?;
        let mut exports = Vec::new();
        exports
            .try_reserve_exact(execution.exports().len())
            .map_err(|_| SyncError::Allocation)?;
        for export in execution.exports() {
            exports.push(runtime_export(export)?);
        }
        let mut host_imports = Vec::new();
        host_imports
            .try_reserve_exact(execution.host_imports().len())
            .map_err(|_| SyncError::Allocation)?;
        for import in execution.host_imports() {
            host_imports.push(runtime_host_import(&import.info)?);
        }
        Ok(Self {
            modules,
            exports,
            host_imports,
            poisoned: false,
        })
    }

    pub fn module_count(&self) -> usize {
        self.modules.instance_count()
    }

    /// Whether execution crossed into guest state and then failed before full
    /// canonical cleanup. A poisoned instance is diagnostic-only and must be
    /// cold-instantiated before it can execute again.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn function_type(&self, name: &str) -> Option<&FunctionType> {
        self.exports
            .iter()
            .find(|export| export.name == name)
            .map(|export| &export.function_type)
    }

    /// Starts a validator-wired, typed Component export call.
    ///
    /// The returned call exclusively borrows both the component and its exact
    /// resource table until it reaches post-return or is dropped. That is the
    /// synchronous borrow scope: resource handles cannot be removed while the
    /// guest continuation is pending.
    pub fn start_typed_call<'a, A>(
        &'a mut self,
        resources: &'a mut ResourceTable<A>,
        export: &str,
        arguments: Vec<CanonicalValue>,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<TypedCall<'a, A>, SyncError> {
        self.start_typed_call_inner(resources, None, export, arguments, total_work, poll_quantum)
    }

    /// Starts a typed Component export call with one call-scoped host-import
    /// dispatcher. The dispatcher is borrowed for the whole continuation and
    /// can only receive values after Canonical ABI and resource validation.
    pub fn start_typed_call_with_host<'a, A, D: HostDispatcher<A> + 'a>(
        &'a mut self,
        resources: &'a mut ResourceTable<A>,
        dispatcher: &'a mut D,
        export: &str,
        arguments: Vec<CanonicalValue>,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<TypedCall<'a, A>, SyncError> {
        self.start_typed_call_inner(
            resources,
            Some(dispatcher),
            export,
            arguments,
            total_work,
            poll_quantum,
        )
    }

    fn start_typed_call_inner<'a, A>(
        &'a mut self,
        resources: &'a mut ResourceTable<A>,
        dispatcher: Option<&'a mut dyn HostDispatcher<A>>,
        export: &str,
        mut arguments: Vec<CanonicalValue>,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<TypedCall<'a, A>, SyncError> {
        if self.poisoned {
            return Err(SyncError::Poisoned);
        }
        if self.modules.any_active_call() {
            return Err(SyncError::Busy);
        }
        if total_work == 0
            || total_work > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_work
        {
            return Err(SyncError::InvalidBudget);
        }
        let export = self
            .exports
            .iter()
            .position(|binding| binding.name == export)
            .ok_or(SyncError::MissingExport)?;
        let binding = &self.exports[export];
        if binding.function_type.parameters.len() != arguments.len() {
            return Err(SyncError::Value);
        }
        for (parameter, argument) in binding.function_type.parameters.iter().zip(&arguments) {
            validate_value_with_resources(
                &parameter.value,
                argument,
                resources,
                ValuePosition::Parameter,
            )
            .map_err(|_| SyncError::Resource)?;
        }

        let parameter_types = clone_parameter_types(&binding.function_type)?;
        let active_baselines = zero_baselines(self.module_count())?;
        let mut guest_resources = resources
            .begin_guest_call()
            .map_err(|_| SyncError::Resource)?;
        if lower_argument_resources(
            &parameter_types,
            &mut arguments,
            resources,
            &mut guest_resources,
        )
        .is_err()
        {
            let _ = resources.close_guest_call(guest_resources);
            return Err(SyncError::Resource);
        }
        let mut planning_memory = PlanningMemory;
        let mut planner = AllocationPlanner::default();
        let planned = match lower_parameters(
            &mut planning_memory,
            &mut planner,
            &parameter_types,
            &arguments,
        ) {
            Ok(planned) => planned,
            Err(_) => {
                let _ = resources.close_guest_call(guest_resources);
                return Err(SyncError::Codec);
            }
        };
        let (planned_arguments, usage) = match lowered_parts(planned) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = resources.close_guest_call(guest_resources);
                return Err(error);
            }
        };
        if !planner.requests.is_empty() && (binding.memory.is_none() || binding.realloc.is_none()) {
            let _ = resources.close_guest_call(guest_resources);
            return Err(SyncError::InvalidWiring);
        }
        if usage.work > total_work {
            let _ = resources.close_guest_call(guest_resources);
            return Ok(TypedCall::terminal(
                self,
                resources,
                dispatcher,
                export,
                total_work,
                poll_quantum,
                TrapCode::FuelExhausted,
            ));
        }
        let remaining_work = total_work - usage.work;
        if remaining_work == 0 && (!planner.requests.is_empty() || !planned_arguments.is_empty()) {
            let _ = resources.close_guest_call(guest_resources);
            return Ok(TypedCall::terminal(
                self,
                resources,
                dispatcher,
                export,
                total_work,
                poll_quantum,
                TrapCode::FuelExhausted,
            ));
        }
        let mut pointers = Vec::new();
        if pointers.try_reserve_exact(planner.requests.len()).is_err() {
            let _ = resources.close_guest_call(guest_resources);
            return Err(SyncError::Allocation);
        }
        Ok(TypedCall {
            component: self,
            resources,
            dispatcher,
            export,
            arguments,
            allocations: planner.requests,
            allocation_index: 0,
            pointers,
            replay_arguments: None,
            core_results: None,
            result: None,
            stage: TypedStage::Allocate,
            total_work,
            remaining_work,
            poll_quantum,
            active_baselines,
            host_lower: None,
            cancelled: false,
            guest_started: false,
            guest_resources: Some(guest_resources),
        })
    }

    /// Copy-only access to the exact Core memory named by an export's
    /// canonical options. Primarily useful for diagnostics and tests.
    pub fn read_export_memory(
        &self,
        export: &str,
        offset: u32,
        destination: &mut [u8],
    ) -> Result<(), SyncError> {
        let binding = self
            .exports
            .iter()
            .find(|binding| binding.name == export)
            .ok_or(SyncError::MissingExport)?;
        let memory = binding.memory.as_deref().ok_or(SyncError::InvalidWiring)?;
        self.modules
            .read_memory(binding.core_instance, memory, offset as usize, destination)
            .map_err(|_| SyncError::Memory)
    }
}

fn runtime_export(export: &ExecutableExportPlan) -> Result<RuntimeExport, SyncError> {
    Ok(RuntimeExport {
        name: copied(&export.info.name)?,
        function_type: crate::types::try_clone_function_type(&export.info.function)
            .map_err(|_| SyncError::Allocation)?,
        core_instance: export.core_instance,
        function: copied(&export.function)?,
        memory: export.memory.as_deref().map(copied).transpose()?,
        realloc: export.realloc.as_deref().map(copied).transpose()?,
        post_return: export.post_return.as_deref().map(copied).transpose()?,
    })
}

fn runtime_host_import(import: &HostImportInfo) -> Result<HostImportInfo, SyncError> {
    Ok(HostImportInfo {
        interface: copied(&import.interface)?,
        function: copied(&import.function)?,
        function_type: crate::types::try_clone_function_type(&import.function_type)
            .map_err(|_| SyncError::Allocation)?,
        core_instance: import.core_instance,
        core_module: copied(&import.core_module)?,
        core_field: copied(&import.core_field)?,
        string_encoding: import.string_encoding,
        memory: import
            .memory
            .as_ref()
            .map(runtime_host_core_export)
            .transpose()?,
        realloc: import
            .realloc
            .as_ref()
            .map(runtime_host_core_export)
            .transpose()?,
    })
}

fn runtime_host_core_export(export: &HostCoreExportInfo) -> Result<HostCoreExportInfo, SyncError> {
    Ok(HostCoreExportInfo {
        core_instance: export.core_instance,
        export: copied(&export.export)?,
    })
}

fn clone_host_binding(
    binding: Option<&HostCoreExportInfo>,
) -> Result<Option<HostCoreExportInfo>, TrapCode> {
    binding
        .map(|binding| {
            let mut export = String::new();
            export
                .try_reserve_exact(binding.export.len())
                .map_err(|_| TrapCode::LimitExceeded)?;
            export.push_str(&binding.export);
            Ok(HostCoreExportInfo {
                core_instance: binding.core_instance,
                export,
            })
        })
        .transpose()
}

fn validate_host_retptr(
    modules: &CoreComponentGroup,
    memory: Option<&HostCoreExportInfo>,
    function: &FunctionType,
    pointer: u32,
) -> Result<(), TrapCode> {
    let result = function.result.as_ref().ok_or(TrapCode::CanonicalAbi)?;
    let layout = crate::value::validate_type(result)
        .map_err(|_| TrapCode::CanonicalAbi)?
        .layout;
    if pointer as usize & (layout.alignment - 1) != 0 {
        return Err(TrapCode::CanonicalAbi);
    }
    let memory = memory.ok_or(TrapCode::Validation)?;
    let length = modules
        .memory_size(memory.core_instance, &memory.export)
        .map_err(|_| TrapCode::MemoryOutOfBounds)?;
    let end = usize::try_from(pointer)
        .ok()
        .and_then(|start| start.checked_add(layout.size))
        .ok_or(TrapCode::MemoryOutOfBounds)?;
    if end > length {
        return Err(TrapCode::MemoryOutOfBounds);
    }
    Ok(())
}

fn host_retptr_span(function: &FunctionType, pointer: u32) -> Result<(u32, u32), TrapCode> {
    let result = function.result.as_ref().ok_or(TrapCode::CanonicalAbi)?;
    let size = crate::value::validate_type(result)
        .map_err(|_| TrapCode::CanonicalAbi)?
        .layout
        .size;
    Ok((
        pointer,
        u32::try_from(size).map_err(|_| TrapCode::LimitExceeded)?,
    ))
}

fn valid_bound_allocation(
    modules: &CoreComponentGroup,
    memory: Option<&HostCoreExportInfo>,
    pointers: &[u32],
    requests: &[AllocationRequest],
    pointer: u32,
    size: u32,
    protected: Option<(u32, u32)>,
) -> bool {
    let Some(memory) = memory else {
        return false;
    };
    let Ok(length) = modules.memory_size(memory.core_instance, &memory.export) else {
        return false;
    };
    let start = u64::from(pointer);
    let end = start + u64::from(size);
    if end > length as u64 {
        return false;
    }
    if let Some((protected_pointer, protected_size)) = protected {
        let protected_start = u64::from(protected_pointer);
        let protected_end = protected_start + u64::from(protected_size);
        if start < protected_end && protected_start < end {
            return false;
        }
    }
    for (index, previous) in pointers.iter().copied().enumerate() {
        let Some(request) = requests.get(index) else {
            return false;
        };
        let previous_start = u64::from(previous);
        let previous_end = previous_start + u64::from(request.size);
        if start < previous_end && previous_start < end {
            return false;
        }
    }
    true
}

struct ReallocationSpan {
    replaced: usize,
    pointer: u32,
    size: u32,
}

fn valid_bound_reallocation(
    modules: &CoreComponentGroup,
    memory: Option<&HostCoreExportInfo>,
    pointers: &[u32],
    requests: &[AllocationRequest],
    replacement: ReallocationSpan,
    protected: Option<(u32, u32)>,
) -> bool {
    let Some(memory) = memory else {
        return false;
    };
    let Ok(length) = modules.memory_size(memory.core_instance, &memory.export) else {
        return false;
    };
    let start = u64::from(replacement.pointer);
    let end = start + u64::from(replacement.size);
    if end > length as u64 {
        return false;
    }
    if let Some((protected_pointer, protected_size)) = protected {
        let protected_start = u64::from(protected_pointer);
        let protected_end = protected_start + u64::from(protected_size);
        if start < protected_end && protected_start < end {
            return false;
        }
    }
    let Some(old_pointer) = pointers.get(replacement.replaced).copied() else {
        return false;
    };
    let Some(old_request) = requests.get(replacement.replaced) else {
        return false;
    };
    let old_start = u64::from(old_pointer);
    let old_end = old_start + u64::from(old_request.size);
    // A canonical realloc may retain its base pointer or return a disjoint
    // allocation. An interior pointer is never a valid moved allocation even
    // if the smaller exact span would fit inside the old block.
    if replacement.pointer != old_pointer && start < old_end && old_start < end {
        return false;
    }
    for (index, previous) in pointers.iter().copied().enumerate() {
        if index == replacement.replaced {
            continue;
        }
        let Some(request) = requests.get(index) else {
            return false;
        };
        let previous_start = u64::from(previous);
        let previous_end = previous_start + u64::from(request.size);
        if start < previous_end && previous_start < end {
            return false;
        }
    }
    true
}

fn lower_host_response(
    modules: &mut CoreComponentGroup,
    pending: &mut PendingHostLower,
    values: &[CanonicalValue],
) -> Result<(Vec<CoreValue>, CodecUsage, usize), TrapCode> {
    let mut replay = ReplayAllocator {
        pointers: &pending.pointers,
        requests: &pending.allocations,
        cursor: 0,
    };
    let usage = match pending.caller_retptr {
        Some(pointer) => {
            let memory = pending.memory.as_ref().ok_or(TrapCode::Validation)?;
            let mut guest = CoreGuestMemory::new(modules, memory.core_instance, &memory.export)
                .map_err(|_| TrapCode::MemoryOutOfBounds)?;
            lower_results_into_prepared(
                &mut guest,
                &mut replay,
                pending.function.result.as_slice(),
                values,
                pointer,
                &mut pending.lowering_journal,
            )
            .map_err(|_| TrapCode::CanonicalAbi)?
        }
        None => {
            let mut no_memory = NoGuestMemory;
            let prepared = pending.flat_results.as_mut().ok_or(TrapCode::Validation)?;
            let (values, usage) = lower_flat_results_prepared(
                &mut no_memory,
                &mut replay,
                pending.function.result.as_slice(),
                values,
                prepared,
            )
            .map_err(|_| TrapCode::CanonicalAbi)?;
            return Ok((values, usage, replay.cursor));
        }
    };
    let results = pending.resume_results.take().ok_or(TrapCode::Validation)?;
    Ok((results, usage, replay.cursor))
}

fn owned_core_module_imports(
    runtime_instance: usize,
    bindings: &[CoreImportPlan],
    host_imports: &[HostImportPlan],
) -> Result<Vec<OwnedCoreModuleImport>, SyncError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(bindings.len())
        .map_err(|_| SyncError::Allocation)?;
    for binding in bindings {
        match binding {
            CoreImportPlan::Host {
                module,
                field,
                host_import,
            } => {
                let import = host_imports
                    .get(*host_import)
                    .ok_or(SyncError::InvalidWiring)?;
                if import.info.core_instance != runtime_instance
                    || import.info.core_module != *module
                    || import.info.core_field != *field
                {
                    return Err(SyncError::InvalidWiring);
                }
                let (parameters, results) = core_host_signature(&import.info.function_type)?;
                result.push(OwnedCoreModuleImport::Host(OwnedCoreHostImport {
                    id: u32::try_from(*host_import).map_err(|_| SyncError::InvalidWiring)?,
                    module: copied(module)?,
                    name: copied(field)?,
                    parameters,
                    results,
                }));
            }
            CoreImportPlan::InstanceExport {
                module,
                field,
                core_instance,
                export,
            } => {
                if *core_instance >= runtime_instance {
                    return Err(SyncError::InvalidWiring);
                }
                result.push(OwnedCoreModuleImport::InstanceExport {
                    module: copied(module)?,
                    name: copied(field)?,
                    instance: *core_instance,
                    export: copied(export)?,
                });
            }
        }
    }
    Ok(result)
}

fn core_host_signature(
    function: &FunctionType,
) -> Result<(Vec<CoreValueType>, Vec<CoreValueType>), SyncError> {
    let parameter_types = clone_parameter_types(function)?;
    let flat_parameters = flat_signature(&parameter_types).map_err(|_| SyncError::InvalidWiring)?;
    let mut parameters = if flat_parameters.len() <= MAX_FLAT_PARAMS {
        core_value_types(&flat_parameters)?
    } else {
        let mut indirect = Vec::new();
        indirect
            .try_reserve_exact(1)
            .map_err(|_| SyncError::Allocation)?;
        indirect.push(CoreValueType::I32);
        indirect
    };
    let flat_results = match function.result.as_ref() {
        Some(result) => {
            flat_signature(core::slice::from_ref(result)).map_err(|_| SyncError::InvalidWiring)?
        }
        None => Vec::new(),
    };
    let results = if flat_results.len() <= MAX_FLAT_RESULTS {
        core_value_types(&flat_results)?
    } else {
        parameters
            .try_reserve(1)
            .map_err(|_| SyncError::Allocation)?;
        parameters.push(CoreValueType::I32);
        Vec::new()
    };
    Ok((parameters, results))
}

fn core_value_types(flat: &[FlatKind]) -> Result<Vec<CoreValueType>, SyncError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(flat.len())
        .map_err(|_| SyncError::Allocation)?;
    for kind in flat {
        result.push(match kind {
            FlatKind::I32 => CoreValueType::I32,
            FlatKind::I64 => CoreValueType::I64,
        });
    }
    Ok(result)
}

fn host_function_requires_resource_transfer(function: &FunctionType) -> bool {
    function
        .parameters
        .iter()
        .any(|parameter| contains_owned_resource(&parameter.value))
        || function.result.as_ref().is_some_and(contains_resource)
}

fn contains_resource(value: &ValueType) -> bool {
    match value {
        ValueType::Resource { .. } => true,
        ValueType::List(value) | ValueType::Option(value) => contains_resource(value),
        ValueType::Tuple(values) | ValueType::Record(values) => {
            values.iter().any(contains_resource)
        }
        ValueType::Result { ok, error } => ok
            .iter()
            .chain(error.iter())
            .any(|value| contains_resource(value)),
        ValueType::Variant(cases) => cases.iter().flatten().any(contains_resource),
        _ => false,
    }
}

fn contains_owned_resource(value: &ValueType) -> bool {
    match value {
        ValueType::Resource {
            ownership: ResourceOwnership::Own,
            ..
        } => true,
        ValueType::List(value) | ValueType::Option(value) => contains_owned_resource(value),
        ValueType::Tuple(values) | ValueType::Record(values) => {
            values.iter().any(contains_owned_resource)
        }
        ValueType::Result { ok, error } => ok
            .iter()
            .chain(error.iter())
            .any(|value| contains_owned_resource(value)),
        ValueType::Variant(cases) => cases.iter().flatten().any(contains_owned_resource),
        _ => false,
    }
}

fn contains_payload_allocation(value: &ValueType) -> bool {
    match value {
        ValueType::String | ValueType::List(_) => true,
        ValueType::Tuple(values) | ValueType::Record(values) => {
            values.iter().any(contains_payload_allocation)
        }
        ValueType::Option(value) => contains_payload_allocation(value),
        ValueType::Result { ok, error } => ok
            .iter()
            .chain(error.iter())
            .any(|value| contains_payload_allocation(value)),
        ValueType::Variant(cases) => cases.iter().flatten().any(contains_payload_allocation),
        _ => false,
    }
}

fn result_lower_work_reservation(function: &FunctionType) -> Result<u64, TrapCode> {
    let Some(result) = function.result.as_ref() else {
        return Ok(0);
    };
    let dynamic = contains_payload_allocation(result);
    let nodes = if dynamic {
        u64::from(PROFILE_1_LIMITS.max_canonical_values)
    } else {
        max_selected_nodes(result)?
    };
    let payload_bytes = if dynamic {
        u64::try_from(PROFILE_1_LIMITS.max_canonical_value_bytes)
            .map_err(|_| TrapCode::LimitExceeded)?
    } else {
        0
    };
    let flat = flat_signature(core::slice::from_ref(result)).map_err(|_| TrapCode::CanonicalAbi)?;
    if flat.len() <= MAX_FLAT_RESULTS {
        return nodes
            .checked_add(payload_bytes)
            .ok_or(TrapCode::LimitExceeded);
    }
    let bytes = u64::try_from(
        crate::value::validate_type(result)
            .map_err(|_| TrapCode::CanonicalAbi)?
            .layout
            .size,
    )
    .map_err(|_| TrapCode::LimitExceeded)?;
    nodes
        .checked_add(payload_bytes)
        .and_then(|work| work.checked_add(bytes))
        .ok_or(TrapCode::LimitExceeded)
}

fn max_selected_nodes(value: &ValueType) -> Result<u64, TrapCode> {
    let descendants = match value {
        ValueType::List(value) | ValueType::Option(value) => max_selected_nodes(value)?,
        ValueType::Tuple(values) | ValueType::Record(values) => {
            let mut total = 0_u64;
            for value in values {
                total = total
                    .checked_add(max_selected_nodes(value)?)
                    .ok_or(TrapCode::LimitExceeded)?;
            }
            total
        }
        ValueType::Result { ok, error } => max_optional_selected_nodes(ok.as_deref())?
            .max(max_optional_selected_nodes(error.as_deref())?),
        ValueType::Variant(cases) => {
            let mut maximum = 0_u64;
            for case in cases {
                maximum = maximum.max(max_optional_selected_nodes(case.as_ref())?);
            }
            maximum
        }
        _ => 0,
    };
    descendants.checked_add(1).ok_or(TrapCode::LimitExceeded)
}

fn max_optional_selected_nodes(value: Option<&ValueType>) -> Result<u64, TrapCode> {
    value.map_or(Ok(0), max_selected_nodes)
}

fn copied(value: &str) -> Result<String, SyncError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| SyncError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn zero_baselines(count: usize) -> Result<Vec<u64>, SyncError> {
    let mut baselines = Vec::new();
    baselines
        .try_reserve_exact(count)
        .map_err(|_| SyncError::Allocation)?;
    baselines.resize(count, 0);
    Ok(baselines)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedCallMetrics {
    pub consumed_work: u64,
    pub remaining_work: u64,
}

/// Caller-supplied monotonic tick source for the portable C8.4 profiler.
///
/// The runtime deliberately assigns no unit or platform implementation to a
/// tick. Tick subtraction is wrapping, so one hardware-counter wrap remains a
/// valid interval. A clock that moves backwards for any other reason produces
/// a conservatively large interval which saturates the corresponding counter.
#[cfg(feature = "c84-profile-hooks")]
pub trait ProfileClock {
    fn ticks(&mut self) -> u64;

    /// Switches an external phase recorder to Core interpretation and returns
    /// the tick sampled after that observer work, immediately before entering
    /// the interpreter. An override must sample the returned tick as its final
    /// operation. Clocks interested only in totals need only implement
    /// [`ProfileClock::ticks`].
    fn core_poll_started(&mut self) -> u64 {
        self.ticks()
    }

    /// Observes the exact tick sampled immediately after leaving the Core
    /// interpreter.
    fn core_poll_finished(&mut self, _tick: u64) {}
}

/// Cumulative timing and work buckets for profiled synchronous typed polls.
///
/// Every field uses saturating accumulation. `consumed_work` includes only
/// work charged while calling [`TypedCall::poll_profiled`], not construction
/// and Canonical ABI planning performed before the call is returned. A formal
/// whole-call `fuel_consumed` value must therefore come from terminal
/// [`TypedCallMetrics::consumed_work`], not this profiling delta.
///
/// These five counters are not an exhaustive platform phase ledger. Without
/// additional trap hooks, `core_interpreter_ticks` includes interrupt/trap
/// service that occurs inside `poll_call`; outer-minus-core combines Canonical
/// ABI, host-dispatch, and portable runtime work. The clock observer callbacks
/// expose real Core boundaries so a platform collector can refine those
/// phases instead of reconstructing intervals from aggregate totals.
///
/// A field that reaches `u64::MAX` is a fail-closed, unpublishable sample. The
/// saturated value prevents under-reporting but must not be emitted as a valid
/// formal measurement.
#[cfg(feature = "c84-profile-hooks")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncCallProfile {
    pub typed_polls: u64,
    pub core_polls: u64,
    pub outer_poll_ticks: u64,
    pub core_interpreter_ticks: u64,
    pub consumed_work: u64,
}

trait SyncPollProfiler {
    type CoreStart;

    fn begin_core_poll(&mut self) -> Self::CoreStart;
    fn end_core_poll(&mut self, started: Self::CoreStart);
}

struct Unprofiled;

impl SyncPollProfiler for Unprofiled {
    type CoreStart = ();

    fn begin_core_poll(&mut self) {}

    fn end_core_poll(&mut self, (): ()) {}
}

#[cfg(feature = "c84-profile-hooks")]
struct ProfileSession<'a, C: ProfileClock + ?Sized> {
    clock: &'a mut C,
    profile: &'a mut SyncCallProfile,
}

#[cfg(feature = "c84-profile-hooks")]
impl<C: ProfileClock + ?Sized> SyncPollProfiler for ProfileSession<'_, C> {
    type CoreStart = u64;

    fn begin_core_poll(&mut self) -> Self::CoreStart {
        self.clock.core_poll_started()
    }

    fn end_core_poll(&mut self, started: Self::CoreStart) {
        let finished = self.clock.ticks();
        self.clock.core_poll_finished(finished);
        let elapsed = finished.wrapping_sub(started);
        self.profile.core_polls = self.profile.core_polls.saturating_add(1);
        self.profile.core_interpreter_ticks =
            self.profile.core_interpreter_ticks.saturating_add(elapsed);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TypedPoll {
    Pending(TypedCallMetrics),
    /// The Core guest is suspended at one exact host operation. Repeated
    /// ordinary polls return the same copy-only token without consulting the
    /// dispatcher; the supervisor must register a wake and explicitly resume.
    HostPending(HostOperationToken),
    Ready(CanonicalValue),
    /// A typed failure returned by the trusted host boundary. This is kept
    /// distinct from a guest/runtime trap so supervisors can preserve denied,
    /// unavailable, and backend-fault terminal semantics.
    HostFailed(HostError),
    Trapped(TrapCode),
}

#[derive(Clone, Copy)]
enum CallFailure {
    Host(HostError),
    Trap(TrapCode),
}

impl From<HostError> for CallFailure {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}

impl From<TrapCode> for CallFailure {
    fn from(trap: TrapCode) -> Self {
        Self::Trap(trap)
    }
}

enum TypedStage {
    Allocate,
    Replay,
    Transform,
    HostAllocate,
    HostDispatch,
    HostShrink,
    HostCommit,
    HostWaiting,
    HostFreeUnused,
    Lift,
    PostReturn,
    Cleanup,
    Terminal(TrapCode),
    Complete,
}

/// One non-async Component call. Every `poll` drives at most one Core call
/// poll, so a Core `Pending` is never hidden behind an internal loop.
pub struct TypedCall<'a, A> {
    component: &'a mut SynchronousComponent,
    resources: &'a mut ResourceTable<A>,
    dispatcher: Option<&'a mut dyn HostDispatcher<A>>,
    export: usize,
    arguments: Vec<CanonicalValue>,
    allocations: Vec<AllocationRequest>,
    allocation_index: usize,
    pointers: Vec<u32>,
    replay_arguments: Option<Vec<CoreValue>>,
    core_results: Option<Vec<CoreValue>>,
    result: Option<CanonicalValue>,
    stage: TypedStage,
    total_work: u64,
    remaining_work: u64,
    poll_quantum: u64,
    active_baselines: Vec<u64>,
    host_lower: Option<PendingHostLower>,
    cancelled: bool,
    guest_started: bool,
    guest_resources: Option<GuestCallResources>,
}

struct PendingHostLower {
    call_id: u32,
    outer_instance: usize,
    import_index: usize,
    function: FunctionType,
    arguments: Vec<CanonicalValue>,
    caller_retptr: Option<u32>,
    memory: Option<HostCoreExportInfo>,
    realloc: Option<HostCoreExportInfo>,
    allocations: Vec<AllocationRequest>,
    pointers: Vec<u32>,
    shrink_reservations: Vec<Option<CoreCallReservation>>,
    free_reservations: Vec<CoreCallReservation>,
    allocation_index: usize,
    shrink_index: usize,
    exact_allocations: Option<Vec<AllocationRequest>>,
    phase: PendingHostPhase,
    required_host_work: u64,
    lower_reservation: u64,
    actual_lower_work: u64,
    provider_reservation: u64,
    provider_consumed: u64,
    provider_fuel_per_call: u64,
    free_index: usize,
    resume_results: Option<Vec<CoreValue>>,
    resume_after_free: Option<Vec<CoreValue>>,
    failure_after_free: Option<CallFailure>,
    lowering_journal: LoweringJournal,
    flat_results: Option<PreparedFlatResults>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingHostPhase {
    Start,
    Waiting {
        operation: HostOperationToken,
        wake_registered: bool,
    },
    ResumeRequested(HostOperationToken),
    Prepared(HostOperationToken),
    Consumed,
}

impl<'a, A> TypedCall<'a, A> {
    fn terminal(
        component: &'a mut SynchronousComponent,
        resources: &'a mut ResourceTable<A>,
        dispatcher: Option<&'a mut dyn HostDispatcher<A>>,
        export: usize,
        total_work: u64,
        poll_quantum: u64,
        trap: TrapCode,
    ) -> Self {
        Self {
            component,
            resources,
            dispatcher,
            export,
            arguments: Vec::new(),
            allocations: Vec::new(),
            allocation_index: 0,
            pointers: Vec::new(),
            replay_arguments: None,
            core_results: None,
            result: None,
            stage: TypedStage::Terminal(trap),
            total_work,
            remaining_work: 0,
            poll_quantum,
            active_baselines: Vec::new(),
            host_lower: None,
            cancelled: false,
            guest_started: false,
            guest_resources: None,
        }
    }

    pub const fn metrics(&self) -> TypedCallMetrics {
        TypedCallMetrics {
            consumed_work: self.total_work - self.remaining_work,
            remaining_work: self.remaining_work,
        }
    }

    /// Register the supervisor's sole wake envelope for the exact operation
    /// returned by [`TypedPoll::HostPending`]. A duplicate or stale token is
    /// rejected before the dispatcher is called.
    pub fn register_host_wake(
        &mut self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), HostError> {
        let matches = self.host_lower.as_ref().is_some_and(|pending| {
            matches!(
                pending.phase,
                PendingHostPhase::Waiting {
                    operation: expected,
                    wake_registered: false,
                } if expected == operation
            )
        });
        if !matches || !matches!(self.stage, TypedStage::HostWaiting) {
            return Err(HostError::InvalidArgument);
        }
        self.dispatcher
            .as_deref_mut()
            .ok_or(HostError::BackendFault)?
            .register_wake(operation, wake)?;
        let Some(pending) = self.host_lower.as_mut() else {
            return Err(HostError::BackendFault);
        };
        pending.phase = PendingHostPhase::Waiting {
            operation,
            wake_registered: true,
        };
        Ok(())
    }

    /// Authorize one dispatcher retry after the registered wake fired.
    ///
    /// This method only records the exact resume intent. The next `poll` makes
    /// one `HostDispatcher::resume` call; further ordinary polls never retry
    /// it implicitly.
    pub fn resume_host(&mut self, operation: HostOperationToken) -> Result<(), HostError> {
        let matches = self.host_lower.as_ref().is_some_and(|pending| {
            matches!(
                pending.phase,
                PendingHostPhase::Waiting {
                    operation: expected,
                    wake_registered: true,
                } if expected == operation
            )
        });
        if !matches || !matches!(self.stage, TypedStage::HostWaiting) {
            return Err(HostError::InvalidArgument);
        }
        self.host_lower
            .as_mut()
            .expect("validated pending host lower")
            .phase = PendingHostPhase::ResumeRequested(operation);
        self.stage = TypedStage::HostDispatch;
        Ok(())
    }

    pub fn cancel(&mut self) {
        if matches!(self.stage, TypedStage::Terminal(_) | TypedStage::Complete) {
            return;
        }
        let _ = self.cancel_live_host_operation();
        self.cancelled = true;
        self.component.poisoned = true;
        self.component.modules.discard_all_calls();
    }

    pub fn poll(&mut self) -> TypedPoll {
        self.poll_with_profiler(&mut Unprofiled)
    }

    /// Polls through the ordinary synchronous path while recording portable
    /// C8.4 timing buckets with a caller-owned clock.
    ///
    /// The outer bucket inclusively spans the complete typed poll, including
    /// interpreter time. The interpreter bucket spans the two clock samples
    /// immediately bracketing `CoreComponentGroup::poll_call`; setup,
    /// Canonical ABI work, and result handling remain exclusively in the outer
    /// bucket. Subtracting `core_interpreter_ticks` from `outer_poll_ticks`
    /// therefore yields non-interpreter overhead for the same samples.
    #[cfg(feature = "c84-profile-hooks")]
    pub fn poll_profiled<C: ProfileClock + ?Sized>(
        &mut self,
        clock: &mut C,
        profile: &mut SyncCallProfile,
    ) -> TypedPoll {
        let work_before = self.metrics().consumed_work;
        let outer_started = clock.ticks();
        let mut session = ProfileSession { clock, profile };
        let result = self.poll_with_profiler(&mut session);
        let outer_elapsed = session.clock.ticks().wrapping_sub(outer_started);
        let work_after = self.metrics().consumed_work;
        // A decreasing work ledger is an invariant violation. Charge the
        // maximum rather than silently under-reporting the sample.
        let consumed = work_after.checked_sub(work_before).unwrap_or(u64::MAX);
        session.profile.typed_polls = session.profile.typed_polls.saturating_add(1);
        session.profile.outer_poll_ticks = session
            .profile
            .outer_poll_ticks
            .saturating_add(outer_elapsed);
        session.profile.consumed_work = session.profile.consumed_work.saturating_add(consumed);
        result
    }

    fn poll_with_profiler<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        if self.cancelled {
            self.stage = TypedStage::Terminal(TrapCode::Cancelled);
        }
        match self.stage {
            TypedStage::Terminal(trap) => {
                if self.close_resources(false).is_err() {
                    self.component.poisoned = true;
                }
                self.stage = TypedStage::Complete;
                TypedPoll::Trapped(trap)
            }
            TypedStage::Complete => TypedPoll::Trapped(TrapCode::Cancelled),
            TypedStage::Allocate => self.poll_allocate(profile),
            TypedStage::Replay => self.replay(),
            TypedStage::Transform => self.poll_transform(profile),
            TypedStage::HostAllocate => self.poll_host_allocate(profile),
            TypedStage::HostDispatch => self.dispatch_host_call(),
            TypedStage::HostShrink => self.poll_host_shrink(profile),
            TypedStage::HostCommit => self.commit_prepared_host_call(),
            TypedStage::HostWaiting => self.poll_host_waiting(),
            TypedStage::HostFreeUnused => self.poll_host_free_unused(profile),
            TypedStage::Lift => self.lift(),
            TypedStage::PostReturn => self.poll_post_return(profile),
            TypedStage::Cleanup => self.poll_cleanup(profile),
        }
    }

    fn poll_allocate<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        if self.active_instance().is_none() {
            if self.allocation_index >= self.allocations.len() {
                self.stage = TypedStage::Replay;
                return TypedPoll::Pending(self.metrics());
            }
            let request = self.allocations[self.allocation_index];
            let inputs = [
                CoreValue::I32(0),
                CoreValue::I32(0),
                CoreValue::I32(request.alignment as i32),
                CoreValue::I32(request.size as i32),
            ];
            if let Err(trap) = self.start_subcall(Subcall::Realloc, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall(profile) {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) => match values.as_slice() {
                [CoreValue::I32(pointer)] if *pointer != 0 => {
                    let request = self.allocations[self.allocation_index];
                    let pointer = *pointer as u32;
                    if pointer & (request.alignment - 1) != 0
                        || !self.valid_allocation(pointer, request.size)
                    {
                        return self.finish_trap(TrapCode::CanonicalAbi);
                    }
                    if self.pointers.try_reserve(1).is_err() {
                        return self.finish_trap(TrapCode::LimitExceeded);
                    }
                    self.pointers.push(pointer);
                    self.allocation_index += 1;
                    TypedPoll::Pending(self.metrics())
                }
                _ => self.finish_trap(TrapCode::CanonicalAbi),
            },
        }
    }

    fn replay(&mut self) -> TypedPoll {
        let binding = &self.component.exports[self.export];
        let instance_index = binding.core_instance;
        let parameter_types =
            match clone_parameter_types(&self.component.exports[self.export].function_type) {
                Ok(types) => types,
                Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
            };
        let mut replay = ReplayAllocator {
            pointers: &self.pointers,
            requests: &self.allocations,
            cursor: 0,
        };
        let lowered = match binding.memory.as_deref() {
            Some(memory_name) => {
                let mut memory = match CoreGuestMemory::new(
                    &mut self.component.modules,
                    instance_index,
                    memory_name,
                ) {
                    Ok(memory) => memory,
                    Err(_) => return self.finish_trap(TrapCode::MemoryOutOfBounds),
                };
                lower_parameters(&mut memory, &mut replay, &parameter_types, &self.arguments)
            }
            None => {
                let mut memory = NoGuestMemory;
                lower_parameters(&mut memory, &mut replay, &parameter_types, &self.arguments)
            }
        };
        let lowered = match lowered {
            Ok(lowered) if replay.cursor == replay.requests.len() => lowered,
            _ => return self.finish_trap(TrapCode::CanonicalAbi),
        };
        self.replay_arguments = match lowered_parts(lowered) {
            Ok((arguments, _)) => Some(arguments),
            Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
        };
        self.stage = TypedStage::Transform;
        TypedPoll::Pending(self.metrics())
    }

    fn poll_transform<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        if self.active_instance().is_none() {
            let Some(arguments) = self.replay_arguments.take() else {
                return self.finish_trap(TrapCode::Validation);
            };
            if let Err(trap) = self.start_subcall(Subcall::Transform, &arguments) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall(profile) {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(call) => self.handle_host_call(call),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(results) => {
                self.core_results = Some(results);
                self.stage = TypedStage::Lift;
                TypedPoll::Pending(self.metrics())
            }
        }
    }

    fn handle_host_call(&mut self, call: CoreHostCall) -> TypedPoll {
        match self.handle_host_call_inner(call) {
            Ok(()) => TypedPoll::Pending(self.metrics()),
            Err(CallFailure::Host(error)) => self.finish_host_failure(error),
            Err(CallFailure::Trap(trap)) => self.finish_trap(trap),
        }
    }

    fn handle_host_call_inner(&mut self, call: CoreHostCall) -> Result<(), CallFailure> {
        let import_index = usize::try_from(call.id).map_err(|_| TrapCode::Validation)?;
        let active_instance = self
            .component
            .exports
            .get(self.export)
            .map(|export| export.core_instance)
            .ok_or(TrapCode::Validation)?;
        let function = {
            let import = self
                .component
                .host_imports
                .get(import_index)
                .ok_or(TrapCode::Validation)?;
            if call.origin_instance != import.core_instance {
                return Err(TrapCode::Validation.into());
            }
            crate::types::try_clone_function_type(&import.function_type)
                .map_err(|_| TrapCode::LimitExceeded)?
        };
        let parameter_types =
            clone_parameter_types(&function).map_err(|_| TrapCode::LimitExceeded)?;
        let flat_parameters =
            flat_signature(&parameter_types).map_err(|_| TrapCode::CanonicalAbi)?;
        let parameter_arity = if flat_parameters.len() <= MAX_FLAT_PARAMS {
            flat_parameters.len()
        } else {
            1
        };
        let flat_results = match function.result.as_ref() {
            Some(result) => {
                flat_signature(core::slice::from_ref(result)).map_err(|_| TrapCode::CanonicalAbi)?
            }
            None => Vec::new(),
        };
        let has_retptr = flat_results.len() > MAX_FLAT_RESULTS;
        let expected_arguments = parameter_arity
            .checked_add(usize::from(has_retptr))
            .ok_or(TrapCode::LimitExceeded)?;
        if call.arguments.len() != expected_arguments {
            return Err(TrapCode::CanonicalAbi.into());
        }
        let caller_retptr = if has_retptr {
            match call.arguments.last() {
                Some(CoreValue::I32(pointer)) => Some(*pointer as u32),
                _ => return Err(TrapCode::CanonicalAbi.into()),
            }
        } else {
            None
        };

        let (mut arguments, lift_usage) = {
            let import = self
                .component
                .host_imports
                .get(import_index)
                .ok_or(TrapCode::Validation)?;
            let scope = self.guest_resources.as_ref().ok_or(TrapCode::Validation)?;
            let binder = HostParameterBinder {
                table: &*self.resources,
                scope,
            };
            let core_arguments = &call.arguments[..parameter_arity];
            match import.memory.as_ref() {
                Some(binding) => {
                    let memory = CoreGuestMemory::new(
                        &mut self.component.modules,
                        binding.core_instance,
                        &binding.export,
                    )
                    .map_err(|_| TrapCode::MemoryOutOfBounds)?;
                    lift_parameters(&memory, &binder, &parameter_types, core_arguments)
                        .map_err(|_| TrapCode::CanonicalAbi)?
                }
                None => {
                    let memory = NoGuestMemory;
                    lift_parameters(&memory, &binder, &parameter_types, core_arguments)
                        .map_err(|_| TrapCode::CanonicalAbi)?
                }
            }
        };
        self.charge(lift_usage.work)
            .map_err(|_| TrapCode::FuelExhausted)?;
        self.component
            .modules
            .debit_call_fuel(active_instance, lift_usage.work)
            .map_err(|_| TrapCode::FuelExhausted)?;
        let baseline = self
            .active_baselines
            .get_mut(active_instance)
            .ok_or(TrapCode::Validation)?;
        *baseline = baseline
            .checked_add(lift_usage.work)
            .ok_or(TrapCode::LimitExceeded)?;
        lift_host_argument_resources(
            &parameter_types,
            &mut arguments,
            self.resources,
            self.guest_resources.as_mut().ok_or(TrapCode::Validation)?,
        )
        .map_err(|_| TrapCode::ResourceMisuse)?;
        let lower_reservation = result_lower_work_reservation(&function)?;

        let required_host_work = {
            let dispatcher = self.dispatcher.as_deref().ok_or(TrapCode::Validation)?;
            let import = self
                .component
                .host_imports
                .get(import_index)
                .ok_or(TrapCode::Validation)?;
            dispatcher
                .required_work(import, &arguments)
                .map_err(CallFailure::Host)?
        };
        if required_host_work == 0 {
            return Err(TrapCode::Validation.into());
        }
        let planned_allocations = {
            let dispatcher = self.dispatcher.as_deref().ok_or(TrapCode::Validation)?;
            let import = self
                .component
                .host_imports
                .get(import_index)
                .ok_or(TrapCode::Validation)?;
            dispatcher
                .result_allocations(import, &arguments)
                .map_err(CallFailure::Host)?
        };
        if planned_allocations.len() > PROFILE_1_LIMITS.max_abi_allocations as usize {
            return Err(TrapCode::LimitExceeded.into());
        }
        let mut allocations = Vec::new();
        allocations
            .try_reserve_exact(planned_allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        for allocation in planned_allocations {
            if allocation.size == 0
                || allocation.alignment == 0
                || !allocation.alignment.is_power_of_two()
            {
                return Err(TrapCode::Validation.into());
            }
            allocations.push(AllocationRequest {
                size: allocation.size,
                alignment: allocation.alignment,
            });
        }
        let (memory, realloc) = {
            let import = self
                .component
                .host_imports
                .get(import_index)
                .ok_or(TrapCode::Validation)?;
            (
                clone_host_binding(import.memory.as_ref())?,
                clone_host_binding(import.realloc.as_ref())?,
            )
        };
        if (!allocations.is_empty() || caller_retptr.is_some()) && memory.is_none() {
            return Err(TrapCode::Validation.into());
        }
        if !allocations.is_empty() && realloc.is_none() {
            return Err(TrapCode::Validation.into());
        }
        if let Some(pointer) = caller_retptr {
            validate_host_retptr(&self.component.modules, memory.as_ref(), &function, pointer)?;
        }
        let provider_fuel_per_call = self.poll_quantum;
        // Reserve initial allocation, exact prepared-result shrink, and
        // worst-case rollback free fuel before any provider or backend side
        // effect. The unused portion is released only after result lowering
        // and rollback have completed.
        let provider_calls = u64::try_from(allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?
            .checked_mul(3)
            .ok_or(TrapCode::LimitExceeded)?;
        let provider_reservation = provider_calls
            .checked_mul(provider_fuel_per_call)
            .ok_or(TrapCode::LimitExceeded)?;
        let reserved_work = required_host_work
            .checked_add(lower_reservation)
            .and_then(|work| work.checked_add(provider_reservation))
            .ok_or(TrapCode::LimitExceeded)?;
        if self.remaining_work <= reserved_work {
            return Err(TrapCode::FuelExhausted.into());
        }
        self.component
            .modules
            .debit_call_fuel(active_instance, reserved_work)
            .map_err(|_| TrapCode::FuelExhausted)?;
        let baseline = self
            .active_baselines
            .get_mut(active_instance)
            .ok_or(TrapCode::Validation)?;
        *baseline = baseline
            .checked_add(reserved_work)
            .ok_or(TrapCode::LimitExceeded)?;
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        let mut free_reservations = Vec::new();
        free_reservations
            .try_reserve_exact(allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        let mut shrink_reservations = Vec::new();
        shrink_reservations
            .try_reserve_exact(allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        if let Some(provider) = realloc.as_ref() {
            for _ in &allocations {
                shrink_reservations.push(Some(
                    self.component
                        .modules
                        .reserve_call(provider.core_instance, &provider.export)?,
                ));
                free_reservations.push(
                    self.component
                        .modules
                        .reserve_call(provider.core_instance, &provider.export)?,
                );
            }
        }
        let lowering_journal = LoweringJournal::try_with_capacity(allocations.len())
            .map_err(|_| TrapCode::LimitExceeded)?;
        let flat_results = if caller_retptr.is_none() {
            Some(
                PreparedFlatResults::try_new(function.result.as_slice())
                    .map_err(|_| TrapCode::CanonicalAbi)?,
            )
        } else {
            None
        };
        let mut resume_results = Vec::new();
        resume_results
            .try_reserve_exact(usize::from(
                caller_retptr.is_none() && function.result.is_some(),
            ))
            .map_err(|_| TrapCode::LimitExceeded)?;
        self.host_lower = Some(PendingHostLower {
            call_id: call.id,
            outer_instance: active_instance,
            import_index,
            function,
            arguments,
            caller_retptr,
            memory,
            realloc,
            allocations,
            pointers,
            shrink_reservations,
            free_reservations,
            allocation_index: 0,
            shrink_index: 0,
            exact_allocations: None,
            phase: PendingHostPhase::Start,
            required_host_work,
            lower_reservation,
            actual_lower_work: 0,
            provider_reservation,
            provider_consumed: 0,
            provider_fuel_per_call,
            free_index: 0,
            resume_results: Some(resume_results),
            resume_after_free: None,
            failure_after_free: None,
            lowering_journal,
            flat_results,
        });
        self.stage = if self
            .host_lower
            .as_ref()
            .is_some_and(|pending| pending.allocations.is_empty())
        {
            TypedStage::HostDispatch
        } else {
            TypedStage::HostAllocate
        };
        Ok(())
    }

    fn poll_host_allocate<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        let Some(pending) = self.host_lower.as_ref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        if pending.allocation_index >= pending.allocations.len() {
            self.stage = TypedStage::HostDispatch;
            return TypedPoll::Pending(self.metrics());
        }
        let provider = match pending.realloc.as_ref() {
            Some(provider) => provider,
            None => return self.finish_trap(TrapCode::Validation),
        };
        let provider_instance = provider.core_instance;
        if !self.component.modules.has_active_call(provider_instance) {
            let request = pending.allocations[pending.allocation_index];
            let inputs = [
                CoreValue::I32(0),
                CoreValue::I32(0),
                CoreValue::I32(request.alignment as i32),
                CoreValue::I32(request.size as i32),
            ];
            if self
                .component
                .modules
                .start_call(
                    provider_instance,
                    &provider.export,
                    &inputs,
                    pending.provider_fuel_per_call,
                    self.poll_quantum.min(pending.provider_fuel_per_call),
                )
                .is_err()
            {
                return self.finish_trap(TrapCode::Validation);
            }
            let Some(baseline) = self.active_baselines.get_mut(provider_instance) else {
                return self.finish_trap(TrapCode::Validation);
            };
            *baseline = 0;
            self.guest_started = true;
        }
        let (result, consumed) = self.poll_instance_measured(provider_instance, true, profile);
        let pending = self.host_lower.as_mut().expect("pending host lower");
        pending.provider_consumed = match pending.provider_consumed.checked_add(consumed) {
            Some(consumed) => consumed,
            None => return self.finish_trap(TrapCode::FuelExhausted),
        };
        match result {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) => match values.as_slice() {
                [CoreValue::I32(pointer)] if *pointer != 0 => {
                    let pointer = *pointer as u32;
                    let pending = self.host_lower.as_mut().expect("pending host lower");
                    let request = pending.allocations[pending.allocation_index];
                    if pointer & (request.alignment - 1) != 0
                        || !valid_bound_allocation(
                            &self.component.modules,
                            pending.memory.as_ref(),
                            &pending.pointers,
                            &pending.allocations,
                            pointer,
                            request.size,
                            pending.caller_retptr.and_then(|retptr| {
                                host_retptr_span(&pending.function, retptr).ok()
                            }),
                        )
                    {
                        return self.finish_trap(TrapCode::CanonicalAbi);
                    }
                    pending.pointers.push(pointer);
                    pending.allocation_index += 1;
                    TypedPoll::Pending(self.metrics())
                }
                _ => self.finish_trap(TrapCode::CanonicalAbi),
            },
        }
    }

    fn dispatch_host_call(&mut self) -> TypedPoll {
        let Some(mut pending) = self.host_lower.take() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let previous_operation = match pending.phase {
            PendingHostPhase::Start => None,
            PendingHostPhase::ResumeRequested(operation) => Some(operation),
            _ => {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            }
        };
        // `start` and `resume` each consume their action exactly once, on
        // every return. Mark it consumed before crossing the trusted boundary
        // so cancellation cannot race a completed dispatcher action.
        pending.phase = PendingHostPhase::Consumed;
        let dispatch = {
            let Some(dispatcher) = self.dispatcher.as_deref_mut() else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(import) = self.component.host_imports.get(pending.import_index) else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(scope) = self.guest_resources.as_ref() else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let request = HostRequest::new(import, &pending.arguments, &*self.resources, scope);
            match previous_operation {
                Some(operation) => dispatcher.resume(operation, request),
                None => dispatcher.start(request),
            }
        };
        let dispatch = match dispatch {
            Ok(dispatch) => dispatch,
            Err(error) => {
                return self.defer_host_failure_after_cleanup(pending, CallFailure::Host(error));
            }
        };
        match dispatch {
            HostDispatch::Ready(response) => self.accept_host_response(pending, response),
            HostDispatch::Pending(operation) => {
                if previous_operation.is_some_and(|previous| !operation.strictly_after(previous)) {
                    pending.phase = PendingHostPhase::Waiting {
                        operation,
                        wake_registered: false,
                    };
                    return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
                }
                pending.phase = PendingHostPhase::Waiting {
                    operation,
                    wake_registered: false,
                };
                self.host_lower = Some(pending);
                self.stage = TypedStage::HostWaiting;
                TypedPoll::HostPending(operation)
            }
            HostDispatch::Prepared(prepared) => {
                if previous_operation
                    .is_some_and(|previous| !prepared.operation().strictly_after(previous))
                {
                    pending.phase = PendingHostPhase::Prepared(prepared.operation());
                    return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
                }
                self.accept_host_prepared(pending, prepared)
            }
        }
    }

    fn poll_host_waiting(&mut self) -> TypedPoll {
        let Some(pending) = self.host_lower.as_ref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        match pending.phase {
            PendingHostPhase::Waiting { operation, .. } => TypedPoll::HostPending(operation),
            _ => self.finish_trap(TrapCode::Validation),
        }
    }

    fn accept_host_prepared(
        &mut self,
        mut pending: PendingHostLower,
        prepared: HostPrepared,
    ) -> TypedPoll {
        let (operation, exact) = prepared.into_parts();
        pending.phase = PendingHostPhase::Prepared(operation);
        if exact.len() != pending.allocations.len()
            || exact.len() > PROFILE_1_LIMITS.max_abi_allocations as usize
        {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
        }
        let mut exact_allocations = Vec::new();
        if exact_allocations.try_reserve_exact(exact.len()).is_err() {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::LimitExceeded);
        }
        for (maximum, exact) in pending.allocations.iter().zip(exact) {
            if exact.size == 0
                || exact.size > maximum.size
                || exact.alignment != maximum.alignment
                || exact.alignment == 0
                || !exact.alignment.is_power_of_two()
            {
                return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
            }
            exact_allocations.push(AllocationRequest {
                size: exact.size,
                alignment: exact.alignment,
            });
        }
        pending.exact_allocations = Some(exact_allocations);
        pending.shrink_index = 0;
        self.host_lower = Some(pending);
        self.stage = TypedStage::HostShrink;
        TypedPoll::Pending(self.metrics())
    }

    fn poll_host_shrink<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        let (index, old, exact, provider_instance) = {
            let Some(pending) = self.host_lower.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            if !matches!(pending.phase, PendingHostPhase::Prepared(_)) {
                return self.finish_trap(TrapCode::Validation);
            }
            let Some(exact_allocations) = pending.exact_allocations.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            if pending.shrink_index >= exact_allocations.len() {
                self.stage = TypedStage::HostCommit;
                return TypedPoll::Pending(self.metrics());
            }
            let index = pending.shrink_index;
            let Some(old) = pending.allocations.get(index).copied() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let exact = exact_allocations[index];
            let Some(provider) = pending.realloc.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            (index, old, exact, provider.core_instance)
        };
        if old == exact {
            self.host_lower
                .as_mut()
                .expect("validated pending host lower")
                .shrink_index += 1;
            return TypedPoll::Pending(self.metrics());
        }
        if !self.component.modules.has_active_call(provider_instance) {
            let poll_quantum = self.poll_quantum;
            let modules = &mut self.component.modules;
            let active_baselines = &mut self.active_baselines;
            let Some(pending) = self.host_lower.as_mut() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(provider) = pending.realloc.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(pointer) = pending.pointers.get(index).copied() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(reservation) = pending
                .shrink_reservations
                .get_mut(index)
                .and_then(Option::take)
            else {
                return self.finish_trap(TrapCode::Validation);
            };
            let provider_fuel = pending.provider_fuel_per_call;
            let inputs = [
                CoreValue::I32(pointer as i32),
                CoreValue::I32(old.size as i32),
                CoreValue::I32(old.alignment as i32),
                CoreValue::I32(exact.size as i32),
            ];
            if modules
                .start_call_reserved(
                    reservation,
                    provider_instance,
                    &provider.export,
                    &inputs,
                    provider_fuel,
                    poll_quantum.min(provider_fuel),
                )
                .is_err()
            {
                return self.finish_trap(TrapCode::Validation);
            }
            let Some(baseline) = active_baselines.get_mut(provider_instance) else {
                return self.finish_trap(TrapCode::Validation);
            };
            *baseline = 0;
            self.guest_started = true;
        }
        let (result, consumed) = self.poll_instance_measured(provider_instance, true, profile);
        let pending = self.host_lower.as_mut().expect("pending host lower");
        pending.provider_consumed = match pending.provider_consumed.checked_add(consumed) {
            Some(consumed) => consumed,
            None => return self.finish_trap(TrapCode::FuelExhausted),
        };
        match result {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) => match values.as_slice() {
                [CoreValue::I32(pointer)] if *pointer != 0 => {
                    let pointer = *pointer as u32;
                    let pending = self.host_lower.as_mut().expect("pending host lower");
                    if pointer & (exact.alignment - 1) != 0
                        || !valid_bound_reallocation(
                            &self.component.modules,
                            pending.memory.as_ref(),
                            &pending.pointers,
                            &pending.allocations,
                            ReallocationSpan {
                                replaced: index,
                                pointer,
                                size: exact.size,
                            },
                            pending.caller_retptr.and_then(|retptr| {
                                host_retptr_span(&pending.function, retptr).ok()
                            }),
                        )
                    {
                        return self.finish_trap(TrapCode::CanonicalAbi);
                    }
                    pending.pointers[index] = pointer;
                    pending.allocations[index] = exact;
                    pending.shrink_index += 1;
                    TypedPoll::Pending(self.metrics())
                }
                _ => self.finish_trap(TrapCode::CanonicalAbi),
            },
        }
    }

    fn commit_prepared_host_call(&mut self) -> TypedPoll {
        let Some(mut pending) = self.host_lower.take() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let operation = match pending.phase {
            PendingHostPhase::Prepared(operation) => operation,
            _ => {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            }
        };
        let response = {
            let Some(dispatcher) = self.dispatcher.as_deref_mut() else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(import) = self.component.host_imports.get(pending.import_index) else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(scope) = self.guest_resources.as_ref() else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            dispatcher.commit_prepared(
                operation,
                HostRequest::new(import, &pending.arguments, &*self.resources, scope),
            )
        };
        match response {
            Ok(response) => {
                pending.phase = PendingHostPhase::Consumed;
                self.accept_host_response(pending, response)
            }
            Err(error) => self.defer_host_failure_after_cleanup(pending, CallFailure::Host(error)),
        }
    }

    fn accept_host_response(
        &mut self,
        mut pending: PendingHostLower,
        response: crate::host::HostResponse,
    ) -> TypedPoll {
        let (mut values, host_work) = response.into_parts();
        if host_work != pending.required_host_work {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
        }
        let shape = match pending.function.result.as_ref() {
            Some(result) if values.len() == 1 => validate_value_with_resources(
                result,
                &values[0],
                self.resources,
                ValuePosition::Result,
            ),
            None if values.is_empty() => Ok(Default::default()),
            _ => {
                return self.defer_host_trap_after_cleanup(pending, TrapCode::CanonicalAbi);
            }
        };
        if shape.is_err() {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::ResourceMisuse);
        }
        if let Some(result) = pending.function.result.as_ref() {
            if rewrite_lowered_resources(
                result,
                values.first_mut().expect("one validated result"),
                self.resources,
                self.guest_resources.as_mut().expect("live guest scope"),
            )
            .is_err()
            {
                return self.defer_host_trap_after_cleanup(pending, TrapCode::ResourceMisuse);
            }
        }
        let lowered = lower_host_response(&mut self.component.modules, &mut pending, &values);
        let (core_results, usage, used_allocations) = match lowered {
            Ok(lowered) => lowered,
            Err(trap) => {
                return self.defer_host_trap_after_cleanup(pending, trap);
            }
        };
        if usage.work > pending.lower_reservation || used_allocations > pending.pointers.len() {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
        }
        pending.actual_lower_work = usage.work;
        // Only spans consumed by the selected response branch transfer to the
        // guest. Preallocated inactive-branch spans are rolled back first.
        if used_allocations < pending.pointers.len() {
            pending.free_index = pending.pointers.len();
            pending.allocation_index = used_allocations;
            pending.resume_after_free = Some(core_results);
            self.host_lower = Some(pending);
            self.stage = TypedStage::HostFreeUnused;
            return TypedPoll::Pending(self.metrics());
        }
        if self.release_host_reservation(&pending, usage.work).is_err() {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
        }
        if self
            .component
            .modules
            .resume_host_call(pending.outer_instance, pending.call_id, &core_results)
            .is_err()
        {
            return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
        }
        self.stage = TypedStage::Transform;
        TypedPoll::Pending(self.metrics())
    }

    fn defer_host_trap_after_cleanup(
        &mut self,
        pending: PendingHostLower,
        trap: TrapCode,
    ) -> TypedPoll {
        self.defer_host_failure_after_cleanup(pending, CallFailure::Trap(trap))
    }

    fn defer_host_failure_after_cleanup(
        &mut self,
        mut pending: PendingHostLower,
        failure: CallFailure,
    ) -> TypedPoll {
        if self.cancel_pending_host_operation(&mut pending).is_err() {
            // The dispatcher could not prove that the exact reservation was
            // detached. Do not run guest rollback code against ambiguous
            // state; poison the instance and conservatively leak its spans.
            return self.finish_failure(failure);
        }
        if pending.pointers.is_empty() {
            return self.finish_failure(failure);
        }
        pending.free_index = pending.pointers.len();
        pending.allocation_index = 0;
        pending.failure_after_free = Some(failure);
        self.host_lower = Some(pending);
        self.stage = TypedStage::HostFreeUnused;
        TypedPoll::Pending(self.metrics())
    }

    fn cancel_pending_host_operation(
        &mut self,
        pending: &mut PendingHostLower,
    ) -> Result<(), HostError> {
        let operation = match pending.phase {
            PendingHostPhase::Waiting { operation, .. }
            | PendingHostPhase::ResumeRequested(operation)
            | PendingHostPhase::Prepared(operation) => operation,
            PendingHostPhase::Start | PendingHostPhase::Consumed => return Ok(()),
        };
        // Regardless of the dispatcher result this token must never be used a
        // second time by portable runtime state.
        pending.phase = PendingHostPhase::Consumed;
        self.dispatcher
            .as_deref_mut()
            .ok_or(HostError::BackendFault)?
            .cancel(operation)
    }

    fn cancel_live_host_operation(&mut self) -> Result<(), HostError> {
        let Some(mut pending) = self.host_lower.take() else {
            return Ok(());
        };
        let result = self.cancel_pending_host_operation(&mut pending);
        self.host_lower = Some(pending);
        result
    }

    fn poll_host_free_unused<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        let cleanup_complete = match self.host_lower.as_ref() {
            Some(pending) => pending.free_index <= pending.allocation_index,
            None => return self.finish_trap(TrapCode::Validation),
        };
        if cleanup_complete {
            let mut pending = self.host_lower.take().expect("pending host lower");
            if let Some(failure) = pending.failure_after_free.take() {
                return self.finish_failure(failure);
            }
            let Some(results) = pending.resume_after_free.take() else {
                self.host_lower = Some(pending);
                return self.finish_trap(TrapCode::Validation);
            };
            let actual_lower_work = pending.actual_lower_work;
            debug_assert!(actual_lower_work <= pending.lower_reservation);
            if self
                .release_host_reservation(&pending, actual_lower_work)
                .is_err()
            {
                return self.finish_trap(TrapCode::Validation);
            }
            if self
                .component
                .modules
                .resume_host_call(pending.outer_instance, pending.call_id, &results)
                .is_err()
            {
                pending.pointers.truncate(pending.allocation_index);
                pending.allocations.truncate(pending.allocation_index);
                return self.defer_host_trap_after_cleanup(pending, TrapCode::Validation);
            }
            self.stage = TypedStage::Transform;
            return TypedPoll::Pending(self.metrics());
        }
        let poll_quantum = self.poll_quantum;
        let provider_instance = {
            let modules = &mut self.component.modules;
            let active_baselines = &mut self.active_baselines;
            let Some(pending) = self.host_lower.as_mut() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let Some(provider) = pending.realloc.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let provider_instance = provider.core_instance;
            if !modules.has_active_call(provider_instance) {
                let index = pending.free_index - 1;
                let request = pending.allocations[index];
                let pointer = pending.pointers[index];
                let inputs = [
                    CoreValue::I32(pointer as i32),
                    CoreValue::I32(request.size as i32),
                    CoreValue::I32(request.alignment as i32),
                    CoreValue::I32(0),
                ];
                let Some(reservation) = pending.free_reservations.pop() else {
                    return self.finish_trap(TrapCode::Validation);
                };
                if modules
                    .start_call_reserved(
                        reservation,
                        provider_instance,
                        &provider.export,
                        &inputs,
                        pending.provider_fuel_per_call,
                        poll_quantum.min(pending.provider_fuel_per_call),
                    )
                    .is_err()
                {
                    return self.finish_trap(TrapCode::Validation);
                }
                let Some(baseline) = active_baselines.get_mut(provider_instance) else {
                    return self.finish_trap(TrapCode::Validation);
                };
                *baseline = 0;
            }
            provider_instance
        };
        let (result, consumed) = self.poll_instance_measured(provider_instance, true, profile);
        let pending = self.host_lower.as_mut().expect("pending host lower");
        pending.provider_consumed = match pending.provider_consumed.checked_add(consumed) {
            Some(consumed) => consumed,
            None => return self.finish_trap(TrapCode::FuelExhausted),
        };
        match result {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) if values == [CoreValue::I32(0)] => {
                let pending = self.host_lower.as_mut().expect("pending host lower");
                pending.free_index -= 1;
                pending.pointers.pop();
                pending.allocations.pop();
                TypedPoll::Pending(self.metrics())
            }
            PollResult::Ready(_) => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn lift(&mut self) -> TypedPoll {
        let function_type = match crate::types::try_clone_function_type(
            &self.component.exports[self.export].function_type,
        ) {
            Ok(function) => function,
            Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
        };
        let results = match self.core_results.as_deref() {
            Some(results) => results,
            None => return self.finish_trap(TrapCode::Validation),
        };
        let Some(result_type) = function_type.result.as_ref() else {
            if !results.is_empty() {
                return self.finish_trap(TrapCode::CanonicalAbi);
            }
            // `CanonicalValue` has no unit scalar. Preserve the established
            // one-value completion API with the canonical empty tuple sentinel
            // while keeping the declared function result absent.
            self.result = Some(CanonicalValue::Tuple(Vec::new()));
            if self.component.exports[self.export].post_return.is_some() {
                self.stage = TypedStage::PostReturn;
            } else {
                self.stage = TypedStage::Cleanup;
            }
            return TypedPoll::Pending(self.metrics());
        };
        let binder = TableBinder {
            table: &*self.resources,
        };
        let lifted = match self.component.exports[self.export].memory.as_deref() {
            Some(memory_name) => {
                let instance_index = self.component.exports[self.export].core_instance;
                let memory = match CoreGuestMemory::new(
                    &mut self.component.modules,
                    instance_index,
                    memory_name,
                ) {
                    Ok(memory) => memory,
                    Err(_) => return self.finish_trap(TrapCode::MemoryOutOfBounds),
                };
                lift_results(
                    &memory,
                    &binder,
                    core::slice::from_ref(result_type),
                    results,
                )
            }
            None => {
                let memory = NoGuestMemory;
                lift_results(
                    &memory,
                    &binder,
                    core::slice::from_ref(result_type),
                    results,
                )
            }
        };
        let (mut values, usage) = match lifted {
            Ok(value) => value,
            Err(_) => return self.finish_trap(TrapCode::CanonicalAbi),
        };
        if self.charge(usage.work).is_err() {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        let Some(result) = values.pop() else {
            return self.finish_trap(TrapCode::CanonicalAbi);
        };
        let result = match lift_result_resources(
            result_type,
            result,
            self.resources,
            self.guest_resources
                .as_mut()
                .expect("a running typed call owns one resource scope"),
        ) {
            Ok(result) => result,
            Err(_) => return self.finish_trap(TrapCode::CanonicalAbi),
        };
        self.result = Some(result);
        if self.component.exports[self.export].post_return.is_some() {
            self.stage = TypedStage::PostReturn;
        } else {
            self.stage = TypedStage::Cleanup;
        }
        TypedPoll::Pending(self.metrics())
    }

    fn poll_post_return<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        if self.active_instance().is_none() {
            let Some(results) = self.core_results.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let mut inputs = Vec::new();
            if inputs.try_reserve_exact(results.len()).is_err() {
                return self.finish_trap(TrapCode::LimitExceeded);
            }
            inputs.extend_from_slice(results);
            if let Err(trap) = self.start_subcall(Subcall::PostReturn, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall(profile) {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) if values.is_empty() => {
                self.stage = TypedStage::Cleanup;
                TypedPoll::Pending(self.metrics())
            }
            PollResult::Ready(_) => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn poll_cleanup<P: SyncPollProfiler>(&mut self, profile: &mut P) -> TypedPoll {
        if self.active_instance().is_none() {
            if self.allocation_index == 0 {
                if self.close_resources(true).is_err() {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                self.stage = TypedStage::Complete;
                return TypedPoll::Ready(self.result.take().expect("lift produced one result"));
            }
            let request = self.allocations[self.allocation_index - 1];
            let pointer = self.pointers[self.allocation_index - 1];
            let inputs = [
                CoreValue::I32(pointer as i32),
                CoreValue::I32(request.size as i32),
                CoreValue::I32(request.alignment as i32),
                CoreValue::I32(0),
            ];
            if let Err(trap) = self.start_subcall(Subcall::Free, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall(profile) {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::HostCall(_) => self.finish_trap(TrapCode::Validation),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) if values == [CoreValue::I32(0)] => {
                self.allocation_index -= 1;
                TypedPoll::Pending(self.metrics())
            }
            PollResult::Ready(_) => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn start_subcall(&mut self, kind: Subcall, inputs: &[CoreValue]) -> Result<(), TrapCode> {
        if self.remaining_work == 0 {
            return Err(TrapCode::FuelExhausted);
        }
        let binding = &self.component.exports[self.export];
        let name = match kind {
            Subcall::Realloc => binding.realloc.as_deref(),
            Subcall::Transform => Some(binding.function.as_str()),
            Subcall::PostReturn => binding.post_return.as_deref(),
            Subcall::Free => binding.realloc.as_deref(),
        }
        .ok_or(TrapCode::Validation)?;
        self.component.modules.start_call(
            binding.core_instance,
            name,
            inputs,
            self.remaining_work,
            self.poll_quantum.min(self.remaining_work),
        )?;
        // Each Core call starts a fresh continuation whose consumed-fuel
        // counter begins at zero. Baselines are instance-local because a
        // provider realloc may run while the outer caller remains suspended.
        *self
            .active_baselines
            .get_mut(binding.core_instance)
            .ok_or(TrapCode::Validation)? = 0;
        self.guest_started = true;
        Ok(())
    }

    fn poll_subcall<P: SyncPollProfiler>(&mut self, profile: &mut P) -> PollResult {
        let Some(instance) = self.active_instance() else {
            return PollResult::Trapped(TrapCode::Validation);
        };
        self.poll_instance(instance, false, profile)
    }

    fn poll_instance<P: SyncPollProfiler>(
        &mut self,
        instance: usize,
        precharged: bool,
        profile: &mut P,
    ) -> PollResult {
        self.poll_instance_measured(instance, precharged, profile).0
    }

    fn poll_instance_measured<P: SyncPollProfiler>(
        &mut self,
        instance: usize,
        precharged: bool,
        profile: &mut P,
    ) -> (PollResult, u64) {
        let core_started = profile.begin_core_poll();
        let result = self.component.modules.poll_call(instance);
        profile.end_core_poll(core_started);
        let baseline = self.active_baselines.get_mut(instance);
        let Some(baseline) = baseline else {
            return (PollResult::Trapped(TrapCode::Validation), 0);
        };
        let Some(consumed) = self
            .component
            .modules
            .call_metrics(instance)
            .map_or(Some(0), |metrics| {
                metrics.consumed_fuel.checked_sub(*baseline)
            })
        else {
            return (PollResult::Trapped(TrapCode::Validation), 0);
        };
        let Some(next_baseline) = baseline.checked_add(consumed) else {
            return (PollResult::Trapped(TrapCode::FuelExhausted), 0);
        };
        *baseline = next_baseline;
        if !precharged {
            match self.remaining_work.checked_sub(consumed) {
                Some(remaining) => self.remaining_work = remaining,
                None => {
                    self.component.modules.discard_all_calls();
                    self.component.poisoned = true;
                    return (PollResult::Trapped(TrapCode::FuelExhausted), consumed);
                }
            }
        }
        (result, consumed)
    }

    fn active_instance(&self) -> Option<usize> {
        let index = self.component.exports.get(self.export)?.core_instance;
        self.component
            .modules
            .has_active_call(index)
            .then_some(index)
    }

    fn memory_binding(&self) -> Result<(usize, &str), TrapCode> {
        let binding = self
            .component
            .exports
            .get(self.export)
            .ok_or(TrapCode::Validation)?;
        Ok((
            binding.core_instance,
            binding.memory.as_deref().ok_or(TrapCode::Validation)?,
        ))
    }

    fn valid_span(&self, pointer: u32, size: u32) -> bool {
        let Ok((instance, memory)) = self.memory_binding() else {
            return false;
        };
        let Ok(length) = self.component.modules.memory_size(instance, memory) else {
            return false;
        };
        u64::from(pointer)
            .checked_add(u64::from(size))
            .is_some_and(|end| end <= length as u64)
    }

    fn valid_allocation(&self, pointer: u32, size: u32) -> bool {
        if !self.valid_span(pointer, size) {
            return false;
        }
        let start = u64::from(pointer);
        let end = start + u64::from(size);
        for (index, previous) in self.pointers.iter().copied().enumerate() {
            let Some(request) = self.allocations.get(index) else {
                return false;
            };
            let previous_start = u64::from(previous);
            let previous_end = previous_start + u64::from(request.size);
            if start < previous_end && previous_start < end {
                return false;
            }
        }
        true
    }

    fn charge(&mut self, work: u64) -> Result<(), ()> {
        self.remaining_work = self.remaining_work.checked_sub(work).ok_or(())?;
        Ok(())
    }

    fn release_host_reservation(
        &mut self,
        pending: &PendingHostLower,
        actual_lower_work: u64,
    ) -> Result<(), TrapCode> {
        let unused_lower = pending
            .lower_reservation
            .checked_sub(actual_lower_work)
            .ok_or(TrapCode::Validation)?;
        let unused_provider = pending
            .provider_reservation
            .checked_sub(pending.provider_consumed)
            .ok_or(TrapCode::Validation)?;
        let unused = unused_lower
            .checked_add(unused_provider)
            .ok_or(TrapCode::Validation)?;
        let exact_work = pending
            .required_host_work
            .checked_add(actual_lower_work)
            .and_then(|work| work.checked_add(pending.provider_consumed))
            .ok_or(TrapCode::Validation)?;
        let remaining = self
            .remaining_work
            .checked_sub(exact_work)
            .ok_or(TrapCode::FuelExhausted)?;
        let baseline = self
            .active_baselines
            .get(pending.outer_instance)
            .copied()
            .ok_or(TrapCode::Validation)?
            .checked_sub(unused)
            .ok_or(TrapCode::Validation)?;
        self.component
            .modules
            .credit_call_fuel(pending.outer_instance, unused)?;
        self.remaining_work = remaining;
        *self
            .active_baselines
            .get_mut(pending.outer_instance)
            .expect("validated host-call baseline remains present") = baseline;
        Ok(())
    }

    fn finish_trap(&mut self, trap: TrapCode) -> TypedPoll {
        self.finish_failure(CallFailure::Trap(trap))
    }

    fn finish_host_failure(&mut self, error: HostError) -> TypedPoll {
        self.finish_failure(CallFailure::Host(error))
    }

    fn finish_failure(&mut self, failure: CallFailure) -> TypedPoll {
        let _ = self.cancel_live_host_operation();
        self.component.poisoned = true;
        self.component.modules.discard_all_calls();
        let _ = self.close_resources(false);
        self.stage = TypedStage::Complete;
        match failure {
            CallFailure::Host(error) => TypedPoll::HostFailed(error),
            CallFailure::Trap(trap) => TypedPoll::Trapped(trap),
        }
    }

    fn close_resources(&mut self, commit: bool) -> Result<(), ()> {
        let Some(mut scope) = self.guest_resources.take() else {
            return Ok(());
        };
        if commit && self.resources.commit_guest_call(&mut scope).is_err() {
            let _ = self.resources.close_guest_call(scope);
            return Err(());
        }
        self.resources.close_guest_call(scope).map_err(|_| ())
    }
}

impl<A> Drop for TypedCall<'_, A> {
    fn drop(&mut self) {
        if self.guest_started && !matches!(self.stage, TypedStage::Complete) {
            self.component.poisoned = true;
        }
        let _ = self.cancel_live_host_operation();
        self.component.modules.discard_all_calls();
        let _ = self.close_resources(false);
    }
}

#[derive(Clone, Copy)]
enum Subcall {
    Realloc,
    Transform,
    PostReturn,
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AllocationRequest {
    size: u32,
    alignment: u32,
}

#[derive(Default)]
struct AllocationPlanner {
    requests: Vec<AllocationRequest>,
    next: u32,
}

impl PayloadAllocator<PlanningMemory> for AllocationPlanner {
    fn allocate(
        &mut self,
        _memory: &mut PlanningMemory,
        size: u32,
        alignment: u32,
    ) -> Result<u32, CodecError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(CodecError::Misaligned);
        }
        if self.requests.len() >= PROFILE_1_LIMITS.max_abi_allocations as usize {
            return Err(CodecError::AllocationLimit);
        }
        let mask = alignment - 1;
        let pointer = self
            .next
            .max(1)
            .checked_add(mask)
            .ok_or(CodecError::Overflow)?
            & !mask;
        self.next = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
        self.requests
            .try_reserve(1)
            .map_err(|_| CodecError::Allocation)?;
        self.requests.push(AllocationRequest { size, alignment });
        Ok(pointer)
    }
}

struct PlanningMemory;

impl GuestMemory for PlanningMemory {
    fn len(&self) -> u64 {
        u64::from(u32::MAX) + 1
    }

    fn read_exact(&self, _pointer: u32, destination: &mut [u8]) -> Result<(), AbiError> {
        destination.fill(0);
        Ok(())
    }

    fn write_exact(&mut self, _pointer: u32, _source: &[u8]) -> Result<(), AbiError> {
        Ok(())
    }
}

struct NoGuestMemory;

impl GuestMemory for NoGuestMemory {
    fn len(&self) -> u64 {
        0
    }

    fn read_exact(&self, _pointer: u32, _destination: &mut [u8]) -> Result<(), AbiError> {
        Err(AbiError::OutOfBounds)
    }

    fn write_exact(&mut self, _pointer: u32, _source: &[u8]) -> Result<(), AbiError> {
        Err(AbiError::OutOfBounds)
    }
}

struct ReplayAllocator<'a> {
    pointers: &'a [u32],
    requests: &'a [AllocationRequest],
    cursor: usize,
}

impl<M: GuestMemory> PayloadAllocator<M> for ReplayAllocator<'_> {
    fn allocate(&mut self, _memory: &mut M, size: u32, alignment: u32) -> Result<u32, CodecError> {
        let request = self
            .requests
            .get(self.cursor)
            .ok_or(CodecError::AllocationLimit)?;
        if request.size != size || request.alignment != alignment {
            return Err(CodecError::TypeMismatch);
        }
        let pointer = *self
            .pointers
            .get(self.cursor)
            .ok_or(CodecError::AllocationLimit)?;
        self.cursor += 1;
        Ok(pointer)
    }
}

/// Copy-only view of one exact Core memory named by canonical options.
struct CoreGuestMemory<'a> {
    group: &'a mut CoreComponentGroup,
    instance: usize,
    export: &'a str,
    length: usize,
}

impl<'a> CoreGuestMemory<'a> {
    fn new(
        group: &'a mut CoreComponentGroup,
        instance: usize,
        export: &'a str,
    ) -> Result<Self, SyncError> {
        let length = group
            .memory_size(instance, export)
            .map_err(|_| SyncError::Memory)?;
        Ok(Self {
            group,
            instance,
            export,
            length,
        })
    }
}

impl GuestMemory for CoreGuestMemory<'_> {
    fn len(&self) -> u64 {
        self.length as u64
    }

    fn read_exact(&self, pointer: u32, destination: &mut [u8]) -> Result<(), AbiError> {
        self.group
            .read_memory(self.instance, self.export, pointer as usize, destination)
            .map_err(|_| AbiError::OutOfBounds)
    }

    fn write_exact(&mut self, pointer: u32, source: &[u8]) -> Result<(), AbiError> {
        self.group
            .write_memory(self.instance, self.export, pointer as usize, source)
            .map_err(|_| AbiError::OutOfBounds)
    }
}

struct TableBinder<'a, A> {
    table: &'a ResourceTable<A>,
}

struct HostParameterBinder<'a, A> {
    table: &'a ResourceTable<A>,
    scope: &'a GuestCallResources,
}

impl<A> ResourceBinder for HostParameterBinder<'_, A> {
    fn bind(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
        ownership: ResourceOwnership,
        position: ValuePosition,
    ) -> Result<ResourceToken, CodecError> {
        if position != ValuePosition::Parameter {
            return Err(CodecError::ResourceBinding);
        }
        match ownership {
            ResourceOwnership::Borrow => self
                .table
                .with_guest_borrow(self.scope, guest_index, expected, |_| ())
                .map_err(|_| CodecError::ResourceBinding)?,
            ResourceOwnership::Own => self
                .table
                .contains_guest_owned_index(guest_index, expected)
                .map(|_| ())
                .map_err(|_| CodecError::ResourceBinding)?,
        }
        Ok(self.table.token_from_guest_index(guest_index))
    }
}

impl<A> ResourceBinder for TableBinder<'_, A> {
    fn bind(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
        ownership: ResourceOwnership,
        position: ValuePosition,
    ) -> Result<ResourceToken, CodecError> {
        if ownership == ResourceOwnership::Borrow && position == ValuePosition::Result {
            return Err(CodecError::BorrowEscape);
        }
        let token = self.table.token_from_guest_index(guest_index);
        match (ownership, position) {
            (ResourceOwnership::Own, ValuePosition::Result) => self
                .table
                .contains_guest_owned_index(guest_index, expected)
                .map_err(|_| CodecError::ResourceBinding)?,
            _ => self
                .table
                .contains(token, expected)
                .map_err(|_| CodecError::ResourceBinding)?,
        };
        Ok(token)
    }
}

fn clone_parameter_types(function: &FunctionType) -> Result<Vec<ValueType>, SyncError> {
    let cloned =
        crate::types::try_clone_function_type(function).map_err(|_| SyncError::Allocation)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(cloned.parameters.len())
        .map_err(|_| SyncError::Allocation)?;
    for parameter in cloned.parameters {
        result.push(parameter.value);
    }
    Ok(result)
}

fn lowered_parts(lowered: LoweredParameters) -> Result<(Vec<CoreValue>, CodecUsage), SyncError> {
    match lowered {
        LoweredParameters::Flat { values, usage } => Ok((values, usage)),
        LoweredParameters::Indirect {
            arguments, usage, ..
        } => {
            let mut values = Vec::new();
            values
                .try_reserve_exact(arguments.len())
                .map_err(|_| SyncError::Allocation)?;
            values.extend_from_slice(&arguments);
            Ok((values, usage))
        }
    }
}

fn lower_argument_resources<A>(
    types: &[ValueType],
    values: &mut [CanonicalValue],
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    if types.len() != values.len() {
        return Err(());
    }
    for (ty, value) in types.iter().zip(values) {
        rewrite_lowered_resources(ty, value, table, scope)?;
    }
    Ok(())
}

fn lift_host_argument_resources<A>(
    types: &[ValueType],
    values: &mut [CanonicalValue],
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    if types.len() != values.len() {
        return Err(());
    }
    for (ty, value) in types.iter().zip(values) {
        rewrite_host_argument_resources(ty, value, table, scope)?;
    }
    Ok(())
}

fn rewrite_host_argument_resources<A>(
    ty: &ValueType,
    value: &mut CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership: ResourceOwnership::Own,
            },
            CanonicalValue::Resource(token),
        ) => {
            *token = table
                .lift_owned_from_guest(scope, token.guest_index(), *resource_type)
                .map_err(|_| ())?;
            Ok(())
        }
        (
            ValueType::Resource {
                ownership: ResourceOwnership::Borrow,
                ..
            },
            CanonicalValue::Resource(_),
        ) => Ok(()),
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                rewrite_host_argument_resources(item, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            lift_host_argument_resources(types, values, table, scope)
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            rewrite_host_argument_resources(inner, value, table, scope)
        }
        (ValueType::Option(_), CanonicalValue::Option(None)) => Ok(()),
        (ValueType::Result { ok, .. }, CanonicalValue::Result(Ok(value))) => {
            rewrite_optional_host_argument(ok.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Result { error, .. }, CanonicalValue::Result(Err(value))) => {
            rewrite_optional_host_argument(error.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let ty = cases.get(*case as usize).ok_or(())?.as_ref();
            rewrite_optional_host_argument(ty, payload.as_deref_mut(), table, scope)
        }
        _ => Ok(()),
    }
}

fn rewrite_optional_host_argument<A>(
    ty: Option<&ValueType>,
    value: Option<&mut CanonicalValue>,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => rewrite_host_argument_resources(ty, value, table, scope),
        _ => Err(()),
    }
}

fn rewrite_lowered_resources<A>(
    ty: &ValueType,
    value: &mut CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership,
            },
            CanonicalValue::Resource(token),
        ) => {
            *token = match ownership {
                ResourceOwnership::Borrow => {
                    table.lower_borrow_for_guest(scope, *token, *resource_type)
                }
                ResourceOwnership::Own => {
                    table.lower_owned_for_guest(scope, *token, *resource_type)
                }
            }
            .map_err(|_| ())?;
            Ok(())
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                rewrite_lowered_resources(item, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            lower_argument_resources(types, values, table, scope)
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            rewrite_lowered_resources(inner, value, table, scope)
        }
        (ValueType::Option(_), CanonicalValue::Option(None)) => Ok(()),
        (ValueType::Result { ok, .. }, CanonicalValue::Result(Ok(value))) => {
            rewrite_optional_lowered(ok.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Result { error, .. }, CanonicalValue::Result(Err(value))) => {
            rewrite_optional_lowered(error.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let ty = cases.get(*case as usize).ok_or(())?.as_ref();
            rewrite_optional_lowered(ty, payload.as_deref_mut(), table, scope)
        }
        _ => Ok(()),
    }
}

fn rewrite_optional_lowered<A>(
    ty: Option<&ValueType>,
    value: Option<&mut CanonicalValue>,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => rewrite_lowered_resources(ty, value, table, scope),
        _ => Err(()),
    }
}

fn lift_result_resources<A>(
    ty: &ValueType,
    mut value: CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<CanonicalValue, ()> {
    rewrite_lifted_resources(ty, &mut value, table, scope)?;
    Ok(value)
}

fn rewrite_lifted_resources<A>(
    ty: &ValueType,
    value: &mut CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership: ResourceOwnership::Own,
            },
            CanonicalValue::Resource(token),
        ) => {
            *token = table
                .lift_owned_from_guest(scope, token.guest_index(), *resource_type)
                .map_err(|_| ())?;
            Ok(())
        }
        (
            ValueType::Resource {
                ownership: ResourceOwnership::Borrow,
                ..
            },
            CanonicalValue::Resource(_),
        ) => Err(()),
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                rewrite_lifted_resources(item, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            if types.len() != values.len() {
                return Err(());
            }
            for (ty, value) in types.iter().zip(values) {
                rewrite_lifted_resources(ty, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            rewrite_lifted_resources(inner, value, table, scope)
        }
        (ValueType::Option(_), CanonicalValue::Option(None)) => Ok(()),
        (ValueType::Result { ok, .. }, CanonicalValue::Result(Ok(value))) => {
            rewrite_optional_lifted(ok.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Result { error, .. }, CanonicalValue::Result(Err(value))) => {
            rewrite_optional_lifted(error.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let ty = cases.get(*case as usize).ok_or(())?.as_ref();
            rewrite_optional_lifted(ty, payload.as_deref_mut(), table, scope)
        }
        _ => Ok(()),
    }
}

fn rewrite_optional_lifted<A>(
    ty: Option<&ValueType>,
    value: Option<&mut CanonicalValue>,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => rewrite_lifted_resources(ty, value, table, scope),
        _ => Err(()),
    }
}
