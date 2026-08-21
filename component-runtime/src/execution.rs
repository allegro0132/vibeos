//! Inert, validator-derived wiring for synchronous and native async executors.

use crate::{types::FunctionType, value::ValueType};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalStringEncoding {
    Utf8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExecutableExportInfo {
    pub name: String,
    pub function: FunctionType,
    pub core_instance: usize,
    pub core_function: String,
    /// The explicitly encoded canonical option. `None` uses the Component
    /// Model's UTF-8 default.
    pub string_encoding: Option<CanonicalStringEncoding>,
    pub memory: Option<String>,
    pub realloc: Option<String>,
    pub post_return: Option<String>,
}

/// One exact Core export named by a Canonical ABI option on a lowered host
/// import. The instance index is the runtime instance index, not the
/// attacker-controlled Component binary index.
#[derive(Debug, PartialEq, Eq)]
pub struct HostCoreExportInfo {
    pub core_instance: usize,
    pub export: String,
}

/// Validator-derived wiring for one Component import that is callable from an
/// embedded Core module. This is inert metadata: live host authority is bound
/// only when an instance is admitted in C3.
#[derive(Debug, PartialEq, Eq)]
pub struct HostImportInfo {
    /// Exact Component import name. For an interface import this is the
    /// versioned interface name, for example `vibe:clock/monotonic@1.0.0`.
    pub interface: String,
    /// Exact imported function member. Direct function imports use their own
    /// import name for both `interface` and `function`.
    pub function: String,
    pub function_type: FunctionType,
    /// Runtime Core instance which calls this host function.
    pub core_instance: usize,
    /// Exact Core module and field names consumed by the embedded module.
    pub core_module: String,
    pub core_field: String,
    /// The explicitly encoded canonical option. `None` is UTF-8.
    pub string_encoding: Option<CanonicalStringEncoding>,
    pub memory: Option<HostCoreExportInfo>,
    pub realloc: Option<HostCoreExportInfo>,
}

/// A validated Core export referenced by an async Canonical ABI plan.
///
/// Async plans are inspection-only today. This identity is retained so a
/// future executor does not need to reinterpret attacker-controlled indices.
#[derive(Debug, PartialEq, Eq)]
pub struct AsyncCoreExportRef {
    pub core_instance: u32,
    pub export: String,
}

/// The validated source of a Core function used by an async canonical entry.
#[derive(Debug, PartialEq, Eq)]
pub enum AsyncCoreFunctionSource {
    Export(AsyncCoreExportRef),
    Lower {
        canonical_index: u32,
        component_function: u32,
    },
    SyncCanonical {
        canonical_index: u32,
    },
    AsyncCanonical {
        canonical_index: u32,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct AsyncCoreFunctionRef {
    pub core_function: u32,
    pub source: AsyncCoreFunctionSource,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AsyncCoreMemoryRef {
    pub core_memory: u32,
    pub source: AsyncCoreExportRef,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncComponentFunctionSource {
    Import {
        interface: Option<String>,
        function: String,
    },
    Lift {
        canonical_index: u32,
        core_function: u32,
    },
    AsyncLift {
        canonical_index: u32,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct AsyncComponentFunctionRef {
    pub component_function: u32,
    pub source: AsyncComponentFunctionSource,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AsyncCanonicalOptionsPlan {
    /// `None` is the Canonical ABI UTF-8 default.
    pub string_encoding: Option<CanonicalStringEncoding>,
    pub async_: bool,
    pub memory: Option<AsyncCoreMemoryRef>,
    pub realloc: Option<AsyncCoreFunctionRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AsyncComponentValueTypeRef {
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    Char,
    String,
    Defined(u32),
}

/// One validated, typed, but not yet executable async Canonical ABI entry.
#[derive(Debug, PartialEq, Eq)]
pub struct AsyncCanonicalPlan {
    pub canonical_index: u32,
    pub function: AsyncCanonicalFunctionPlan,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncCanonicalFunctionPlan {
    Lift {
        core_function: AsyncCoreFunctionRef,
        function_type: FunctionType,
        callback: AsyncCoreFunctionRef,
        options: AsyncCanonicalOptionsPlan,
    },
    Lower {
        component_function: AsyncComponentFunctionRef,
        function_type: FunctionType,
        options: AsyncCanonicalOptionsPlan,
    },
    TaskReturn {
        result: Option<ValueType>,
        options: AsyncCanonicalOptionsPlan,
    },
    TaskCancel,
    ContextGet {
        value_type: AsyncCoreValueType,
        slot: u32,
    },
    ContextSet {
        value_type: AsyncCoreValueType,
        slot: u32,
    },
    SubtaskDrop,
    SubtaskCancel {
        async_: bool,
    },
    ThreadYield {
        cancellable: bool,
    },
    Stream(AsyncStreamPlan),
    Future(AsyncFuturePlan),
    Waitable(AsyncWaitablePlan),
    BackpressureInc,
    BackpressureDec,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncStreamPlan {
    New {
        type_index: u32,
        value_type: ValueType,
    },
    Read {
        type_index: u32,
        value_type: ValueType,
        options: AsyncCanonicalOptionsPlan,
    },
    Write {
        type_index: u32,
        value_type: ValueType,
        options: AsyncCanonicalOptionsPlan,
    },
    CancelRead {
        type_index: u32,
        value_type: ValueType,
        async_: bool,
    },
    CancelWrite {
        type_index: u32,
        value_type: ValueType,
        async_: bool,
    },
    DropReadable {
        type_index: u32,
        value_type: ValueType,
    },
    DropWritable {
        type_index: u32,
        value_type: ValueType,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncFuturePlan {
    New {
        type_index: u32,
        value_type: ValueType,
    },
    Read {
        type_index: u32,
        value_type: ValueType,
        options: AsyncCanonicalOptionsPlan,
    },
    Write {
        type_index: u32,
        value_type: ValueType,
        options: AsyncCanonicalOptionsPlan,
    },
    CancelRead {
        type_index: u32,
        value_type: ValueType,
        async_: bool,
    },
    CancelWrite {
        type_index: u32,
        value_type: ValueType,
        async_: bool,
    },
    DropReadable {
        type_index: u32,
        value_type: ValueType,
    },
    DropWritable {
        type_index: u32,
        value_type: ValueType,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncWaitablePlan {
    SetNew,
    SetWait {
        cancellable: bool,
        memory: AsyncCoreMemoryRef,
    },
    SetPoll {
        cancellable: bool,
        memory: AsyncCoreMemoryRef,
    },
    SetDrop,
    Join,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncCoreValueType {
    I32,
    I64,
}

/// One Core export after Component-instance indices have been translated to
/// the exact runtime-instance namespace used by the native async executor.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCoreExportRef {
    pub core_instance: usize,
    pub export: String,
}

/// Canonical options with all Core memory/function provenance resolved.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCanonicalOptionsPlan {
    /// `None` is the Canonical ABI UTF-8 default.
    pub string_encoding: Option<CanonicalStringEncoding>,
    pub async_: bool,
    pub memory: Option<NativeAsyncCoreExportRef>,
    pub realloc: Option<NativeAsyncCoreExportRef>,
}

/// The closed set of canonical entries retained by the resource-free native
/// async profile. Every canonical function in the validated Component has one
/// entry in this table; Core import bridges and Component exports refer to the
/// table by checked indices rather than reinterpreting binary indices later.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCanonicalPlan {
    pub canonical_index: u32,
    pub function: NativeAsyncCanonicalFunctionPlan,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeAsyncCanonicalFunctionPlan {
    Lift {
        core_function: NativeAsyncCoreExportRef,
        function_type: FunctionType,
        callback: NativeAsyncCoreExportRef,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    TaskReturn {
        result: Option<ValueType>,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    TaskCancel,
    Stream(NativeAsyncStreamPlan),
    Future(NativeAsyncFuturePlan),
    Waitable(NativeAsyncWaitablePlan),
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeAsyncStreamPlan {
    New {
        type_index: u32,
        value_type: ValueType,
    },
    Read {
        type_index: u32,
        value_type: ValueType,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    Write {
        type_index: u32,
        value_type: ValueType,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    CancelRead {
        type_index: u32,
        value_type: ValueType,
    },
    CancelWrite {
        type_index: u32,
        value_type: ValueType,
    },
    DropReadable {
        type_index: u32,
        value_type: ValueType,
    },
    DropWritable {
        type_index: u32,
        value_type: ValueType,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeAsyncFuturePlan {
    New {
        type_index: u32,
        value_type: ValueType,
    },
    Read {
        type_index: u32,
        value_type: ValueType,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    Write {
        type_index: u32,
        value_type: ValueType,
        options: NativeAsyncCanonicalOptionsPlan,
    },
    CancelRead {
        type_index: u32,
        value_type: ValueType,
    },
    CancelWrite {
        type_index: u32,
        value_type: ValueType,
    },
    DropReadable {
        type_index: u32,
        value_type: ValueType,
    },
    DropWritable {
        type_index: u32,
        value_type: ValueType,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum NativeAsyncWaitablePlan {
    SetNew,
    SetDrop,
    Join,
}

/// Exact import wiring for one instantiated Core module. A canonical bridge
/// is an index into [`NativeAsyncExecutionPlan::canonical_import_bridges`].
#[derive(Debug, PartialEq, Eq)]
pub enum NativeAsyncCoreImportPlan {
    InstanceExport {
        module: String,
        field: String,
        core_instance: usize,
        export: String,
    },
    Canonical {
        bridge: u32,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCoreInstancePlan {
    pub module: usize,
    pub imports: Vec<NativeAsyncCoreImportPlan>,
}

/// One exact Core import supplied by a canonical builtin. `canonical` indexes
/// the total canonical table and is validated to name a non-lift entry.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCanonicalImportBridge {
    pub core_instance: usize,
    pub core_module: String,
    pub core_field: String,
    pub canonical: u32,
    pub signature: NativeAsyncCoreSignature,
}

/// Exact validator-derived Core function signature for a canonical import.
/// The resource-free profile admits only the integer Core value classes.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncCoreSignature {
    pub parameters: Vec<AsyncCoreValueType>,
    pub results: Vec<AsyncCoreValueType>,
}

/// One exported async Component function. `canonical` indexes the total
/// canonical table and is validated to name an async callback lift.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncExportPlan {
    pub name: String,
    pub canonical: u32,
}

/// Owned, validator-derived wiring for the resource-free native async
/// executor. This plan deliberately remains inert while its profile stage is
/// `ValidationOnly`; constructing it does not authorize execution.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeAsyncExecutionPlan {
    pub(crate) instances: Vec<NativeAsyncCoreInstancePlan>,
    pub(crate) canonical: Vec<NativeAsyncCanonicalPlan>,
    pub(crate) canonical_import_bridges: Vec<NativeAsyncCanonicalImportBridge>,
    pub(crate) exports: Vec<NativeAsyncExportPlan>,
}

impl NativeAsyncExecutionPlan {
    pub fn instances(&self) -> &[NativeAsyncCoreInstancePlan] {
        &self.instances
    }

    pub fn canonical_plans(&self) -> &[NativeAsyncCanonicalPlan] {
        &self.canonical
    }

    pub fn canonical_import_bridges(&self) -> &[NativeAsyncCanonicalImportBridge] {
        &self.canonical_import_bridges
    }

    pub fn exports(&self) -> &[NativeAsyncExportPlan] {
        &self.exports
    }
}

pub(crate) struct ComponentExecutionPlan {
    pub(crate) instances: Vec<CoreInstancePlan>,
    pub(crate) exports: Vec<ExecutableExportPlan>,
    pub(crate) host_imports: Vec<HostImportPlan>,
}

impl ComponentExecutionPlan {
    pub(crate) fn instances(&self) -> &[CoreInstancePlan] {
        &self.instances
    }

    pub(crate) fn exports(&self) -> &[ExecutableExportPlan] {
        &self.exports
    }

    pub(crate) fn host_imports(&self) -> &[HostImportPlan] {
        &self.host_imports
    }
}

pub(crate) struct CoreInstancePlan {
    pub(crate) module: usize,
    pub(crate) imports: Vec<CoreImportPlan>,
}

impl CoreInstancePlan {
    pub(crate) const fn module(&self) -> usize {
        self.module
    }

    pub(crate) fn imports(&self) -> &[CoreImportPlan] {
        &self.imports
    }
}

pub(crate) enum CoreImportPlan {
    Host {
        module: String,
        field: String,
        host_import: usize,
    },
    InstanceExport {
        module: String,
        field: String,
        core_instance: usize,
        export: String,
    },
}

pub(crate) struct HostImportPlan {
    pub(crate) info: HostImportInfo,
}

pub(crate) struct ExecutableExportPlan {
    pub(crate) info: ExecutableExportInfo,
    pub(crate) core_instance: usize,
    pub(crate) function: String,
    pub(crate) memory: Option<String>,
    pub(crate) realloc: Option<String>,
    pub(crate) post_return: Option<String>,
}

#[derive(Clone)]
pub(crate) struct CoreExportRef {
    pub(crate) instance: usize,
    pub(crate) name: String,
}

#[derive(Clone, Copy)]
pub(crate) struct LiftDraft {
    pub(crate) canonical_index: u32,
    pub(crate) core_function: u32,
    pub(crate) string_encoding: Option<CanonicalStringEncoding>,
    pub(crate) memory: Option<u32>,
    pub(crate) realloc: Option<u32>,
    pub(crate) post_return: Option<u32>,
}

pub(crate) struct LiftOptionsDraft {
    pub(crate) string_encoding: Option<CanonicalStringEncoding>,
    pub(crate) memory: Option<u32>,
    pub(crate) realloc: Option<u32>,
    pub(crate) post_return: Option<u32>,
}

#[derive(Clone)]
pub(crate) struct ImportedFunctionDraft {
    /// `Some` for an instance import member and `None` for a direct function
    /// import. The public plan deliberately spells direct imports as
    /// `interface == function` while retaining the distinction needed to look
    /// up the validated Component type.
    pub(crate) interface: Option<String>,
    pub(crate) function: String,
}

#[derive(Clone)]
pub(crate) enum ComponentFunctionDraft {
    Lift(LiftDraft),
    AsyncLift { canonical_index: u32 },
    Import(ImportedFunctionDraft),
}

pub(crate) enum ComponentInstanceDraft {
    Import { name: String },
    FromExports(Vec<(String, u32)>),
}

pub(crate) enum CoreFunctionDraft {
    Export(CoreExportRef),
    Lower(LowerDraft),
    SyncCanonical { canonical_index: u32 },
    AsyncCanonical { canonical_index: u32 },
}

#[derive(Clone, Copy)]
pub(crate) struct LowerDraft {
    pub(crate) canonical_index: u32,
    pub(crate) component_function: u32,
    pub(crate) string_encoding: Option<CanonicalStringEncoding>,
    pub(crate) memory: Option<u32>,
    pub(crate) realloc: Option<u32>,
    pub(crate) post_return: Option<u32>,
}

#[derive(Clone, Copy)]
pub(crate) struct AsyncOptionsDraft {
    pub(crate) string_encoding: Option<CanonicalStringEncoding>,
    pub(crate) async_: bool,
    pub(crate) memory: Option<u32>,
    pub(crate) realloc: Option<u32>,
}

pub(crate) struct AsyncCanonicalDraft {
    pub(crate) canonical_index: u32,
    pub(crate) function: AsyncCanonicalFunctionDraft,
}

pub(crate) enum AsyncCanonicalFunctionDraft {
    Lift {
        core_function: u32,
        function_type: u32,
        callback: u32,
        options: AsyncOptionsDraft,
    },
    Lower {
        component_function: u32,
        options: AsyncOptionsDraft,
    },
    TaskReturn {
        result: Option<AsyncComponentValueTypeRef>,
        options: AsyncOptionsDraft,
    },
    TaskCancel,
    ContextGet {
        value_type: AsyncCoreValueType,
        slot: u32,
    },
    ContextSet {
        value_type: AsyncCoreValueType,
        slot: u32,
    },
    SubtaskDrop,
    SubtaskCancel {
        async_: bool,
    },
    ThreadYield {
        cancellable: bool,
    },
    Stream(AsyncStreamDraft),
    Future(AsyncFutureDraft),
    Waitable(AsyncWaitableDraft),
    BackpressureInc,
    BackpressureDec,
}

pub(crate) enum AsyncStreamDraft {
    New {
        type_index: u32,
    },
    Read {
        type_index: u32,
        options: AsyncOptionsDraft,
    },
    Write {
        type_index: u32,
        options: AsyncOptionsDraft,
    },
    CancelRead {
        type_index: u32,
        async_: bool,
    },
    CancelWrite {
        type_index: u32,
        async_: bool,
    },
    DropReadable {
        type_index: u32,
    },
    DropWritable {
        type_index: u32,
    },
}

pub(crate) enum AsyncFutureDraft {
    New {
        type_index: u32,
    },
    Read {
        type_index: u32,
        options: AsyncOptionsDraft,
    },
    Write {
        type_index: u32,
        options: AsyncOptionsDraft,
    },
    CancelRead {
        type_index: u32,
        async_: bool,
    },
    CancelWrite {
        type_index: u32,
        async_: bool,
    },
    DropReadable {
        type_index: u32,
    },
    DropWritable {
        type_index: u32,
    },
}

pub(crate) enum AsyncWaitableDraft {
    SetNew,
    SetWait { cancellable: bool, memory: u32 },
    SetPoll { cancellable: bool, memory: u32 },
    SetDrop,
    Join,
}

pub(crate) struct CoreInstantiationArgDraft {
    pub(crate) name: String,
    pub(crate) instance: usize,
}

pub(crate) enum CoreInstanceDraft {
    Instantiate {
        module: usize,
        arguments: Vec<CoreInstantiationArgDraft>,
    },
    FromExports(Vec<CoreInstanceExportDraft>),
}

pub(crate) struct CoreInstanceExportDraft {
    pub(crate) name: String,
    pub(crate) item: CoreInstanceExportItemDraft,
}

pub(crate) enum CoreInstanceExportItemDraft {
    Function(u32),
    Memory(u32),
}
