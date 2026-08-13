//! Inert, validator-derived wiring for the synchronous Profile-1 executor.

use crate::types::FunctionType;
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
    Import(ImportedFunctionDraft),
}

pub(crate) enum ComponentInstanceDraft {
    Import { name: String },
    FromExports(Vec<(String, u32)>),
}

pub(crate) enum CoreFunctionDraft {
    Export(CoreExportRef),
    Lower(LowerDraft),
}

#[derive(Clone, Copy)]
pub(crate) struct LowerDraft {
    pub(crate) component_function: u32,
    pub(crate) string_encoding: Option<CanonicalStringEncoding>,
    pub(crate) memory: Option<u32>,
    pub(crate) realloc: Option<u32>,
    pub(crate) post_return: Option<u32>,
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
