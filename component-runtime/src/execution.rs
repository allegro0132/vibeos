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

pub(crate) struct ComponentExecutionPlan {
    pub(crate) instances: Vec<CoreInstancePlan>,
    pub(crate) exports: Vec<ExecutableExportPlan>,
}

impl ComponentExecutionPlan {
    pub(crate) fn instances(&self) -> &[CoreInstancePlan] {
        &self.instances
    }

    pub(crate) fn exports(&self) -> &[ExecutableExportPlan] {
        &self.exports
    }
}

pub(crate) struct CoreInstancePlan {
    pub(crate) module: usize,
}

impl CoreInstancePlan {
    pub(crate) const fn module(&self) -> usize {
        self.module
    }
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
