//! Versioned, inert contracts for Vibe Component Profile 1.
//!
//! This crate deliberately contains no engine, host service, capability, or
//! filesystem integration.  It is usable by admission tooling and the kernel's
//! `no_std + alloc` build without making component bytes executable.

#![no_std]

/// Canonical eight-byte prefix for a durable component artifact envelope.
pub const ARTIFACT_MAGIC: [u8; 8] = *b"VIBECMP\0";
pub const ARTIFACT_ABI_VERSION: u16 = 1;
pub const COMPONENT_PROFILE_VERSION: u16 = 1;
pub const CORE_PROFILE_VERSION: u16 = 1;
pub const RUNTIME_ABI_VERSION: u16 = 1;

/// Exact tooling/specification identities admitted by Profile 1.
///
/// These values are part of artifact identity.  Changing one requires a new
/// profile or ABI version; a semver-compatible dependency update is not an
/// implicit compatibility promise.
pub const CORE_SPEC_REVISION: &str = "webassembly-core-2.0-integer-v1";
pub const COMPONENT_MODEL_REVISION: &str = "wasmparser-component-model-0.255.0";
pub const CANONICAL_ABI_REVISION: &str = "component-model-0.255.0-sync";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitPackage {
    pub name: &'static str,
    pub version: &'static str,
}

pub const WIT_PACKAGES: [WitPackage; 5] = [
    WitPackage {
        name: "vibe:stream",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:clock",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:random",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:blob",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:log",
        version: "1.0.0",
    },
];

/// Proposals and baseline value classes reviewed for the private Core profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreFeature {
    IntegerArithmetic,
    StructuredControl,
    Functions,
    Locals,
    Globals,
    LinearMemory,
    Tables,
    ImportsExports,
    Start,
    DataElements,
    Float,
    Simd,
    RelaxedSimd,
    ReferenceTypes,
    FunctionReferences,
    BulkMemory,
    MultiValue,
    TailCall,
    Threads,
    MultiMemory,
    Memory64,
    ExtendedConst,
    Exceptions,
    StackSwitching,
    GarbageCollection,
    CustomPageSizes,
    WideArithmetic,
}

impl CoreFeature {
    pub const fn enabled(self) -> bool {
        matches!(
            self,
            Self::IntegerArithmetic
                | Self::StructuredControl
                | Self::Functions
                | Self::Locals
                | Self::Globals
                | Self::LinearMemory
                | Self::Tables
                | Self::ImportsExports
                | Self::DataElements
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileLimits {
    pub max_artifact_bytes: usize,
    pub max_component_bytes: usize,
    pub max_core_module_bytes: usize,
    pub max_component_nesting: u32,
    pub max_core_nesting: u32,
    pub max_types: u32,
    pub max_functions: u32,
    pub max_params_per_function: u32,
    pub max_results_per_function: u32,
    pub max_imports: u32,
    pub max_exports: u32,
    pub max_globals: u32,
    pub max_locals_per_function: u32,
    pub max_memories: u32,
    pub max_initial_memory_pages: u32,
    pub max_memory_pages: u32,
    pub max_tables: u32,
    pub max_table_elements: u32,
    pub max_data_segments: u32,
    pub max_element_segments: u32,
    pub max_custom_sections: u32,
    pub max_custom_section_bytes: usize,
    pub max_embedded_modules: u32,
    pub max_component_instances: u32,
    pub max_aliases: u32,
    pub max_canonical_functions: u32,
    pub max_adapters: u32,
    pub max_resources: u32,
    pub max_call_depth: u32,
    pub max_canonical_value_bytes: usize,
    pub max_string_bytes: usize,
    pub max_list_elements: u32,
    pub total_fuel: u64,
    pub poll_quantum: u64,
}

pub const PROFILE_1_LIMITS: ProfileLimits = ProfileLimits {
    max_artifact_bytes: 1024 * 1024,
    max_component_bytes: 1024 * 1024,
    max_core_module_bytes: 512 * 1024,
    max_component_nesting: 16,
    max_core_nesting: 128,
    max_types: 1024,
    max_functions: 1024,
    max_params_per_function: 32,
    max_results_per_function: 32,
    max_imports: 256,
    max_exports: 256,
    max_globals: 256,
    max_locals_per_function: 4096,
    max_memories: 1,
    max_initial_memory_pages: 16,
    max_memory_pages: 256,
    max_tables: 1,
    max_table_elements: 4096,
    max_data_segments: 256,
    max_element_segments: 256,
    max_custom_sections: 256,
    max_custom_section_bytes: 64 * 1024,
    max_embedded_modules: 8,
    max_component_instances: 16,
    max_aliases: 256,
    max_canonical_functions: 256,
    max_adapters: 16,
    max_resources: 256,
    max_call_depth: 128,
    max_canonical_value_bytes: 64 * 1024,
    max_string_bytes: 64 * 1024,
    max_list_elements: 4096,
    total_fuel: 10_000_000,
    poll_quantum: 10_000,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TrapCode {
    Validation = 0x0100,
    UnsupportedFeature = 0x0101,
    LimitExceeded = 0x0102,
    Unreachable = 0x0200,
    IntegerDivisionByZero = 0x0201,
    IntegerOverflow = 0x0202,
    MemoryOutOfBounds = 0x0203,
    TableOutOfBounds = 0x0204,
    IndirectCallTypeMismatch = 0x0205,
    CallDepthExceeded = 0x0206,
    FuelExhausted = 0x0300,
    Cancelled = 0x0301,
    CanonicalAbi = 0x0400,
    ResourceMisuse = 0x0401,
}

impl TrapCode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::UnsupportedFeature => "unsupported-feature",
            Self::LimitExceeded => "limit-exceeded",
            Self::Unreachable => "unreachable",
            Self::IntegerDivisionByZero => "integer-division-by-zero",
            Self::IntegerOverflow => "integer-overflow",
            Self::MemoryOutOfBounds => "memory-out-of-bounds",
            Self::TableOutOfBounds => "table-out-of-bounds",
            Self::IndirectCallTypeMismatch => "indirect-call-type-mismatch",
            Self::CallDepthExceeded => "call-depth-exceeded",
            Self::FuelExhausted => "fuel-exhausted",
            Self::Cancelled => "cancelled",
            Self::CanonicalAbi => "canonical-abi",
            Self::ResourceMisuse => "resource-misuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    ArtifactBytes,
    ComponentBytes,
    CoreModuleBytes,
    Types,
    Functions,
    Parameters,
    Results,
    Imports,
    Exports,
    Globals,
    Locals,
    Memories,
    InitialMemoryPages,
    MemoryPages,
    Tables,
    TableElements,
    DataSegments,
    ElementSegments,
    CustomSections,
    CustomSectionBytes,
    EmbeddedModules,
    ComponentInstances,
    Aliases,
    CanonicalFunctions,
    Adapters,
    Resources,
    CanonicalValueBytes,
    StringBytes,
    ListElements,
    CoreNesting,
    EngineAllocationBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitError {
    pub kind: LimitKind,
    pub attempted: u64,
    pub maximum: u64,
}

/// Allocation-independent counters used while streaming an untrusted binary.
///
/// Callers charge a declared length or count before reserving storage for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationAccount {
    pub artifact_bytes: u64,
    pub component_bytes: u64,
    pub embedded_module_bytes: u64,
    pub types: u64,
    pub functions: u64,
    pub imports: u64,
    pub exports: u64,
    pub resources: u64,
}

impl ValidationAccount {
    fn charge(
        value: &mut u64,
        amount: u64,
        maximum: u64,
        kind: LimitKind,
    ) -> Result<(), LimitError> {
        let attempted = value.checked_add(amount).ok_or(LimitError {
            kind,
            attempted: u64::MAX,
            maximum,
        })?;
        if attempted > maximum {
            return Err(LimitError {
                kind,
                attempted,
                maximum,
            });
        }
        *value = attempted;
        Ok(())
    }

    pub fn charge_artifact_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        Self::charge(
            &mut self.artifact_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_artifact_bytes as u64,
            LimitKind::ArtifactBytes,
        )
    }

    pub fn charge_component_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        Self::charge(
            &mut self.component_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_component_bytes as u64,
            LimitKind::ComponentBytes,
        )
    }

    pub fn charge_embedded_module_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        if amount > PROFILE_1_LIMITS.max_core_module_bytes {
            return Err(LimitError {
                kind: LimitKind::CoreModuleBytes,
                attempted: amount as u64,
                maximum: PROFILE_1_LIMITS.max_core_module_bytes as u64,
            });
        }
        Self::charge(
            &mut self.embedded_module_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_component_bytes as u64,
            LimitKind::CoreModuleBytes,
        )
    }

    pub fn charge_types(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.types,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_types),
            LimitKind::Types,
        )
    }

    pub fn charge_functions(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.functions,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_functions),
            LimitKind::Functions,
        )
    }

    pub fn charge_imports(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.imports,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_imports),
            LimitKind::Imports,
        )
    }

    pub fn charge_exports(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.exports,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_exports),
            LimitKind::Exports,
        )
    }

    pub fn charge_resources(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.resources,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_resources),
            LimitKind::Resources,
        )
    }
}

const _: () = assert!(PROFILE_1_LIMITS.poll_quantum > 0);
const _: () = assert!(PROFILE_1_LIMITS.poll_quantum < PROFILE_1_LIMITS.total_fuel);
const _: () = assert!(PROFILE_1_LIMITS.max_memories == 1);
const _: () =
    assert!(PROFILE_1_LIMITS.max_initial_memory_pages <= PROFILE_1_LIMITS.max_memory_pages);
