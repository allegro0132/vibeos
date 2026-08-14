//! Allocation-free structural preflight for Component Model binaries.
//!
//! `wasmparser` intentionally materializes a handful of nested vectors as
//! boxed slices while decoding component types and instances. Profile 1 has
//! tighter limits than wasmparser's general-purpose limits, so those vector
//! lengths must be checked before the regular parser is allowed to see them.
//!
//! This module is only a preflight. It validates top-level section framing and
//! fully walks the allocation-bearing grammar accepted by Profile 1. The
//! regular parser and validator remain responsible for all other sections and
//! for index/type soundness.

use core::str;
use vibeos_component_format::PROFILE_1_LIMITS;

const COMPONENT_HEADER: &[u8; 8] = b"\0asm\x0d\0\x01\0";

const CUSTOM_SECTION: u8 = 0;
const CORE_MODULE_SECTION: u8 = 1;
const CORE_INSTANCE_SECTION: u8 = 2;
const CORE_TYPE_SECTION: u8 = 3;
const COMPONENT_SECTION: u8 = 4;
const COMPONENT_INSTANCE_SECTION: u8 = 5;
const ALIAS_SECTION: u8 = 6;
const COMPONENT_TYPE_SECTION: u8 = 7;
const CANONICAL_SECTION: u8 = 8;
const START_SECTION: u8 = 9;
const IMPORT_SECTION: u8 = 10;
const EXPORT_SECTION: u8 = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PredecodeError {
    NotComponent,
    Malformed,
    Unsupported,
    Limit,
}

/// Checks every allocation-bearing component vector against Profile 1 before
/// `wasmparser` can materialize it.
///
/// This routine performs no allocation. A `Limit` result takes precedence over
/// a truncated vector body once its declared length has been decoded. That is
/// intentional: an attacker cannot make the preflight walk a million claimed
/// entries just to discover that the last one is absent.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn predecode_component(bytes: &[u8]) -> Result<(), PredecodeError> {
    predecode_component_for_profile(
        bytes,
        vibeos_component_format::ProfileIdentity::PROFILE_1
            == vibeos_component_format::ProfileIdentity::PROFILE_1_ASYNC,
    )
}

pub(crate) fn predecode_component_for_profile(
    bytes: &[u8],
    async_profile: bool,
) -> Result<(), PredecodeError> {
    if bytes.len() > PROFILE_1_LIMITS.max_component_bytes {
        return Err(PredecodeError::Limit);
    }
    if bytes.len() < COMPONENT_HEADER.len() {
        return Err(PredecodeError::Malformed);
    }
    if bytes[..4] != COMPONENT_HEADER[..4] || &bytes[..8] != COMPONENT_HEADER {
        return Err(PredecodeError::NotComponent);
    }

    let mut reader = Reader::new(&bytes[COMPONENT_HEADER.len()..]);
    let mut budget = Budget::default();
    while !reader.eof() {
        let id = reader.byte()?;
        if id & 0x80 != 0 {
            return Err(PredecodeError::Malformed);
        }
        let length = reader.var_u32()? as usize;
        let mut section = reader.subreader(length)?;
        match id {
            CUSTOM_SECTION | CORE_MODULE_SECTION | ALIAS_SECTION | IMPORT_SECTION
            | EXPORT_SECTION => {}
            CORE_INSTANCE_SECTION => scan_core_instances(&mut section, &mut budget)?,
            CORE_TYPE_SECTION => {
                // Profile 1 rejects component-level core type declarations.
                // Decode the count first so a malformed LEB is still reported
                // deterministically without invoking wasmparser.
                if section.var_u32()? != 0 {
                    return Err(PredecodeError::Unsupported);
                }
                section.finish()?;
            }
            COMPONENT_SECTION | START_SECTION => return Err(PredecodeError::Unsupported),
            COMPONENT_INSTANCE_SECTION => scan_component_instances(&mut section, &mut budget)?,
            COMPONENT_TYPE_SECTION => {
                scan_component_types(&mut section, &mut budget, async_profile)?
            }
            CANONICAL_SECTION => {
                scan_canonical_functions(&mut section, &mut budget, async_profile)?
            }
            _ => return Err(PredecodeError::Unsupported),
        }
    }
    Ok(())
}

#[derive(Default)]
struct Budget {
    definitions: u32,
    core_instances: u32,
    component_instances: u32,
    aliases: u32,
    resources: u32,
    canonical_functions: u32,
    canonical_options: u32,
    async_functions: u32,
    future_types: u32,
    stream_types: u32,
}

impl Budget {
    fn definitions(&mut self, amount: u32) -> Result<(), PredecodeError> {
        charge(
            &mut self.definitions,
            amount,
            PROFILE_1_LIMITS.max_component_definitions,
        )
    }

    fn core_instances(&mut self, amount: u32) -> Result<(), PredecodeError> {
        charge(
            &mut self.core_instances,
            amount,
            PROFILE_1_LIMITS.max_component_instances,
        )
    }

    fn component_instances(&mut self, amount: u32) -> Result<(), PredecodeError> {
        charge(
            &mut self.component_instances,
            amount,
            PROFILE_1_LIMITS.max_component_instances,
        )
    }

    fn alias(&mut self) -> Result<(), PredecodeError> {
        charge(&mut self.aliases, 1, PROFILE_1_LIMITS.max_aliases)
    }

    fn resource(&mut self) -> Result<(), PredecodeError> {
        charge(&mut self.resources, 1, PROFILE_1_LIMITS.max_resources)
    }

    fn canonical_functions(&mut self, amount: u32) -> Result<(), PredecodeError> {
        charge(
            &mut self.canonical_functions,
            amount,
            PROFILE_1_LIMITS.max_canonical_functions,
        )
    }

    fn canonical_options(&mut self, amount: u32) -> Result<(), PredecodeError> {
        charge(
            &mut self.canonical_options,
            amount,
            PROFILE_1_LIMITS.max_canonical_options,
        )
    }

    fn async_function(&mut self) -> Result<(), PredecodeError> {
        charge(
            &mut self.async_functions,
            1,
            PROFILE_1_LIMITS.max_async_functions,
        )
    }

    fn future_type(&mut self) -> Result<(), PredecodeError> {
        charge(&mut self.future_types, 1, PROFILE_1_LIMITS.max_future_types)
    }

    fn stream_type(&mut self) -> Result<(), PredecodeError> {
        charge(&mut self.stream_types, 1, PROFILE_1_LIMITS.max_stream_types)
    }
}

fn charge(current: &mut u32, amount: u32, maximum: u32) -> Result<(), PredecodeError> {
    let next = current.checked_add(amount).ok_or(PredecodeError::Limit)?;
    if next > maximum {
        return Err(PredecodeError::Limit);
    }
    *current = next;
    Ok(())
}

fn scan_core_instances(reader: &mut Reader<'_>, budget: &mut Budget) -> Result<(), PredecodeError> {
    let count = reader.limited_count(PROFILE_1_LIMITS.max_component_instances)?;
    budget.core_instances(count)?;
    for _ in 0..count {
        match reader.byte()? {
            0x00 => {
                reader.var_u32()?; // module index
                let args = reader.limited_count(PROFILE_1_LIMITS.max_imports)?;
                for _ in 0..args {
                    reader.name()?;
                    if reader.byte()? != 0x12 {
                        return Err(PredecodeError::Malformed);
                    }
                    reader.var_u32()?;
                }
            }
            0x01 => {
                let exports = reader.limited_count(PROFILE_1_LIMITS.max_exports)?;
                for _ in 0..exports {
                    scan_core_export(reader)?;
                }
            }
            _ => return Err(PredecodeError::Malformed),
        }
    }
    reader.finish()
}

fn scan_core_export(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    reader.name()?;
    match reader.byte()? {
        0x00..=0x04 => {}
        _ => return Err(PredecodeError::Malformed),
    }
    reader.var_u32()?;
    Ok(())
}

#[derive(Default)]
struct CanonicalOptions {
    async_: bool,
    callback: bool,
}

fn scan_canonical_functions(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    async_profile: bool,
) -> Result<(), PredecodeError> {
    let count = reader.limited_count(PROFILE_1_LIMITS.max_canonical_functions)?;
    budget.canonical_functions(count)?;
    for _ in 0..count {
        scan_canonical_function(reader, budget, async_profile)?;
    }
    reader.finish()
}

fn scan_canonical_function(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    async_profile: bool,
) -> Result<(), PredecodeError> {
    match reader.byte()? {
        0x00 => {
            if reader.byte()? != 0x00 {
                return Err(PredecodeError::Malformed);
            }
            reader.var_u32()?;
            let options = scan_canonical_options(reader, budget)?;
            reader.var_u32()?;
            validate_lift_options(options, async_profile)
        }
        0x01 => {
            if reader.byte()? != 0x00 {
                return Err(PredecodeError::Malformed);
            }
            reader.var_u32()?;
            let options = scan_canonical_options(reader, budget)?;
            validate_lower_options(options, async_profile)
        }
        0x02..=0x04 => {
            reader.var_u32()?;
            Ok(())
        }
        0x05 | 0x0d | 0x1f | 0x22 | 0x23 | 0x24 | 0x25 => require_async_profile(async_profile),
        0x06 => {
            require_async_profile(async_profile)?;
            // The selected profile keeps the blocking/base spelling; the
            // async cancellation spelling is CM_MORE_ASYNC_BUILTINS.
            if reader.bool()? {
                Err(PredecodeError::Unsupported)
            } else {
                Ok(())
            }
        }
        0x09 => {
            require_async_profile(async_profile)?;
            scan_result_list(reader)?;
            let options = scan_canonical_options(reader, budget)?;
            if options.async_ || options.callback {
                Err(PredecodeError::Unsupported)
            } else {
                Ok(())
            }
        }
        0x0a | 0x0b => {
            require_async_profile(async_profile)?;
            // Profile 1 has one i32 task-context slot. i64 is CM64 and any
            // nonzero slot is gated by CM_THREADING upstream.
            if reader.byte()? != 0x7f || reader.var_u32()? != 0 {
                return Err(PredecodeError::Unsupported);
            }
            Ok(())
        }
        0x0c => {
            require_async_profile(async_profile)?;
            reader.bool()?;
            Ok(())
        }
        0x0e | 0x13 | 0x14 | 0x15 | 0x1a | 0x1b => {
            require_async_profile(async_profile)?;
            reader.var_u32()?;
            Ok(())
        }
        0x0f | 0x10 | 0x16 | 0x17 => {
            require_async_profile(async_profile)?;
            reader.var_u32()?;
            let options = scan_canonical_options(reader, budget)?;
            if !options.async_ || options.callback {
                return Err(PredecodeError::Unsupported);
            }
            Ok(())
        }
        0x11 | 0x12 | 0x18 | 0x19 => {
            require_async_profile(async_profile)?;
            reader.var_u32()?;
            // `true` is the CM_MORE_ASYNC_BUILTINS spelling.
            if reader.bool()? {
                Err(PredecodeError::Unsupported)
            } else {
                Ok(())
            }
        }
        0x20 | 0x21 => {
            require_async_profile(async_profile)?;
            reader.bool()?;
            reader.var_u32()?;
            Ok(())
        }
        // Removed/adjacent async draft opcodes, error-context, and every
        // threading intrinsic are outside the selected revision/feature set.
        0x07 | 0x08 | 0x1c..=0x1e | 0x26..=0x2d | 0x40..=0x42 => Err(PredecodeError::Unsupported),
        _ => Err(PredecodeError::Unsupported),
    }
}

fn require_async_profile(enabled: bool) -> Result<(), PredecodeError> {
    if enabled {
        Ok(())
    } else {
        Err(PredecodeError::Unsupported)
    }
}

fn scan_result_list(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    match reader.byte()? {
        0x00 => scan_component_val_type(reader),
        0x01 if reader.byte()? == 0 => Ok(()),
        0x01 => Err(PredecodeError::Malformed),
        _ => Err(PredecodeError::Malformed),
    }
}

fn validate_lift_options(
    options: CanonicalOptions,
    async_profile: bool,
) -> Result<(), PredecodeError> {
    if options.async_ {
        require_async_profile(async_profile)?;
        if !options.callback {
            // Callback-free lift is the disabled stackful proposal.
            return Err(PredecodeError::Unsupported);
        }
    } else if options.callback {
        return Err(PredecodeError::Unsupported);
    }
    Ok(())
}

fn validate_lower_options(
    options: CanonicalOptions,
    async_profile: bool,
) -> Result<(), PredecodeError> {
    if options.callback {
        return Err(PredecodeError::Unsupported);
    }
    if options.async_ {
        require_async_profile(async_profile)?;
    }
    Ok(())
}

fn scan_canonical_options(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
) -> Result<CanonicalOptions, PredecodeError> {
    let count = reader.limited_count(PROFILE_1_LIMITS.max_canonical_options_per_function)?;
    budget.canonical_options(count)?;
    let mut result = CanonicalOptions::default();
    let mut utf8 = false;
    let mut memory = false;
    let mut realloc = false;
    let mut post_return = false;
    for _ in 0..count {
        let duplicate = match reader.byte()? {
            0x00 => core::mem::replace(&mut utf8, true),
            0x03 => {
                reader.var_u32()?;
                core::mem::replace(&mut memory, true)
            }
            0x04 => {
                reader.var_u32()?;
                core::mem::replace(&mut realloc, true)
            }
            0x05 => {
                reader.var_u32()?;
                core::mem::replace(&mut post_return, true)
            }
            0x06 => core::mem::replace(&mut result.async_, true),
            0x07 => {
                reader.var_u32()?;
                core::mem::replace(&mut result.callback, true)
            }
            // UTF-16, core-type and GC are explicit profile rejections.
            0x01 | 0x02 | 0x08 | 0x09 => return Err(PredecodeError::Unsupported),
            _ => return Err(PredecodeError::Malformed),
        };
        if duplicate {
            return Err(PredecodeError::Malformed);
        }
    }
    Ok(result)
}

fn scan_component_instances(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
) -> Result<(), PredecodeError> {
    let count = reader.limited_count(PROFILE_1_LIMITS.max_component_instances)?;
    budget.component_instances(count)?;
    for _ in 0..count {
        match reader.byte()? {
            0x00 => {
                reader.var_u32()?; // component index
                let args = reader.limited_count(PROFILE_1_LIMITS.max_imports)?;
                for _ in 0..args {
                    reader.name()?;
                    scan_component_external_kind(reader)?;
                    reader.var_u32()?;
                }
            }
            0x01 => {
                let exports = reader.limited_count(PROFILE_1_LIMITS.max_exports)?;
                for _ in 0..exports {
                    reader.component_name()?;
                    scan_component_external_kind(reader)?;
                    reader.var_u32()?;
                }
            }
            _ => return Err(PredecodeError::Malformed),
        }
    }
    reader.finish()
}

fn scan_component_types(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    async_profile: bool,
) -> Result<(), PredecodeError> {
    let count = reader.limited_count(PROFILE_1_LIMITS.max_component_definitions)?;
    budget.definitions(count)?;
    for _ in 0..count {
        scan_component_type(reader, budget, async_profile, 1)?;
    }
    reader.finish()
}

fn scan_component_type(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    async_profile: bool,
    depth: u32,
) -> Result<(), PredecodeError> {
    if depth > PROFILE_1_LIMITS.max_component_nesting {
        return Err(PredecodeError::Limit);
    }
    match reader.byte()? {
        0x3f => {
            // Resource representation. Profile 1 only admits core i32.
            if reader.byte()? != 0x7f {
                return Err(PredecodeError::Unsupported);
            }
            match reader.byte()? {
                0x00 => {}
                0x01 => {
                    reader.var_u32()?;
                }
                _ => return Err(PredecodeError::Malformed),
            }
            budget.resource()
        }
        0x40 => scan_component_func_type(reader),
        0x43 if async_profile => {
            budget.async_function()?;
            scan_component_func_type(reader)
        }
        0x43 => Err(PredecodeError::Unsupported),
        0x41 => {
            // Component types allocate a declaration vector and are outside
            // Profile 1. Still decode and cap the count before classifying it.
            reader.limited_count(PROFILE_1_LIMITS.max_component_definitions)?;
            Err(PredecodeError::Unsupported)
        }
        0x42 => {
            let declarations = reader.limited_count(PROFILE_1_LIMITS.max_component_definitions)?;
            for _ in 0..declarations {
                scan_instance_type_declaration(reader, budget, async_profile, depth)?;
            }
            Ok(())
        }
        byte if is_primitive(byte) => Ok(()),
        0x72 => {
            let fields = reader.limited_count(PROFILE_1_LIMITS.max_canonical_values)?;
            for _ in 0..fields {
                reader.name()?;
                scan_component_val_type(reader)?;
            }
            Ok(())
        }
        0x71 => {
            let cases = reader.limited_count(PROFILE_1_LIMITS.max_canonical_values)?;
            for _ in 0..cases {
                reader.name()?;
                scan_optional_component_val_type(reader)?;
                if reader.byte()? != 0 {
                    return Err(PredecodeError::Malformed);
                }
            }
            Ok(())
        }
        0x70 | 0x6b => scan_component_val_type(reader),
        0x6f => {
            let types = reader.limited_count(PROFILE_1_LIMITS.max_canonical_values)?;
            for _ in 0..types {
                scan_component_val_type(reader)?;
            }
            Ok(())
        }
        0x6e | 0x6d => {
            let names = reader.limited_count(PROFILE_1_LIMITS.max_canonical_values)?;
            for _ in 0..names {
                reader.name()?;
            }
            Ok(())
        }
        0x6a => {
            scan_optional_component_val_type(reader)?;
            scan_optional_component_val_type(reader)
        }
        0x69 | 0x68 => {
            reader.var_u32()?;
            Ok(())
        }
        // map and fixed-length-list are not in Profile 1.
        0x63 | 0x67 => Err(PredecodeError::Unsupported),
        0x65 if async_profile => {
            budget.future_type()?;
            scan_optional_component_val_type(reader)
        }
        0x66 if async_profile => {
            budget.stream_type()?;
            scan_optional_component_val_type(reader)
        }
        0x65 | 0x66 => Err(PredecodeError::Unsupported),
        _ => Err(PredecodeError::Malformed),
    }
}

fn scan_component_func_type(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    let params = reader.limited_count(PROFILE_1_LIMITS.max_params_per_function)?;
    for _ in 0..params {
        reader.name()?;
        scan_component_val_type(reader)?;
    }
    match reader.byte()? {
        // A single unnamed result.
        0x00 => scan_component_val_type(reader),
        // The result-list form currently only permits zero results.
        0x01 if reader.byte()? == 0 => Ok(()),
        0x01 => Err(PredecodeError::Malformed),
        _ => Err(PredecodeError::Malformed),
    }
}

fn scan_instance_type_declaration(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    async_profile: bool,
    depth: u32,
) -> Result<(), PredecodeError> {
    match reader.byte()? {
        // Any component-level core type is outside Profile 1. Reject before
        // wasmparser can materialize a core module type declaration vector.
        0x00 => Err(PredecodeError::Unsupported),
        0x01 => {
            budget.definitions(1)?;
            let next_depth = depth.checked_add(1).ok_or(PredecodeError::Limit)?;
            scan_component_type(reader, budget, async_profile, next_depth)
        }
        0x02 => {
            budget.alias()?;
            scan_component_alias(reader)
        }
        0x04 => {
            reader.component_name()?;
            scan_component_type_ref(reader)
        }
        _ => Err(PredecodeError::Malformed),
    }
}

fn scan_component_alias(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    let byte1 = reader.byte()?;
    let byte2 = if byte1 == 0x00 {
        Some(reader.byte()?)
    } else {
        None
    };
    match reader.byte()? {
        0x00 => {
            validate_component_external_kind(byte1, byte2)?;
            reader.var_u32()?;
            reader.name()
        }
        0x01 => {
            if byte1 != 0x00 || !matches!(byte2, Some(0x00..=0x04 | 0x20)) {
                return Err(PredecodeError::Malformed);
            }
            reader.var_u32()?;
            reader.name()
        }
        0x02 => {
            match (byte1, byte2) {
                (0x00, Some(0x10 | 0x11)) | (0x03 | 0x04, None) => {}
                _ => return Err(PredecodeError::Malformed),
            }
            reader.var_u32()?;
            reader.var_u32()?;
            Ok(())
        }
        _ => Err(PredecodeError::Malformed),
    }
}

fn scan_component_type_ref(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    match read_component_external_kind(reader)? {
        ComponentKind::Module
        | ComponentKind::Func
        | ComponentKind::Instance
        | ComponentKind::Component => {
            reader.var_u32()?;
            Ok(())
        }
        ComponentKind::Value => scan_component_val_type(reader),
        ComponentKind::Type => match reader.byte()? {
            0x00 => {
                reader.var_u32()?;
                Ok(())
            }
            0x01 => Ok(()),
            _ => Err(PredecodeError::Malformed),
        },
    }
}

fn scan_component_val_type(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    let byte = reader.peek()?;
    if is_primitive(byte) {
        reader.byte()?;
        Ok(())
    } else {
        reader.var_s33()
    }
}

fn scan_optional_component_val_type(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    match reader.byte()? {
        0x00 => Ok(()),
        0x01 => scan_component_val_type(reader),
        _ => Err(PredecodeError::Malformed),
    }
}

const fn is_primitive(byte: u8) -> bool {
    matches!(byte, 0x73..=0x7f | 0x64)
}

#[derive(Clone, Copy)]
enum ComponentKind {
    Module,
    Func,
    Value,
    Type,
    Component,
    Instance,
}

fn scan_component_external_kind(reader: &mut Reader<'_>) -> Result<(), PredecodeError> {
    read_component_external_kind(reader).map(|_| ())
}

fn read_component_external_kind(reader: &mut Reader<'_>) -> Result<ComponentKind, PredecodeError> {
    let byte1 = reader.byte()?;
    let byte2 = if byte1 == 0x00 {
        Some(reader.byte()?)
    } else {
        None
    };
    component_external_kind(byte1, byte2)
}

fn validate_component_external_kind(byte1: u8, byte2: Option<u8>) -> Result<(), PredecodeError> {
    component_external_kind(byte1, byte2).map(|_| ())
}

fn component_external_kind(byte1: u8, byte2: Option<u8>) -> Result<ComponentKind, PredecodeError> {
    match (byte1, byte2) {
        (0x00, Some(0x11)) => Ok(ComponentKind::Module),
        (0x01, None) => Ok(ComponentKind::Func),
        (0x02, None) => Ok(ComponentKind::Value),
        (0x03, None) => Ok(ComponentKind::Type),
        (0x04, None) => Ok(ComponentKind::Component),
        (0x05, None) => Ok(ComponentKind::Instance),
        _ => Err(PredecodeError::Malformed),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn eof(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn finish(&self) -> Result<(), PredecodeError> {
        if self.eof() {
            Ok(())
        } else {
            Err(PredecodeError::Malformed)
        }
    }

    fn peek(&self) -> Result<u8, PredecodeError> {
        self.bytes
            .get(self.position)
            .copied()
            .ok_or(PredecodeError::Malformed)
    }

    fn byte(&mut self) -> Result<u8, PredecodeError> {
        let byte = self.peek()?;
        self.position += 1;
        Ok(byte)
    }

    fn bool(&mut self) -> Result<bool, PredecodeError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PredecodeError::Malformed),
        }
    }

    fn subreader(&mut self, length: usize) -> Result<Reader<'a>, PredecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PredecodeError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(PredecodeError::Malformed)?;
        self.position = end;
        Ok(Reader::new(bytes))
    }

    fn limited_count(&mut self, maximum: u32) -> Result<u32, PredecodeError> {
        let count = self.var_u32()?;
        if count > maximum {
            Err(PredecodeError::Limit)
        } else {
            Ok(count)
        }
    }

    fn var_u32(&mut self) -> Result<u32, PredecodeError> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(u32::from(first));
        }

        let mut result = u32::from(first & 0x7f);
        let mut shift = 7;
        loop {
            let byte = self.byte()?;
            result |= u32::from(byte & 0x7f) << shift;
            if shift >= 25 && (byte >> (32 - shift)) != 0 {
                return Err(PredecodeError::Malformed);
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
    }

    fn var_s33(&mut self) -> Result<(), PredecodeError> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(());
        }

        let mut shift = 7;
        loop {
            let byte = self.byte()?;
            if shift >= 25 {
                let continuation = byte & 0x80 != 0;
                let sign_and_unused = (byte << 1) as i8 >> (33 - shift);
                if continuation || (sign_and_unused != 0 && sign_and_unused != -1) {
                    return Err(PredecodeError::Malformed);
                }
                return Ok(());
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(());
            }
        }
    }

    fn name(&mut self) -> Result<(), PredecodeError> {
        let length = self.var_u32()? as usize;
        if length > PROFILE_1_LIMITS.max_string_bytes {
            return Err(PredecodeError::Limit);
        }
        let name = self.subreader(length)?;
        str::from_utf8(name.bytes).map_err(|_| PredecodeError::Malformed)?;
        Ok(())
    }

    fn component_name(&mut self) -> Result<(), PredecodeError> {
        match self.byte()? {
            // 0x01 is a legacy spelling that wasmparser intentionally keeps
            // accepting; neither discriminator carries additional options.
            0x00 | 0x01 => self.name(),
            // Name options require disabled component-model proposals.
            0x02 => Err(PredecodeError::Unsupported),
            _ => Err(PredecodeError::Malformed),
        }
    }
}
