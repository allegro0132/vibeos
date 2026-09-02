//! Acceptance-only Canonical ABI codec for the C8.8 scalar-float candidate.
//!
//! This module deliberately owns a flat-value representation that is
//! disjoint from `vibeos-wasm-runtime::CoreValue`.  It can therefore validate
//! and exercise the Profile-2 Canonical ABI without making scalar floats
//! reachable from the current Profile-1 runtime.

use super::{
    add_pointer, align_to, allocate_payload, indexed, lift_at, lower_at, read_vec, sequence_layout,
    span, span_size, try_box, validate_position, zero, AllocationSpan, Budget,
};
pub use super::{
    CodecError, CodecUsage, LoweringJournal, PayloadAllocator, RejectResources, ResourceBinder,
};
use crate::{
    memory::GuestMemory,
    value::{
        validate_type, validate_value, CanonicalF32, CanonicalF64, CanonicalValue, ValuePosition,
        ValueType,
    },
};
use alloc::{boxed::Box, string::String, vec::Vec};
use vibeos_component_format::PROFILE_1_LIMITS;

pub use super::{MAX_FLAT_PARAMS, MAX_FLAT_RESULTS};

/// Core numeric kind used only by the acceptance candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFlatKind {
    I32,
    I64,
    F32,
    F64,
}

/// Bit-only Core numeric value used only by the acceptance candidate.
///
/// Floating-point variants intentionally expose bits, not host `f32`/`f64`,
/// so no operation in this codec can depend on the host floating-point unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateFlatValue {
    I32(i32),
    I64(i64),
    F32Bits(u32),
    F64Bits(u64),
}

impl CandidateFlatValue {
    pub const fn kind(self) -> CandidateFlatKind {
        match self {
            Self::I32(_) => CandidateFlatKind::I32,
            Self::I64(_) => CandidateFlatKind::I64,
            Self::F32Bits(_) => CandidateFlatKind::F32,
            Self::F64Bits(_) => CandidateFlatKind::F64,
        }
    }

    const fn zero(kind: CandidateFlatKind) -> Self {
        match kind {
            CandidateFlatKind::I32 => Self::I32(0),
            CandidateFlatKind::I64 => Self::I64(0),
            CandidateFlatKind::F32 => Self::F32Bits(0),
            CandidateFlatKind::F64 => Self::F64Bits(0),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateLoweredParameters {
    Flat {
        values: Vec<CandidateFlatValue>,
        usage: CodecUsage,
    },
    Indirect {
        pointer: u32,
        arguments: [CandidateFlatValue; 1],
        usage: CodecUsage,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum CandidateLoweredResults {
    Flat {
        values: Vec<CandidateFlatValue>,
        usage: CodecUsage,
    },
    Retptr {
        pointer: u32,
        usage: CodecUsage,
    },
}

pub type LoweredParameters = CandidateLoweredParameters;
pub type LoweredResults = CandidateLoweredResults;

/// Pre-reserved one-flat result buffer for post-dispatch lowering.
pub struct CandidatePreparedFlatResults {
    signature: Vec<CandidateFlatKind>,
    values: Vec<CandidateFlatValue>,
}

pub type PreparedFlatResults = CandidatePreparedFlatResults;

impl CandidatePreparedFlatResults {
    pub fn try_new(types: &[ValueType]) -> Result<Self, CodecError> {
        let signature = flat_signature(types)?;
        if signature.len() > MAX_FLAT_RESULTS {
            return Err(CodecError::FlatLimit);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(signature.len())
            .map_err(|_| CodecError::Allocation)?;
        Ok(Self { signature, values })
    }

    pub fn signature(&self) -> &[CandidateFlatKind] {
        &self.signature
    }
}

/// Lowers one candidate value to its exact memory32 Canonical ABI layout.
pub fn lower_value<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: &ValueType,
    value: &CanonicalValue,
    pointer: u32,
    position: ValuePosition,
) -> Result<CodecUsage, CodecError> {
    let layout = validate_type(ty)?.layout;
    ensure_candidate_supported(ty)?;
    validate_value(ty, value)?;
    validate_position(ty, position)?;
    let mut budget = Budget::default();
    budget.protect(pointer, layout.size)?;
    lower_at(memory, allocator, ty, value, pointer, 1, true, &mut budget)?;
    Ok(budget.usage)
}

/// Lifts one candidate value from hostile memory and canonicalizes every NaN.
pub fn lift_value<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: &ValueType,
    pointer: u32,
    position: ValuePosition,
) -> Result<(CanonicalValue, CodecUsage), CodecError> {
    validate_type(ty)?;
    ensure_candidate_supported(ty)?;
    validate_position(ty, position)?;
    let mut budget = Budget::default();
    let value = lift_at(memory, binder, ty, pointer, position, 1, true, &mut budget)?;
    validate_value(ty, &value)?;
    Ok((value, budget.usage))
}

/// Computes the acceptance candidate's exact flat Core signature.
pub fn flat_signature(types: &[ValueType]) -> Result<Vec<CandidateFlatKind>, CodecError> {
    let mut result = Vec::new();
    for ty in types {
        validate_type(ty)?;
        ensure_candidate_supported(ty)?;
        append_flat_types(ty, &mut result)?;
    }
    Ok(result)
}

/// Lifts parameters from their flat form or the required indirect pointer.
pub fn lift_parameters<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    arguments: &[CandidateFlatValue],
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_PARAMS {
        lift_flat_values(memory, binder, types, arguments, ValuePosition::Parameter)
    } else {
        let pointer = exact_pointer(arguments)?;
        lift_indirect_values(memory, binder, types, pointer, ValuePosition::Parameter)
    }
}

/// Lifts results from their flat form or an exact `[i32(retptr)]` form.
pub fn lift_results<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    results: &[CandidateFlatValue],
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_RESULTS {
        lift_flat_values(memory, binder, types, results, ValuePosition::Result)
    } else {
        let pointer = exact_pointer(results)?;
        lift_indirect_values(memory, binder, types, pointer, ValuePosition::Result)
    }
}

/// Lifts an exact sequence layout from hostile memory.
pub fn lift_indirect_values<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    pointer: u32,
    position: ValuePosition,
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    validate_type_sequence(types, position)?;
    let layout = sequence_layout(types)?;
    span(memory, pointer, layout)?;
    let mut budget = Budget::default();
    budget.bytes(layout.size)?;
    let mut values = Vec::new();
    if !types.is_empty() {
        budget.allocation()?;
    }
    values
        .try_reserve_exact(types.len())
        .map_err(|_| CodecError::Allocation)?;
    let mut offset = 0usize;
    for ty in types {
        let field = validate_type(ty)?.layout;
        offset = align_to(offset, field.alignment)?;
        values.push(lift_at(
            memory,
            binder,
            ty,
            add_pointer(pointer, offset)?,
            position,
            1,
            false,
            &mut budget,
        )?);
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok((values, budget.usage))
}

/// Lifts values from an exact candidate flat signature.
pub fn lift_flat_values<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    flat: &[CandidateFlatValue],
    position: ValuePosition,
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    validate_type_sequence(types, position)?;
    let signature = flat_signature(types)?;
    if flat.len() != signature.len() {
        return Err(CodecError::FlatLimit);
    }
    if flat
        .iter()
        .zip(&signature)
        .any(|(value, expected)| value.kind() != *expected)
    {
        return Err(CodecError::TypeMismatch);
    }
    let mut budget = Budget::default();
    let mut values = Vec::new();
    if !types.is_empty() {
        budget.allocation()?;
    }
    values
        .try_reserve_exact(types.len())
        .map_err(|_| CodecError::Allocation)?;
    let mut cursor = CandidateFlatCursor::new(flat);
    for ty in types {
        values.push(lift_flat_value(
            memory,
            binder,
            ty,
            &mut cursor,
            position,
            1,
            &mut budget,
        )?);
    }
    if !cursor.is_empty() {
        return Err(CodecError::FlatLimit);
    }
    Ok((values, budget.usage))
}

/// Lowers parameters to a flat signature, or to one indirect pointer.
pub fn lower_parameters<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
) -> Result<CandidateLoweredParameters, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Parameter)?;
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_PARAMS {
        let (values, usage) = lower_flat_values(memory, allocator, types, values)?;
        return Ok(CandidateLoweredParameters::Flat { values, usage });
    }
    let layout = sequence_layout(types)?;
    let mut budget = Budget::default();
    let pointer = allocate_payload(
        memory,
        allocator,
        layout.size,
        layout.alignment,
        &mut budget,
    )?;
    budget.protected = Some(AllocationSpan {
        start: pointer,
        size: u32::try_from(layout.size).map_err(|_| CodecError::ByteLimit)?,
    });
    lower_sequence_at(memory, allocator, types, values, pointer, &mut budget)?;
    Ok(CandidateLoweredParameters::Indirect {
        pointer,
        arguments: [CandidateFlatValue::I32(pointer as i32)],
        usage: budget.usage,
    })
}

/// Lowers results to at most one flat value, or to a newly allocated retptr.
pub fn lower_results<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
) -> Result<CandidateLoweredResults, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Result)?;
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_RESULTS {
        let (values, usage) = lower_flat_values(memory, allocator, types, values)?;
        return Ok(CandidateLoweredResults::Flat { values, usage });
    }
    let layout = sequence_layout(types)?;
    let mut budget = Budget::default();
    let pointer = allocate_payload(
        memory,
        allocator,
        layout.size,
        layout.alignment,
        &mut budget,
    )?;
    budget.protected = Some(AllocationSpan {
        start: pointer,
        size: u32::try_from(layout.size).map_err(|_| CodecError::ByteLimit)?,
    });
    lower_sequence_at(memory, allocator, types, values, pointer, &mut budget)?;
    Ok(CandidateLoweredResults::Retptr {
        pointer,
        usage: budget.usage,
    })
}

/// Lowers an exact flat sequence without exposing the production Core value.
pub fn lower_flat_values<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
) -> Result<(Vec<CandidateFlatValue>, CodecUsage), CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Parameter)?;
    let signature = flat_signature(types)?;
    let mut budget = Budget::default();
    let mut flat = Vec::new();
    flat.try_reserve_exact(signature.len())
        .map_err(|_| CodecError::Allocation)?;
    for (ty, value) in types.iter().zip(values) {
        flatten_value(memory, allocator, ty, value, 1, &mut flat, &mut budget)?;
    }
    if flat.len() != signature.len()
        || flat
            .iter()
            .zip(&signature)
            .any(|(value, expected)| value.kind() != *expected)
    {
        return Err(CodecError::FlatLimit);
    }
    Ok((flat, budget.usage))
}

/// Allocation-free lowering for a pre-reserved single flat result.
pub fn lower_flat_results_prepared<M: GuestMemory, A: PayloadAllocator<M>>(
    _memory: &mut M,
    _allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
    prepared: &mut CandidatePreparedFlatResults,
) -> Result<(Vec<CandidateFlatValue>, CodecUsage), CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Result)?;
    prepared.values.clear();
    let mut budget = Budget::default();
    let expected_len = prepared.signature.len();
    for (ty, value) in types.iter().zip(values) {
        flatten_value_prepared(
            ty,
            value,
            1,
            &mut prepared.values,
            expected_len,
            &mut budget,
        )?;
    }
    if prepared.values.len() != prepared.signature.len()
        || prepared
            .values
            .iter()
            .zip(&prepared.signature)
            .any(|(value, expected)| value.kind() != *expected)
    {
        return Err(CodecError::FlatLimit);
    }
    let mut result = Vec::new();
    core::mem::swap(&mut result, &mut prepared.values);
    Ok((result, budget.usage))
}

/// Lowers an indirect result tuple into a caller-provided return area.
pub fn lower_results_into<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
    pointer: u32,
) -> Result<CodecUsage, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Result)?;
    if flat_signature(types)?.len() <= MAX_FLAT_RESULTS {
        return Err(CodecError::FlatLimit);
    }
    let layout = sequence_layout(types)?;
    span(memory, pointer, layout)?;
    let mut budget = Budget::default();
    budget.bytes(layout.size)?;
    budget.protect(pointer, layout.size)?;
    zero(memory, pointer, layout.size)?;
    lower_sequence_at(memory, allocator, types, values, pointer, &mut budget)?;
    Ok(budget.usage)
}

/// Allocation-stable indirect lowering using the production allocation journal.
pub fn lower_results_into_prepared<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
    pointer: u32,
    journal: &mut LoweringJournal,
) -> Result<CodecUsage, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Result)?;
    if flat_signature(types)?.len() <= MAX_FLAT_RESULTS {
        return Err(CodecError::FlatLimit);
    }
    let layout = sequence_layout(types)?;
    span(memory, pointer, layout)?;
    let allocations = core::mem::take(&mut journal.allocations);
    let mut budget = Budget {
        allocations,
        allocations_fixed: true,
        ..Budget::default()
    };
    budget.allocations.clear();
    let result = (|| {
        budget.bytes(layout.size)?;
        budget.protect(pointer, layout.size)?;
        zero(memory, pointer, layout.size)?;
        lower_sequence_at(memory, allocator, types, values, pointer, &mut budget)?;
        Ok(budget.usage)
    })();
    journal.allocations = budget.allocations;
    result
}

fn ensure_candidate_supported(ty: &ValueType) -> Result<(), CodecError> {
    match ty {
        ValueType::Stream { .. } | ValueType::Future { .. } => Err(CodecError::Unsupported),
        ValueType::List(item) | ValueType::Option(item) => ensure_candidate_supported(item),
        ValueType::Tuple(types) | ValueType::Record(types) => {
            for ty in types {
                ensure_candidate_supported(ty)?;
            }
            Ok(())
        }
        ValueType::Result { ok, error } => {
            if let Some(ok) = ok {
                ensure_candidate_supported(ok)?;
            }
            if let Some(error) = error {
                ensure_candidate_supported(error)?;
            }
            Ok(())
        }
        ValueType::Variant(cases) => {
            for case in cases.iter().flatten() {
                ensure_candidate_supported(case)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_type_sequence(types: &[ValueType], position: ValuePosition) -> Result<(), CodecError> {
    for ty in types {
        validate_type(ty)?;
        ensure_candidate_supported(ty)?;
        validate_position(ty, position)?;
    }
    Ok(())
}

fn validate_sequence(
    types: &[ValueType],
    values: &[CanonicalValue],
    position: ValuePosition,
) -> Result<(), CodecError> {
    for (ty, value) in types.iter().zip(values) {
        validate_type(ty)?;
        ensure_candidate_supported(ty)?;
        validate_value(ty, value)?;
        validate_position(ty, position)?;
    }
    Ok(())
}

fn lower_sequence_at<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
    pointer: u32,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    let mut offset = 0usize;
    for (ty, value) in types.iter().zip(values) {
        let field = validate_type(ty)?.layout;
        offset = align_to(offset, field.alignment)?;
        lower_at(
            memory,
            allocator,
            ty,
            value,
            add_pointer(pointer, offset)?,
            1,
            false,
            budget,
        )?;
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok(())
}

fn append_flat_types(
    ty: &ValueType,
    output: &mut Vec<CandidateFlatKind>,
) -> Result<(), CodecError> {
    validate_type(ty)?;
    match ty {
        ValueType::U64 | ValueType::S64 => push_flat_kind(output, CandidateFlatKind::I64),
        ValueType::F32 => push_flat_kind(output, CandidateFlatKind::F32),
        ValueType::F64 => push_flat_kind(output, CandidateFlatKind::F64),
        ValueType::String | ValueType::List(_) => {
            push_flat_kind(output, CandidateFlatKind::I32)?;
            push_flat_kind(output, CandidateFlatKind::I32)
        }
        ValueType::Tuple(types) | ValueType::Record(types) => {
            for ty in types {
                append_flat_types(ty, output)?;
            }
            Ok(())
        }
        ValueType::Flags(count) => {
            let words = count.checked_add(31).ok_or(CodecError::InvalidFlags)? / 32;
            for _ in 0..words {
                push_flat_kind(output, CandidateFlatKind::I32)?;
            }
            Ok(())
        }
        ValueType::Option(inner) => append_variant_flat([None, Some(inner.as_ref())], output),
        ValueType::Result { ok, error } => {
            append_variant_flat([ok.as_deref(), error.as_deref()], output)
        }
        ValueType::Variant(cases) => append_variant_flat(cases.iter().map(Option::as_ref), output),
        ValueType::Stream { .. } | ValueType::Future { .. } => Err(CodecError::Unsupported),
        _ => push_flat_kind(output, CandidateFlatKind::I32),
    }
}

fn append_variant_flat<'a>(
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
    output: &mut Vec<CandidateFlatKind>,
) -> Result<(), CodecError> {
    push_flat_kind(output, CandidateFlatKind::I32)?;
    let mut joined = Vec::new();
    for case in cases {
        let mut shape = Vec::new();
        if let Some(case) = case {
            append_flat_types(case, &mut shape)?;
        }
        for (index, incoming) in shape.into_iter().enumerate() {
            if let Some(current) = joined.get_mut(index) {
                *current = join_flat_kinds(*current, incoming);
            } else {
                joined.try_reserve(1).map_err(|_| CodecError::Allocation)?;
                joined.push(incoming);
            }
        }
    }
    for kind in joined {
        push_flat_kind(output, kind)?;
    }
    Ok(())
}

const fn join_flat_kinds(left: CandidateFlatKind, right: CandidateFlatKind) -> CandidateFlatKind {
    if left as u8 == right as u8 {
        return left;
    }
    match (left, right) {
        (CandidateFlatKind::I32, CandidateFlatKind::F32)
        | (CandidateFlatKind::F32, CandidateFlatKind::I32) => CandidateFlatKind::I32,
        _ => CandidateFlatKind::I64,
    }
}

fn push_flat_kind(
    output: &mut Vec<CandidateFlatKind>,
    value: CandidateFlatKind,
) -> Result<(), CodecError> {
    if output.len() >= PROFILE_1_LIMITS.max_canonical_values as usize {
        return Err(CodecError::FlatLimit);
    }
    output.try_reserve(1).map_err(|_| CodecError::Allocation)?;
    output.push(value);
    Ok(())
}

fn exact_pointer(values: &[CandidateFlatValue]) -> Result<u32, CodecError> {
    match values {
        [CandidateFlatValue::I32(pointer)] => Ok(*pointer as u32),
        [_] => Err(CodecError::TypeMismatch),
        _ => Err(CodecError::FlatLimit),
    }
}

struct CandidateFlatCursor<'a> {
    values: &'a [CandidateFlatValue],
    offset: usize,
}

impl<'a> CandidateFlatCursor<'a> {
    const fn new(values: &'a [CandidateFlatValue]) -> Self {
        Self { values, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.values.len()
    }

    fn take(&mut self, expected: CandidateFlatKind) -> Result<CandidateFlatValue, CodecError> {
        let value = self
            .values
            .get(self.offset)
            .copied()
            .ok_or(CodecError::FlatLimit)?;
        if value.kind() != expected {
            return Err(CodecError::TypeMismatch);
        }
        self.offset += 1;
        Ok(value)
    }

    fn take_i32(&mut self) -> Result<i32, CodecError> {
        match self.take(CandidateFlatKind::I32)? {
            CandidateFlatValue::I32(value) => Ok(value),
            _ => Err(CodecError::TypeMismatch),
        }
    }

    fn take_i64(&mut self) -> Result<i64, CodecError> {
        match self.take(CandidateFlatKind::I64)? {
            CandidateFlatValue::I64(value) => Ok(value),
            _ => Err(CodecError::TypeMismatch),
        }
    }

    fn take_f32_bits(&mut self) -> Result<u32, CodecError> {
        match self.take(CandidateFlatKind::F32)? {
            CandidateFlatValue::F32Bits(value) => Ok(value),
            _ => Err(CodecError::TypeMismatch),
        }
    }

    fn take_f64_bits(&mut self) -> Result<u64, CodecError> {
        match self.take(CandidateFlatKind::F64)? {
            CandidateFlatValue::F64Bits(value) => Ok(value),
            _ => Err(CodecError::TypeMismatch),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_flat_value<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: &ValueType,
    cursor: &mut CandidateFlatCursor<'_>,
    position: ValuePosition,
    depth: u32,
    budget: &mut Budget,
) -> Result<CanonicalValue, CodecError> {
    budget.enter(depth)?;
    match ty {
        ValueType::Bool => match cursor.take_i32()? {
            0 => Ok(CanonicalValue::Bool(false)),
            1 => Ok(CanonicalValue::Bool(true)),
            _ => Err(CodecError::InvalidBool),
        },
        ValueType::U8 => u8::try_from(cursor.take_i32()?)
            .map(CanonicalValue::U8)
            .map_err(|_| CodecError::TypeMismatch),
        ValueType::S8 => i8::try_from(cursor.take_i32()?)
            .map(CanonicalValue::S8)
            .map_err(|_| CodecError::TypeMismatch),
        ValueType::U16 => u16::try_from(cursor.take_i32()?)
            .map(CanonicalValue::U16)
            .map_err(|_| CodecError::TypeMismatch),
        ValueType::S16 => i16::try_from(cursor.take_i32()?)
            .map(CanonicalValue::S16)
            .map_err(|_| CodecError::TypeMismatch),
        ValueType::U32 => Ok(CanonicalValue::U32(cursor.take_i32()? as u32)),
        ValueType::S32 => Ok(CanonicalValue::S32(cursor.take_i32()?)),
        ValueType::U64 => Ok(CanonicalValue::U64(cursor.take_i64()? as u64)),
        ValueType::S64 => Ok(CanonicalValue::S64(cursor.take_i64()?)),
        ValueType::F32 => Ok(CanonicalValue::F32(CanonicalF32::from_bits(
            cursor.take_f32_bits()?,
        ))),
        ValueType::F64 => Ok(CanonicalValue::F64(CanonicalF64::from_bits(
            cursor.take_f64_bits()?,
        ))),
        ValueType::Char => char::from_u32(cursor.take_i32()? as u32)
            .map(CanonicalValue::Char)
            .ok_or(CodecError::InvalidChar),
        ValueType::String => {
            let pointer = cursor.take_i32()? as u32;
            let length =
                usize::try_from(cursor.take_i32()? as u32).map_err(|_| CodecError::ByteLimit)?;
            if length > PROFILE_1_LIMITS.max_string_bytes {
                return Err(CodecError::ByteLimit);
            }
            budget.bytes(length)?;
            if length != 0 {
                budget.allocation()?;
            }
            let bytes = read_vec(memory, pointer, length, 1)?;
            String::from_utf8(bytes)
                .map(CanonicalValue::String)
                .map_err(|_| CodecError::InvalidUtf8)
        }
        ValueType::List(item) => {
            let pointer = cursor.take_i32()? as u32;
            let length =
                usize::try_from(cursor.take_i32()? as u32).map_err(|_| CodecError::ElementLimit)?;
            budget.elements(length)?;
            let layout = validate_type(item)?.layout;
            let size = layout
                .size
                .checked_mul(length)
                .ok_or(CodecError::ByteLimit)?;
            budget.bytes(size)?;
            span_size(memory, pointer, size, layout.alignment)?;
            let mut values = Vec::new();
            if length != 0 {
                budget.allocation()?;
            }
            values
                .try_reserve_exact(length)
                .map_err(|_| CodecError::Allocation)?;
            for index in 0..length {
                values.push(lift_at(
                    memory,
                    binder,
                    item,
                    indexed(pointer, index, layout.size)?,
                    position,
                    depth + 1,
                    false,
                    budget,
                )?);
            }
            Ok(CanonicalValue::List(values))
        }
        ValueType::Tuple(types) | ValueType::Record(types) => {
            let mut values = Vec::new();
            if !types.is_empty() {
                budget.allocation()?;
            }
            values
                .try_reserve_exact(types.len())
                .map_err(|_| CodecError::Allocation)?;
            for ty in types {
                values.push(lift_flat_value(
                    memory,
                    binder,
                    ty,
                    cursor,
                    position,
                    depth + 1,
                    budget,
                )?);
            }
            Ok(if matches!(ty, ValueType::Tuple(_)) {
                CanonicalValue::Tuple(values)
            } else {
                CanonicalValue::Record(values)
            })
        }
        ValueType::Flags(count) => {
            let word_count = count.checked_add(31).ok_or(CodecError::InvalidFlags)? / 32;
            let mut words = Vec::new();
            if word_count != 0 {
                budget.allocation()?;
            }
            words
                .try_reserve_exact(word_count as usize)
                .map_err(|_| CodecError::Allocation)?;
            for _ in 0..word_count {
                words.push(cursor.take_i32()? as u32);
            }
            if let Some(last) = words.last() {
                let used = count % 32;
                if used != 0 && *last >> used != 0 {
                    return Err(CodecError::InvalidFlags);
                }
            }
            Ok(CanonicalValue::Flags(words))
        }
        ValueType::Enum(cases) => {
            let case = cursor.take_i32()? as u32;
            if case >= *cases {
                return Err(CodecError::InvalidDiscriminant);
            }
            Ok(CanonicalValue::Enum(case))
        }
        ValueType::Option(inner) => {
            let (case, payload) = lift_flat_variant(
                memory,
                binder,
                [None, Some(inner.as_ref())],
                cursor,
                position,
                depth,
                budget,
            )?;
            Ok(CanonicalValue::Option(if case == 0 {
                None
            } else {
                payload
            }))
        }
        ValueType::Result { ok, error } => {
            let (case, payload) = lift_flat_variant(
                memory,
                binder,
                [ok.as_deref(), error.as_deref()],
                cursor,
                position,
                depth,
                budget,
            )?;
            Ok(CanonicalValue::Result(if case == 0 {
                Ok(payload)
            } else {
                Err(payload)
            }))
        }
        ValueType::Variant(cases) => {
            let (case, payload) = lift_flat_variant(
                memory,
                binder,
                cases.iter().map(Option::as_ref),
                cursor,
                position,
                depth,
                budget,
            )?;
            Ok(CanonicalValue::Variant { case, payload })
        }
        ValueType::Resource {
            resource_type,
            ownership,
        } => binder
            .bind(
                cursor.take_i32()? as u32,
                *resource_type,
                *ownership,
                position,
            )
            .map(CanonicalValue::Resource),
        ValueType::Stream { .. } | ValueType::Future { .. } => Err(CodecError::Unsupported),
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_flat_variant<'a, M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
    cursor: &mut CandidateFlatCursor<'_>,
    position: ValuePosition,
    depth: u32,
    budget: &mut Budget,
) -> Result<(u32, Option<Box<CanonicalValue>>), CodecError> {
    let mut cases_vec = Vec::new();
    for case in cases {
        cases_vec
            .try_reserve(1)
            .map_err(|_| CodecError::Allocation)?;
        cases_vec.push(case);
    }
    let case = cursor.take_i32()? as u32;
    let selected = cases_vec
        .get(case as usize)
        .ok_or(CodecError::InvalidDiscriminant)?;

    let mut joined = Vec::new();
    append_variant_flat(cases_vec.iter().copied(), &mut joined)?;
    let mut joined_values = Vec::new();
    joined_values
        .try_reserve_exact(joined.len().saturating_sub(1))
        .map_err(|_| CodecError::Allocation)?;
    for kind in joined.iter().skip(1).copied() {
        joined_values.push(cursor.take(kind)?);
    }

    let Some(selected) = selected else {
        return Ok((case, None));
    };
    let mut selected_signature = Vec::new();
    append_flat_types(selected, &mut selected_signature)?;
    let mut selected_values = Vec::new();
    selected_values
        .try_reserve_exact(selected_signature.len())
        .map_err(|_| CodecError::Allocation)?;
    for (index, kind) in selected_signature.iter().copied().enumerate() {
        let joined_value = joined_values
            .get(index)
            .copied()
            .ok_or(CodecError::FlatLimit)?;
        selected_values.push(uncoerce_flat(joined_value, kind)?);
    }
    let mut selected_cursor = CandidateFlatCursor::new(&selected_values);
    let value = lift_flat_value(
        memory,
        binder,
        selected,
        &mut selected_cursor,
        position,
        depth + 1,
        budget,
    )?;
    if !selected_cursor.is_empty() {
        return Err(CodecError::FlatLimit);
    }
    budget.allocation()?;
    Ok((case, Some(try_box(value)?)))
}

fn flatten_value<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: &ValueType,
    value: &CanonicalValue,
    depth: u32,
    output: &mut Vec<CandidateFlatValue>,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    budget.enter(depth)?;
    match (ty, value) {
        (ValueType::Bool, CanonicalValue::Bool(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U8, CanonicalValue::U8(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U16, CanonicalValue::U16(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U32, CanonicalValue::U32(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(*value as i32))
        }
        (ValueType::S8, CanonicalValue::S8(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::S16, CanonicalValue::S16(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::S32, CanonicalValue::S32(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(*value))
        }
        (ValueType::U64, CanonicalValue::U64(value)) => {
            push_flat_value(output, CandidateFlatValue::I64(*value as i64))
        }
        (ValueType::S64, CanonicalValue::S64(value)) => {
            push_flat_value(output, CandidateFlatValue::I64(*value))
        }
        (ValueType::F32, CanonicalValue::F32(value)) => {
            push_flat_value(output, CandidateFlatValue::F32Bits(value.to_bits()))
        }
        (ValueType::F64, CanonicalValue::F64(value)) => {
            push_flat_value(output, CandidateFlatValue::F64Bits(value.to_bits()))
        }
        (ValueType::Char, CanonicalValue::Char(value)) => {
            push_flat_value(output, CandidateFlatValue::I32(*value as i32))
        }
        (ValueType::String, CanonicalValue::String(value)) => {
            let pointer = allocate_payload(memory, allocator, value.len(), 1, budget)?;
            if !value.is_empty() {
                memory.write_exact(pointer, value.as_bytes())?;
            }
            push_flat_value(output, CandidateFlatValue::I32(pointer as i32))?;
            push_flat_value(output, CandidateFlatValue::I32(value.len() as i32))
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            budget.elements(values.len())?;
            let layout = validate_type(item)?.layout;
            let size = layout
                .size
                .checked_mul(values.len())
                .ok_or(CodecError::ByteLimit)?;
            let pointer = allocate_payload(memory, allocator, size, layout.alignment, budget)?;
            for (index, value) in values.iter().enumerate() {
                lower_at(
                    memory,
                    allocator,
                    item,
                    value,
                    indexed(pointer, index, layout.size)?,
                    depth + 1,
                    false,
                    budget,
                )?;
            }
            push_flat_value(output, CandidateFlatValue::I32(pointer as i32))?;
            push_flat_value(output, CandidateFlatValue::I32(values.len() as i32))
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            for (ty, value) in types.iter().zip(values) {
                flatten_value(memory, allocator, ty, value, depth + 1, output, budget)?;
            }
            Ok(())
        }
        (ValueType::Flags(_), CanonicalValue::Flags(words)) => {
            for word in words {
                push_flat_value(output, CandidateFlatValue::I32(*word as i32))?;
            }
            Ok(())
        }
        (ValueType::Enum(_), CanonicalValue::Enum(case)) => {
            push_flat_value(output, CandidateFlatValue::I32(*case as i32))
        }
        (ValueType::Resource { .. }, CanonicalValue::Resource(token)) => {
            push_flat_value(output, CandidateFlatValue::I32(token.guest_index() as i32))
        }
        (ValueType::Option(inner), CanonicalValue::Option(value)) => {
            let selected = value.as_deref().map(|value| (inner.as_ref(), value));
            flatten_variant(
                memory,
                allocator,
                [None, Some(inner.as_ref())],
                u32::from(value.is_some()),
                selected,
                depth,
                output,
                budget,
            )
        }
        (ValueType::Result { ok, error }, CanonicalValue::Result(result)) => match result {
            Ok(value) => flatten_variant(
                memory,
                allocator,
                [ok.as_deref(), error.as_deref()],
                0,
                ok.as_deref().zip(value.as_deref()),
                depth,
                output,
                budget,
            ),
            Err(value) => flatten_variant(
                memory,
                allocator,
                [ok.as_deref(), error.as_deref()],
                1,
                error.as_deref().zip(value.as_deref()),
                depth,
                output,
                budget,
            ),
        },
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let selected_ty = cases.get(*case as usize).and_then(Option::as_ref);
            flatten_variant(
                memory,
                allocator,
                cases.iter().map(Option::as_ref),
                *case,
                selected_ty.zip(payload.as_deref()),
                depth,
                output,
                budget,
            )
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

#[allow(clippy::too_many_arguments)]
fn flatten_variant<'a, M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
    discriminant: u32,
    selected: Option<(&'a ValueType, &'a CanonicalValue)>,
    depth: u32,
    output: &mut Vec<CandidateFlatValue>,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    let cases: Vec<Option<&ValueType>> = {
        let mut values = Vec::new();
        for case in cases {
            values.try_reserve(1).map_err(|_| CodecError::Allocation)?;
            values.push(case);
        }
        values
    };
    let mut joined = Vec::new();
    append_variant_flat(cases.iter().copied(), &mut joined)?;
    push_flat_value(output, CandidateFlatValue::I32(discriminant as i32))?;
    let payload_kinds = &joined[1..];
    let mut raw = Vec::new();
    if let Some((ty, value)) = selected {
        flatten_value(memory, allocator, ty, value, depth + 1, &mut raw, budget)?;
    }
    if raw.len() > payload_kinds.len() {
        return Err(CodecError::FlatLimit);
    }
    for (index, kind) in payload_kinds.iter().copied().enumerate() {
        let value = raw
            .get(index)
            .copied()
            .unwrap_or_else(|| CandidateFlatValue::zero(kind));
        push_flat_value(output, coerce_flat(value, kind)?)?;
    }
    Ok(())
}

fn coerce_flat(
    value: CandidateFlatValue,
    target: CandidateFlatKind,
) -> Result<CandidateFlatValue, CodecError> {
    if value.kind() == target {
        return Ok(value);
    }
    match (value, target) {
        (CandidateFlatValue::F32Bits(bits), CandidateFlatKind::I32) => {
            Ok(CandidateFlatValue::I32(bits as i32))
        }
        (CandidateFlatValue::I32(value), CandidateFlatKind::F32) => {
            Ok(CandidateFlatValue::F32Bits(value as u32))
        }
        (CandidateFlatValue::I32(value), CandidateFlatKind::I64) => {
            Ok(CandidateFlatValue::I64(i64::from(value as u32)))
        }
        (CandidateFlatValue::F32Bits(bits), CandidateFlatKind::I64) => {
            Ok(CandidateFlatValue::I64(i64::from(bits)))
        }
        (CandidateFlatValue::F64Bits(bits), CandidateFlatKind::I64) => {
            Ok(CandidateFlatValue::I64(bits as i64))
        }
        (CandidateFlatValue::I64(value), CandidateFlatKind::F64) => {
            Ok(CandidateFlatValue::F64Bits(value as u64))
        }
        (CandidateFlatValue::I64(value), CandidateFlatKind::I32) => {
            Ok(CandidateFlatValue::I32(value as i32))
        }
        (CandidateFlatValue::I64(value), CandidateFlatKind::F32) => {
            Ok(CandidateFlatValue::F32Bits(value as u32))
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

fn uncoerce_flat(
    value: CandidateFlatValue,
    target: CandidateFlatKind,
) -> Result<CandidateFlatValue, CodecError> {
    coerce_flat(value, target)
}

fn push_flat_value(
    output: &mut Vec<CandidateFlatValue>,
    value: CandidateFlatValue,
) -> Result<(), CodecError> {
    if output.len() >= PROFILE_1_LIMITS.max_canonical_values as usize {
        return Err(CodecError::FlatLimit);
    }
    output.try_reserve(1).map_err(|_| CodecError::Allocation)?;
    output.push(value);
    Ok(())
}

fn flatten_value_prepared(
    ty: &ValueType,
    value: &CanonicalValue,
    depth: u32,
    output: &mut Vec<CandidateFlatValue>,
    output_limit: usize,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    budget.enter(depth)?;
    let scalar = match (ty, value) {
        (ValueType::Bool, CanonicalValue::Bool(value)) => {
            Some(CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U8, CanonicalValue::U8(value)) => {
            Some(CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U16, CanonicalValue::U16(value)) => {
            Some(CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::U32, CanonicalValue::U32(value)) => {
            Some(CandidateFlatValue::I32(*value as i32))
        }
        (ValueType::S8, CanonicalValue::S8(value)) => {
            Some(CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::S16, CanonicalValue::S16(value)) => {
            Some(CandidateFlatValue::I32(i32::from(*value)))
        }
        (ValueType::S32, CanonicalValue::S32(value)) => Some(CandidateFlatValue::I32(*value)),
        (ValueType::U64, CanonicalValue::U64(value)) => {
            Some(CandidateFlatValue::I64(*value as i64))
        }
        (ValueType::S64, CanonicalValue::S64(value)) => Some(CandidateFlatValue::I64(*value)),
        (ValueType::F32, CanonicalValue::F32(value)) => {
            Some(CandidateFlatValue::F32Bits(value.to_bits()))
        }
        (ValueType::F64, CanonicalValue::F64(value)) => {
            Some(CandidateFlatValue::F64Bits(value.to_bits()))
        }
        (ValueType::Char, CanonicalValue::Char(value)) => {
            Some(CandidateFlatValue::I32(*value as i32))
        }
        (ValueType::Enum(_), CanonicalValue::Enum(case)) => {
            Some(CandidateFlatValue::I32(*case as i32))
        }
        (ValueType::Resource { .. }, CanonicalValue::Resource(token)) => {
            Some(CandidateFlatValue::I32(token.guest_index() as i32))
        }
        (ValueType::String, CanonicalValue::String(_))
        | (ValueType::List(_), CanonicalValue::List(_)) => return Err(CodecError::FlatLimit),
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            for (ty, value) in types.iter().zip(values) {
                flatten_value_prepared(ty, value, depth + 1, output, output_limit, budget)?;
            }
            None
        }
        (ValueType::Flags(_), CanonicalValue::Flags(words)) => {
            for word in words {
                push_prepared(output, output_limit, CandidateFlatValue::I32(*word as i32))?;
            }
            None
        }
        (ValueType::Option(inner), CanonicalValue::Option(selected)) => {
            push_prepared(
                output,
                output_limit,
                CandidateFlatValue::I32(i32::from(selected.is_some())),
            )?;
            if let Some(selected) = selected.as_deref() {
                flatten_value_prepared(inner, selected, depth + 1, output, output_limit, budget)?;
            }
            None
        }
        (ValueType::Result { ok, error }, CanonicalValue::Result(selected)) => {
            let (discriminant, ty, value) = match selected {
                Ok(value) => (0, ok.as_deref(), value.as_deref()),
                Err(value) => (1, error.as_deref(), value.as_deref()),
            };
            push_prepared(output, output_limit, CandidateFlatValue::I32(discriminant))?;
            if let (Some(ty), Some(value)) = (ty, value) {
                flatten_value_prepared(ty, value, depth + 1, output, output_limit, budget)?;
            }
            None
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            push_prepared(output, output_limit, CandidateFlatValue::I32(*case as i32))?;
            if let (Some(ty), Some(value)) = (
                cases.get(*case as usize).and_then(Option::as_ref),
                payload.as_deref(),
            ) {
                flatten_value_prepared(ty, value, depth + 1, output, output_limit, budget)?;
            }
            None
        }
        _ => return Err(CodecError::TypeMismatch),
    };
    if let Some(value) = scalar {
        push_prepared(output, output_limit, value)?;
    }
    Ok(())
}

fn push_prepared(
    output: &mut Vec<CandidateFlatValue>,
    output_limit: usize,
    value: CandidateFlatValue,
) -> Result<(), CodecError> {
    if output.len() >= output_limit || output.len() >= output.capacity() {
        return Err(CodecError::FlatLimit);
    }
    output.push(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::VecMemory;
    use alloc::{boxed::Box, vec};

    struct NoAlloc;

    impl PayloadAllocator<VecMemory> for NoAlloc {
        fn allocate(
            &mut self,
            _memory: &mut VecMemory,
            _size: u32,
            _alignment: u32,
        ) -> Result<u32, CodecError> {
            Err(CodecError::Allocation)
        }
    }

    #[test]
    fn scalar_nan_lift_is_canonical_and_lower_is_bit_only() {
        let memory = VecMemory::new(64, 64).unwrap();
        let (values, _) = lift_flat_values(
            &memory,
            &RejectResources,
            &[ValueType::F32, ValueType::F64],
            &[
                CandidateFlatValue::F32Bits(0xff80_0001),
                CandidateFlatValue::F64Bits(0xfff0_0000_0000_0001),
            ],
            ValuePosition::Parameter,
        )
        .unwrap();
        assert_eq!(
            values,
            vec![
                CanonicalValue::F32(CanonicalF32::from_bits(0x7fc0_0000)),
                CanonicalValue::F64(CanonicalF64::from_bits(0x7ff8_0000_0000_0000)),
            ]
        );
        let (flat, _) = lower_flat_values(
            &mut VecMemory::new(64, 64).unwrap(),
            &mut NoAlloc,
            &[ValueType::F32, ValueType::F64],
            &values,
        )
        .unwrap();
        assert_eq!(
            flat,
            vec![
                CandidateFlatValue::F32Bits(0x7fc0_0000),
                CandidateFlatValue::F64Bits(0x7ff8_0000_0000_0000),
            ]
        );
    }

    #[test]
    fn variant_join_and_bit_coercion_follow_canonical_abi() {
        assert_eq!(
            flat_signature(&[ValueType::Option(Box::new(ValueType::F32))]).unwrap(),
            vec![CandidateFlatKind::I32, CandidateFlatKind::F32]
        );
        let ty = ValueType::Variant(vec![
            Some(ValueType::F32),
            Some(ValueType::S32),
            Some(ValueType::F64),
        ]);
        assert_eq!(
            flat_signature(&[ty]).unwrap(),
            vec![CandidateFlatKind::I32, CandidateFlatKind::I64]
        );
        assert_eq!(
            coerce_flat(
                CandidateFlatValue::F32Bits(0x8000_0000),
                CandidateFlatKind::I64
            ),
            Ok(CandidateFlatValue::I64(0x8000_0000))
        );
        assert_eq!(
            uncoerce_flat(CandidateFlatValue::I64(0x8000_0000), CandidateFlatKind::F32),
            Ok(CandidateFlatValue::F32Bits(0x8000_0000))
        );
    }

    #[test]
    fn nested_streams_remain_unsupported() {
        let ty = ValueType::List(Box::new(ValueType::Stream {
            type_id: crate::value::AsyncValueTypeId::new(1).unwrap(),
            element: None,
        }));
        assert_eq!(flat_signature(&[ty]), Err(CodecError::Unsupported));
    }
}
