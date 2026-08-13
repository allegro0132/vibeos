//! Memory32 Canonical ABI codec for Profile-1 rich values.
//!
//! The codec never retains a guest-memory reference. Every pointer, length,
//! alignment, discriminant, UTF-8 string, flag word, and resource position is
//! rechecked at the point of use. Dynamic string/list storage is obtained only
//! through [`PayloadAllocator`], allowing the caller to make lowering atomic
//! and poison/tear down the instance if a partial lower fails.

use crate::{
    memory::{checked_span, AbiError, GuestMemory},
    resource::{ResourceToken, ResourceTypeId},
    value::{
        validate_type, validate_value, CanonicalLayout, CanonicalValue, ResourceOwnership,
        ValueError, ValuePosition, ValueType,
    },
};
use alloc::{alloc::alloc, boxed::Box, string::String, vec::Vec};
use core::{alloc::Layout, ptr::NonNull};
use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_wasm_runtime::CoreValue;

pub const MAX_FLAT_PARAMS: usize = 16;
pub const MAX_FLAT_RESULTS: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CodecError {
    TypeMismatch = 2,
    Memory = 3,
    OutOfBounds = 4,
    Misaligned = 5,
    InvalidBool = 6,
    InvalidChar = 7,
    InvalidUtf8 = 8,
    InvalidDiscriminant = 9,
    InvalidFlags = 10,
    ElementLimit = 11,
    ByteLimit = 12,
    NestingLimit = 13,
    ValueLimit = 14,
    AllocationLimit = 15,
    Allocation = 16,
    BorrowEscape = 17,
    Overflow = 18,
    ResourceBinding = 19,
    FlatLimit = 20,
}

impl CodecError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

impl From<ValueError> for CodecError {
    fn from(error: ValueError) -> Self {
        match error {
            ValueError::TypeMismatch => Self::TypeMismatch,
            ValueError::InvalidDiscriminant => Self::InvalidDiscriminant,
            ValueError::InvalidFlags => Self::InvalidFlags,
            ValueError::NestingLimit => Self::NestingLimit,
            ValueError::ValueLimit => Self::ValueLimit,
            ValueError::ByteLimit => Self::ByteLimit,
            ValueError::ListLimit => Self::ElementLimit,
            ValueError::Allocation => Self::Allocation,
            ValueError::BorrowEscape => Self::BorrowEscape,
            ValueError::Resource => Self::ResourceBinding,
        }
    }
}

impl From<AbiError> for CodecError {
    fn from(error: AbiError) -> Self {
        match error {
            AbiError::Misaligned => Self::Misaligned,
            AbiError::OutOfBounds => Self::OutOfBounds,
            AbiError::InvalidBool => Self::InvalidBool,
            AbiError::InvalidChar => Self::InvalidChar,
            AbiError::InvalidUtf8 => Self::InvalidUtf8,
            AbiError::InvalidDiscriminant => Self::InvalidDiscriminant,
            AbiError::ElementLimit => Self::ElementLimit,
            AbiError::LengthLimit => Self::ByteLimit,
            AbiError::Overflow => Self::Overflow,
            AbiError::AllocationLimit => Self::AllocationLimit,
            _ => Self::Memory,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodecUsage {
    pub nodes: u32,
    pub bytes: usize,
    pub list_elements: u32,
    pub allocations: u32,
    pub max_depth: u32,
    pub work: u64,
}

#[derive(Default)]
struct Budget {
    usage: CodecUsage,
    allocations: Vec<AllocationSpan>,
    protected: Option<AllocationSpan>,
}

#[derive(Clone, Copy)]
struct AllocationSpan {
    start: u32,
    size: u32,
}

impl Budget {
    fn enter(&mut self, depth: u32) -> Result<(), CodecError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(CodecError::NestingLimit);
        }
        self.usage.nodes = self
            .usage
            .nodes
            .checked_add(1)
            .ok_or(CodecError::ValueLimit)?;
        if self.usage.nodes > PROFILE_1_LIMITS.max_canonical_values {
            return Err(CodecError::ValueLimit);
        }
        self.usage.max_depth = self.usage.max_depth.max(depth);
        self.usage.work = self
            .usage
            .work
            .checked_add(1)
            .ok_or(CodecError::ValueLimit)?;
        Ok(())
    }

    fn bytes(&mut self, amount: usize) -> Result<(), CodecError> {
        self.usage.bytes = self
            .usage
            .bytes
            .checked_add(amount)
            .ok_or(CodecError::ByteLimit)?;
        if self.usage.bytes > PROFILE_1_LIMITS.max_canonical_value_bytes {
            return Err(CodecError::ByteLimit);
        }
        self.usage.work = self
            .usage
            .work
            .checked_add(u64::try_from(amount).map_err(|_| CodecError::ByteLimit)?)
            .ok_or(CodecError::ByteLimit)?;
        Ok(())
    }

    fn elements(&mut self, amount: usize) -> Result<(), CodecError> {
        let amount = u32::try_from(amount).map_err(|_| CodecError::ElementLimit)?;
        self.usage.list_elements = self
            .usage
            .list_elements
            .checked_add(amount)
            .ok_or(CodecError::ElementLimit)?;
        if self.usage.list_elements > PROFILE_1_LIMITS.max_list_elements {
            return Err(CodecError::ElementLimit);
        }
        Ok(())
    }

    fn allocation(&mut self) -> Result<(), CodecError> {
        self.usage.allocations = self
            .usage
            .allocations
            .checked_add(1)
            .ok_or(CodecError::AllocationLimit)?;
        if self.usage.allocations > PROFILE_1_LIMITS.max_abi_allocations {
            return Err(CodecError::AllocationLimit);
        }
        Ok(())
    }

    fn protect(&mut self, pointer: u32, size: usize) -> Result<(), CodecError> {
        if size == 0 {
            return Ok(());
        }
        self.protected = Some(AllocationSpan {
            start: pointer,
            size: u32::try_from(size).map_err(|_| CodecError::ByteLimit)?,
        });
        Ok(())
    }

    fn record_allocation(&mut self, pointer: u32, size: u32) -> Result<(), CodecError> {
        let candidate = AllocationSpan {
            start: pointer,
            size,
        };
        if self
            .protected
            .into_iter()
            .chain(self.allocations.iter().copied())
            .any(|existing| spans_overlap(existing, candidate))
        {
            return Err(CodecError::Allocation);
        }
        if self.allocations.len() == self.allocations.capacity() {
            return Err(CodecError::Allocation);
        }
        self.allocations.push(candidate);
        Ok(())
    }
}

fn spans_overlap(left: AllocationSpan, right: AllocationSpan) -> bool {
    let left_start = u64::from(left.start);
    let left_end = left_start + u64::from(left.size);
    let right_start = u64::from(right.start);
    let right_end = right_start + u64::from(right.size);
    left_start < right_end && right_start < left_end
}

/// Supplies nested string/list storage. Implementations must return a span of
/// at least `size` bytes at `alignment`, or an error. The caller may journal a
/// partial lower for failure teardown, but must not automatically free
/// successful argument lowering: guest realloc owns that storage. Lifted
/// results are released by the component's `post-return`, not this codec.
/// `size == 0` is represented by pointer zero and never calls this trait.
pub trait PayloadAllocator<M: GuestMemory> {
    fn allocate(&mut self, memory: &mut M, size: u32, alignment: u32) -> Result<u32, CodecError>;
}

/// Rebinds an untrusted resource integer to the exact component instance.
pub trait ResourceBinder {
    fn bind(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
        ownership: ResourceOwnership,
        position: ValuePosition,
    ) -> Result<ResourceToken, CodecError>;
}

impl<F> ResourceBinder for F
where
    F: Fn(
        u32,
        ResourceTypeId,
        ResourceOwnership,
        ValuePosition,
    ) -> Result<ResourceToken, CodecError>,
{
    fn bind(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
        ownership: ResourceOwnership,
        position: ValuePosition,
    ) -> Result<ResourceToken, CodecError> {
        self(guest_index, expected, ownership, position)
    }
}

pub struct RejectResources;

impl ResourceBinder for RejectResources {
    fn bind(
        &self,
        _guest_index: u32,
        _expected: ResourceTypeId,
        _ownership: ResourceOwnership,
        _position: ValuePosition,
    ) -> Result<ResourceToken, CodecError> {
        Err(CodecError::ResourceBinding)
    }
}

/// Lowers one value into its exact memory32 Canonical ABI representation.
pub fn lower_value<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: &ValueType,
    value: &CanonicalValue,
    pointer: u32,
    position: ValuePosition,
) -> Result<CodecUsage, CodecError> {
    validate_type(ty)?;
    validate_value(ty, value)?;
    validate_position(ty, position)?;
    let mut budget = Budget::default();
    budget.protect(pointer, validate_type(ty)?.layout.size)?;
    lower_at(memory, allocator, ty, value, pointer, 1, true, &mut budget)?;
    Ok(budget.usage)
}

/// Lifts one value, using only fallible host allocation, from hostile memory.
pub fn lift_value<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: &ValueType,
    pointer: u32,
    position: ValuePosition,
) -> Result<(CanonicalValue, CodecUsage), CodecError> {
    validate_type(ty)?;
    validate_position(ty, position)?;
    let mut budget = Budget::default();
    let value = lift_at(memory, binder, ty, pointer, position, 1, true, &mut budget)?;
    validate_value(ty, &value)?;
    Ok((value, budget.usage))
}

#[allow(clippy::too_many_arguments)]
fn lower_at<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: &ValueType,
    value: &CanonicalValue,
    pointer: u32,
    depth: u32,
    charge_flat: bool,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    budget.enter(depth)?;
    let layout = validate_type(ty)?.layout;
    span(memory, pointer, layout)?;
    if charge_flat {
        budget.bytes(layout.size)?;
    }
    zero(memory, pointer, layout.size)?;
    match (ty, value) {
        (ValueType::Bool, CanonicalValue::Bool(value)) => {
            write_u8(memory, pointer, u8::from(*value))
        }
        (ValueType::U8, CanonicalValue::U8(value)) => write_u8(memory, pointer, *value),
        (ValueType::S8, CanonicalValue::S8(value)) => write_u8(memory, pointer, *value as u8),
        (ValueType::U16, CanonicalValue::U16(value)) => write_u16(memory, pointer, *value),
        (ValueType::S16, CanonicalValue::S16(value)) => write_u16(memory, pointer, *value as u16),
        (ValueType::U32, CanonicalValue::U32(value)) => write_u32(memory, pointer, *value),
        (ValueType::S32, CanonicalValue::S32(value)) => write_u32(memory, pointer, *value as u32),
        (ValueType::U64, CanonicalValue::U64(value)) => write_u64(memory, pointer, *value),
        (ValueType::S64, CanonicalValue::S64(value)) => write_u64(memory, pointer, *value as u64),
        (ValueType::Char, CanonicalValue::Char(value)) => {
            write_u32(memory, pointer, u32::from(*value))
        }
        (ValueType::String, CanonicalValue::String(value)) => {
            if value.len() > PROFILE_1_LIMITS.max_string_bytes {
                return Err(CodecError::ByteLimit);
            }
            let payload = allocate_payload(memory, allocator, value.len(), 1, budget)?;
            if !value.is_empty() {
                memory.write_exact(payload, value.as_bytes())?;
            }
            write_pair(memory, pointer, payload, value.len())
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            budget.elements(values.len())?;
            let item_layout = validate_type(item)?.layout;
            let payload_size = item_layout
                .size
                .checked_mul(values.len())
                .ok_or(CodecError::ByteLimit)?;
            let payload = allocate_payload(
                memory,
                allocator,
                payload_size,
                item_layout.alignment,
                budget,
            )?;
            for (index, value) in values.iter().enumerate() {
                lower_at(
                    memory,
                    allocator,
                    item,
                    value,
                    indexed(payload, index, item_layout.size)?,
                    depth + 1,
                    false,
                    budget,
                )?;
            }
            write_pair(memory, pointer, payload, values.len())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            lower_fields(memory, allocator, types, values, pointer, depth, budget)
        }
        (ValueType::Flags(count), CanonicalValue::Flags(words)) => {
            write_flags(memory, pointer, *count, words)
        }
        (ValueType::Enum(cases), CanonicalValue::Enum(case)) => {
            write_discriminant(memory, pointer, *cases, *case)
        }
        (ValueType::Option(inner), CanonicalValue::Option(value)) => {
            write_discriminant(memory, pointer, 2, u32::from(value.is_some()))?;
            if let Some(value) = value {
                let payload =
                    variant_payload_pointer(pointer, 2, validate_type(inner)?.layout.alignment)?;
                lower_at(
                    memory,
                    allocator,
                    inner,
                    value,
                    payload,
                    depth + 1,
                    false,
                    budget,
                )?;
            }
            Ok(())
        }
        (ValueType::Result { ok, error }, CanonicalValue::Result(Ok(value))) => {
            write_discriminant(memory, pointer, 2, 0)?;
            let payload_alignment = optional_union_alignment([ok.as_deref(), error.as_deref()])?;
            lower_optional(
                memory,
                allocator,
                ok.as_deref(),
                value.as_deref(),
                pointer,
                payload_alignment,
                depth,
                budget,
            )
        }
        (ValueType::Result { ok, error }, CanonicalValue::Result(Err(value))) => {
            write_discriminant(memory, pointer, 2, 1)?;
            let payload_alignment = optional_union_alignment([ok.as_deref(), error.as_deref()])?;
            lower_optional(
                memory,
                allocator,
                error.as_deref(),
                value.as_deref(),
                pointer,
                payload_alignment,
                depth,
                budget,
            )
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            write_discriminant(memory, pointer, cases.len() as u32, *case)?;
            let expected = cases
                .get(*case as usize)
                .ok_or(CodecError::InvalidDiscriminant)?;
            let payload_alignment = optional_union_alignment(cases.iter().map(Option::as_ref))?;
            lower_optional(
                memory,
                allocator,
                expected.as_ref(),
                payload.as_deref(),
                pointer,
                payload_alignment,
                depth,
                budget,
            )
        }
        (ValueType::Resource { .. }, CanonicalValue::Resource(token)) => {
            write_u32(memory, pointer, token.guest_index())
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_at<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: &ValueType,
    pointer: u32,
    position: ValuePosition,
    depth: u32,
    charge_flat: bool,
    budget: &mut Budget,
) -> Result<CanonicalValue, CodecError> {
    budget.enter(depth)?;
    let layout = validate_type(ty)?.layout;
    span(memory, pointer, layout)?;
    if charge_flat {
        budget.bytes(layout.size)?;
    }
    match ty {
        ValueType::Bool => match read_u8(memory, pointer)? {
            0 => Ok(CanonicalValue::Bool(false)),
            1 => Ok(CanonicalValue::Bool(true)),
            _ => Err(CodecError::InvalidBool),
        },
        ValueType::U8 => Ok(CanonicalValue::U8(read_u8(memory, pointer)?)),
        ValueType::S8 => Ok(CanonicalValue::S8(read_u8(memory, pointer)? as i8)),
        ValueType::U16 => Ok(CanonicalValue::U16(read_u16(memory, pointer)?)),
        ValueType::S16 => Ok(CanonicalValue::S16(read_u16(memory, pointer)? as i16)),
        ValueType::U32 => Ok(CanonicalValue::U32(read_u32(memory, pointer)?)),
        ValueType::S32 => Ok(CanonicalValue::S32(read_u32(memory, pointer)? as i32)),
        ValueType::U64 => Ok(CanonicalValue::U64(read_u64(memory, pointer)?)),
        ValueType::S64 => Ok(CanonicalValue::S64(read_u64(memory, pointer)? as i64)),
        ValueType::Char => char::from_u32(read_u32(memory, pointer)?)
            .map(CanonicalValue::Char)
            .ok_or(CodecError::InvalidChar),
        ValueType::String => {
            let (payload, length) = read_pair(memory, pointer)?;
            if length > PROFILE_1_LIMITS.max_string_bytes {
                return Err(CodecError::ByteLimit);
            }
            budget.bytes(length)?;
            if length != 0 {
                budget.allocation()?;
            }
            let bytes = read_vec(memory, payload, length, 1)?;
            String::from_utf8(bytes)
                .map(CanonicalValue::String)
                .map_err(|_| CodecError::InvalidUtf8)
        }
        ValueType::List(item) => {
            let (payload, length) = read_pair(memory, pointer)?;
            budget.elements(length)?;
            let item_layout = validate_type(item)?.layout;
            let payload_size = item_layout
                .size
                .checked_mul(length)
                .ok_or(CodecError::ByteLimit)?;
            budget.bytes(payload_size)?;
            span_size(memory, payload, payload_size, item_layout.alignment)?;
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
                    indexed(payload, index, item_layout.size)?,
                    position,
                    depth + 1,
                    false,
                    budget,
                )?);
            }
            Ok(CanonicalValue::List(values))
        }
        ValueType::Tuple(types) => {
            lift_fields(memory, binder, types, pointer, position, depth, budget)
                .map(CanonicalValue::Tuple)
        }
        ValueType::Record(types) => {
            lift_fields(memory, binder, types, pointer, position, depth, budget)
                .map(CanonicalValue::Record)
        }
        ValueType::Flags(count) => {
            read_flags(memory, pointer, *count, budget).map(CanonicalValue::Flags)
        }
        ValueType::Enum(cases) => {
            read_discriminant(memory, pointer, *cases).map(CanonicalValue::Enum)
        }
        ValueType::Option(inner) => match read_discriminant(memory, pointer, 2)? {
            0 => Ok(CanonicalValue::Option(None)),
            1 => {
                let payload =
                    variant_payload_pointer(pointer, 2, validate_type(inner)?.layout.alignment)?;
                let value = lift_at(
                    memory,
                    binder,
                    inner,
                    payload,
                    position,
                    depth + 1,
                    false,
                    budget,
                )?;
                budget.allocation()?;
                Ok(CanonicalValue::Option(Some(try_box(value)?)))
            }
            _ => Err(CodecError::InvalidDiscriminant),
        },
        ValueType::Result { ok, error } => match read_discriminant(memory, pointer, 2)? {
            case @ (0 | 1) => {
                let payload_alignment =
                    optional_union_alignment([ok.as_deref(), error.as_deref()])?;
                let selected = if case == 0 {
                    ok.as_deref()
                } else {
                    error.as_deref()
                };
                let value = lift_optional(
                    memory,
                    binder,
                    selected,
                    pointer,
                    payload_alignment,
                    position,
                    depth,
                    budget,
                )?;
                Ok(CanonicalValue::Result(if case == 0 {
                    Ok(value)
                } else {
                    Err(value)
                }))
            }
            _ => Err(CodecError::InvalidDiscriminant),
        },
        ValueType::Variant(cases) => {
            let case = read_discriminant(memory, pointer, cases.len() as u32)?;
            let payload_alignment = optional_union_alignment(cases.iter().map(Option::as_ref))?;
            let payload = lift_optional(
                memory,
                binder,
                cases[case as usize].as_ref(),
                pointer,
                payload_alignment,
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
                read_u32(memory, pointer)?,
                *resource_type,
                *ownership,
                position,
            )
            .map(CanonicalValue::Resource),
    }
}

fn lower_fields<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
    pointer: u32,
    depth: u32,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
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
            depth + 1,
            false,
            budget,
        )?;
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok(())
}

fn lift_fields<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    pointer: u32,
    position: ValuePosition,
    depth: u32,
    budget: &mut Budget,
) -> Result<Vec<CanonicalValue>, CodecError> {
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
            depth + 1,
            false,
            budget,
        )?);
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok(values)
}

#[allow(clippy::too_many_arguments)]
fn lower_optional<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: Option<&ValueType>,
    value: Option<&CanonicalValue>,
    pointer: u32,
    payload_alignment: usize,
    depth: u32,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => {
            let payload = variant_payload_pointer(pointer, 2, payload_alignment)?;
            lower_at(
                memory,
                allocator,
                ty,
                value,
                payload,
                depth + 1,
                false,
                budget,
            )
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_optional<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: Option<&ValueType>,
    pointer: u32,
    payload_alignment: usize,
    position: ValuePosition,
    depth: u32,
    budget: &mut Budget,
) -> Result<Option<Box<CanonicalValue>>, CodecError> {
    match ty {
        None => Ok(None),
        Some(ty) => {
            let payload = variant_payload_pointer(pointer, 2, payload_alignment)?;
            let value = lift_at(
                memory,
                binder,
                ty,
                payload,
                position,
                depth + 1,
                false,
                budget,
            )?;
            budget.allocation()?;
            Ok(Some(try_box(value)?))
        }
    }
}

fn allocate_payload<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    size: usize,
    alignment: usize,
    budget: &mut Budget,
) -> Result<u32, CodecError> {
    budget.bytes(size)?;
    if size == 0 {
        return Ok(0);
    }
    budget.allocation()?;
    // Reserve the host journal entry before invoking the guest allocator. Once
    // guest state can have changed, recording the returned span is infallible.
    budget
        .allocations
        .try_reserve(1)
        .map_err(|_| CodecError::Allocation)?;
    let size = u32::try_from(size).map_err(|_| CodecError::ByteLimit)?;
    let alignment = u32::try_from(alignment).map_err(|_| CodecError::Misaligned)?;
    let pointer = allocator.allocate(memory, size, alignment)?;
    span_size(memory, pointer, size as usize, alignment as usize)?;
    budget.record_allocation(pointer, size)?;
    Ok(pointer)
}

fn validate_position(ty: &ValueType, position: ValuePosition) -> Result<(), CodecError> {
    match ty {
        ValueType::Resource {
            ownership: ResourceOwnership::Borrow,
            ..
        } if position == ValuePosition::Result => Err(CodecError::BorrowEscape),
        ValueType::List(item) | ValueType::Option(item) => validate_position(item, position),
        ValueType::Tuple(types) | ValueType::Record(types) => {
            for ty in types {
                validate_position(ty, position)?;
            }
            Ok(())
        }
        ValueType::Result { ok, error } => {
            if let Some(ok) = ok {
                validate_position(ok, position)?;
            }
            if let Some(error) = error {
                validate_position(error, position)?;
            }
            Ok(())
        }
        ValueType::Variant(cases) => {
            for case in cases.iter().flatten() {
                validate_position(case, position)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlatKind {
    I32,
    I64,
}

/// Fallibly computes the Canonical ABI flat signature for a sequence of values.
pub fn flat_signature(types: &[ValueType]) -> Result<Vec<FlatKind>, CodecError> {
    let mut result = Vec::new();
    for ty in types {
        append_flat_types(ty, &mut result)?;
    }
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoweredParameters {
    Flat {
        values: Vec<CoreValue>,
        usage: CodecUsage,
    },
    Indirect {
        pointer: u32,
        arguments: [CoreValue; 1],
        usage: CodecUsage,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoweredResults {
    Flat {
        values: Vec<CoreValue>,
        usage: CodecUsage,
    },
    Retptr {
        pointer: u32,
        usage: CodecUsage,
    },
}

/// Lifts canonical parameters from either their flat Core representation or
/// the single indirect pointer required when the flat signature exceeds
/// [`MAX_FLAT_PARAMS`].
pub fn lift_parameters<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    arguments: &[CoreValue],
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_PARAMS {
        lift_flat_values(memory, binder, types, arguments, ValuePosition::Parameter)
    } else {
        let pointer = exact_pointer(arguments)?;
        lift_indirect_values(memory, binder, types, pointer, ValuePosition::Parameter)
    }
}

/// Lifts canonical results from either their flat Core representation or an
/// exact one-element `[i32(retptr)]` representation for multi-flat results.
pub fn lift_results<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    results: &[CoreValue],
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_RESULTS {
        lift_flat_values(memory, binder, types, results, ValuePosition::Result)
    } else {
        let pointer = exact_pointer(results)?;
        lift_indirect_values(memory, binder, types, pointer, ValuePosition::Result)
    }
}

/// Lifts a sequence from an exact indirect memory32 layout.
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

/// Lifts a sequence from an exact flat Core signature.
pub fn lift_flat_values<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    types: &[ValueType],
    flat: &[CoreValue],
    position: ValuePosition,
) -> Result<(Vec<CanonicalValue>, CodecUsage), CodecError> {
    validate_type_sequence(types, position)?;
    let signature = flat_signature(types)?;
    if flat.len() != signature.len() {
        return Err(CodecError::FlatLimit);
    }
    for (value, expected) in flat.iter().zip(&signature) {
        if core_kind(*value) != *expected {
            return Err(CodecError::TypeMismatch);
        }
    }
    let mut budget = Budget::default();
    let mut values = Vec::new();
    if !types.is_empty() {
        budget.allocation()?;
    }
    values
        .try_reserve_exact(types.len())
        .map_err(|_| CodecError::Allocation)?;
    let mut cursor = FlatCursor::new(flat);
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

fn validate_type_sequence(types: &[ValueType], position: ValuePosition) -> Result<(), CodecError> {
    for ty in types {
        validate_type(ty)?;
        validate_position(ty, position)?;
    }
    Ok(())
}

fn exact_pointer(values: &[CoreValue]) -> Result<u32, CodecError> {
    match values {
        [CoreValue::I32(pointer)] => Ok(*pointer as u32),
        [_] => Err(CodecError::TypeMismatch),
        _ => Err(CodecError::FlatLimit),
    }
}

const fn core_kind(value: CoreValue) -> FlatKind {
    match value {
        CoreValue::I32(_) => FlatKind::I32,
        CoreValue::I64(_) => FlatKind::I64,
    }
}

struct FlatCursor<'a> {
    values: &'a [CoreValue],
    offset: usize,
}

impl<'a> FlatCursor<'a> {
    const fn new(values: &'a [CoreValue]) -> Self {
        Self { values, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.values.len()
    }

    fn take(&mut self, expected: FlatKind) -> Result<CoreValue, CodecError> {
        let value = self
            .values
            .get(self.offset)
            .copied()
            .ok_or(CodecError::FlatLimit)?;
        if core_kind(value) != expected {
            return Err(CodecError::TypeMismatch);
        }
        self.offset += 1;
        Ok(value)
    }

    fn take_i32(&mut self) -> Result<i32, CodecError> {
        match self.take(FlatKind::I32)? {
            CoreValue::I32(value) => Ok(value),
            CoreValue::I64(_) => Err(CodecError::TypeMismatch),
        }
    }

    fn take_i64(&mut self) -> Result<i64, CodecError> {
        match self.take(FlatKind::I64)? {
            CoreValue::I64(value) => Ok(value),
            CoreValue::I32(_) => Err(CodecError::TypeMismatch),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_flat_value<M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    ty: &ValueType,
    cursor: &mut FlatCursor<'_>,
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
        ValueType::U8 => {
            let value = cursor.take_i32()?;
            u8::try_from(value)
                .map(CanonicalValue::U8)
                .map_err(|_| CodecError::TypeMismatch)
        }
        ValueType::S8 => {
            let value = cursor.take_i32()?;
            i8::try_from(value)
                .map(CanonicalValue::S8)
                .map_err(|_| CodecError::TypeMismatch)
        }
        ValueType::U16 => {
            let value = cursor.take_i32()?;
            u16::try_from(value)
                .map(CanonicalValue::U16)
                .map_err(|_| CodecError::TypeMismatch)
        }
        ValueType::S16 => {
            let value = cursor.take_i32()?;
            i16::try_from(value)
                .map(CanonicalValue::S16)
                .map_err(|_| CodecError::TypeMismatch)
        }
        ValueType::U32 => Ok(CanonicalValue::U32(cursor.take_i32()? as u32)),
        ValueType::S32 => Ok(CanonicalValue::S32(cursor.take_i32()?)),
        ValueType::U64 => Ok(CanonicalValue::U64(cursor.take_i64()? as u64)),
        ValueType::S64 => Ok(CanonicalValue::S64(cursor.take_i64()?)),
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
    }
}

#[allow(clippy::too_many_arguments)]
fn lift_flat_variant<'a, M: GuestMemory, B: ResourceBinder>(
    memory: &M,
    binder: &B,
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
    cursor: &mut FlatCursor<'_>,
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
    let mut selected_cursor = FlatCursor::new(&selected_values);
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

fn uncoerce_flat(value: CoreValue, kind: FlatKind) -> Result<CoreValue, CodecError> {
    match (value, kind) {
        (CoreValue::I64(value), FlatKind::I32) => Ok(CoreValue::I32(value as i32)),
        (CoreValue::I32(value), FlatKind::I64) => Ok(CoreValue::I64(i64::from(value as u32))),
        (value, expected) if core_kind(value) == expected => Ok(value),
        _ => Err(CodecError::TypeMismatch),
    }
}

pub fn lower_parameters<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
) -> Result<LoweredParameters, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Parameter)?;
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_PARAMS {
        let mut budget = Budget::default();
        let mut flat = Vec::new();
        flat.try_reserve_exact(signature.len())
            .map_err(|_| CodecError::Allocation)?;
        for (ty, value) in types.iter().zip(values) {
            flatten_value(memory, allocator, ty, value, 1, &mut flat, &mut budget)?;
        }
        return Ok(LoweredParameters::Flat {
            values: flat,
            usage: budget.usage,
        });
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
            &mut budget,
        )?;
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok(LoweredParameters::Indirect {
        pointer,
        arguments: [CoreValue::I32(pointer as i32)],
        usage: budget.usage,
    })
}

pub fn lower_results<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    types: &[ValueType],
    values: &[CanonicalValue],
) -> Result<LoweredResults, CodecError> {
    if types.len() != values.len() {
        return Err(CodecError::TypeMismatch);
    }
    validate_sequence(types, values, ValuePosition::Result)?;
    let signature = flat_signature(types)?;
    if signature.len() <= MAX_FLAT_RESULTS {
        let mut budget = Budget::default();
        let mut flat = Vec::new();
        flat.try_reserve_exact(signature.len())
            .map_err(|_| CodecError::Allocation)?;
        for (ty, value) in types.iter().zip(values) {
            flatten_value(memory, allocator, ty, value, 1, &mut flat, &mut budget)?;
        }
        return Ok(LoweredResults::Flat {
            values: flat,
            usage: budget.usage,
        });
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
            &mut budget,
        )?;
        offset = offset.checked_add(field.size).ok_or(CodecError::Overflow)?;
    }
    Ok(LoweredResults::Retptr {
        pointer,
        usage: budget.usage,
    })
}

fn append_flat_types(ty: &ValueType, output: &mut Vec<FlatKind>) -> Result<(), CodecError> {
    validate_type(ty)?;
    match ty {
        ValueType::U64 | ValueType::S64 => push_flat(output, FlatKind::I64),
        ValueType::String | ValueType::List(_) => {
            push_flat(output, FlatKind::I32)?;
            push_flat(output, FlatKind::I32)
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
                push_flat(output, FlatKind::I32)?;
            }
            Ok(())
        }
        ValueType::Option(inner) => append_variant_flat([None, Some(inner.as_ref())], output),
        ValueType::Result { ok, error } => {
            append_variant_flat([ok.as_deref(), error.as_deref()], output)
        }
        ValueType::Variant(cases) => append_variant_flat(cases.iter().map(Option::as_ref), output),
        _ => push_flat(output, FlatKind::I32),
    }
}

fn validate_sequence(
    types: &[ValueType],
    values: &[CanonicalValue],
    position: ValuePosition,
) -> Result<(), CodecError> {
    for (ty, value) in types.iter().zip(values) {
        validate_type(ty)?;
        validate_value(ty, value)?;
        validate_position(ty, position)?;
    }
    Ok(())
}

fn append_variant_flat<'a>(
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
    output: &mut Vec<FlatKind>,
) -> Result<(), CodecError> {
    push_flat(output, FlatKind::I32)?;
    let mut joined = Vec::new();
    for case in cases {
        let mut shape = Vec::new();
        if let Some(case) = case {
            append_flat_types(case, &mut shape)?;
        }
        if shape.len() > joined.len() {
            joined
                .try_reserve_exact(shape.len() - joined.len())
                .map_err(|_| CodecError::Allocation)?;
            joined.resize(shape.len(), FlatKind::I32);
        }
        for (index, kind) in shape.into_iter().enumerate() {
            if kind == FlatKind::I64 {
                joined[index] = FlatKind::I64;
            }
        }
    }
    for kind in joined {
        push_flat(output, kind)?;
    }
    Ok(())
}

fn push_flat(output: &mut Vec<FlatKind>, value: FlatKind) -> Result<(), CodecError> {
    if output.len() >= PROFILE_1_LIMITS.max_canonical_values as usize {
        return Err(CodecError::FlatLimit);
    }
    output.try_reserve(1).map_err(|_| CodecError::Allocation)?;
    output.push(value);
    Ok(())
}

fn flatten_value<M: GuestMemory, A: PayloadAllocator<M>>(
    memory: &mut M,
    allocator: &mut A,
    ty: &ValueType,
    value: &CanonicalValue,
    depth: u32,
    output: &mut Vec<CoreValue>,
    budget: &mut Budget,
) -> Result<(), CodecError> {
    budget.enter(depth)?;
    match (ty, value) {
        (ValueType::Bool, CanonicalValue::Bool(value)) => {
            push_core(output, CoreValue::I32(i32::from(*value)))
        }
        (ValueType::U8, CanonicalValue::U8(value)) => {
            push_core(output, CoreValue::I32(i32::from(*value)))
        }
        (ValueType::U16, CanonicalValue::U16(value)) => {
            push_core(output, CoreValue::I32(i32::from(*value)))
        }
        (ValueType::U32, CanonicalValue::U32(value)) => {
            push_core(output, CoreValue::I32(*value as i32))
        }
        (ValueType::S8, CanonicalValue::S8(value)) => {
            push_core(output, CoreValue::I32(i32::from(*value)))
        }
        (ValueType::S16, CanonicalValue::S16(value)) => {
            push_core(output, CoreValue::I32(i32::from(*value)))
        }
        (ValueType::S32, CanonicalValue::S32(value)) => push_core(output, CoreValue::I32(*value)),
        (ValueType::U64, CanonicalValue::U64(value)) => {
            push_core(output, CoreValue::I64(*value as i64))
        }
        (ValueType::S64, CanonicalValue::S64(value)) => push_core(output, CoreValue::I64(*value)),
        (ValueType::Char, CanonicalValue::Char(value)) => {
            push_core(output, CoreValue::I32(*value as i32))
        }
        (ValueType::String, CanonicalValue::String(value)) => {
            let pointer = allocate_payload(memory, allocator, value.len(), 1, budget)?;
            if !value.is_empty() {
                memory.write_exact(pointer, value.as_bytes())?;
            }
            push_core(output, CoreValue::I32(pointer as i32))?;
            push_core(output, CoreValue::I32(value.len() as i32))
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
            push_core(output, CoreValue::I32(pointer as i32))?;
            push_core(output, CoreValue::I32(values.len() as i32))
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
                push_core(output, CoreValue::I32(*word as i32))?;
            }
            Ok(())
        }
        (ValueType::Enum(_), CanonicalValue::Enum(case)) => {
            push_core(output, CoreValue::I32(*case as i32))
        }
        (ValueType::Resource { .. }, CanonicalValue::Resource(token)) => {
            push_core(output, CoreValue::I32(token.guest_index() as i32))
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
    output: &mut Vec<CoreValue>,
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
    push_core(output, CoreValue::I32(discriminant as i32))?;
    let payload_kinds = &joined[1..];
    let mut raw = Vec::new();
    if let Some((ty, value)) = selected {
        flatten_value(memory, allocator, ty, value, depth + 1, &mut raw, budget)?;
    }
    for (index, kind) in payload_kinds.iter().copied().enumerate() {
        let value = raw.get(index).copied().unwrap_or(match kind {
            FlatKind::I32 => CoreValue::I32(0),
            FlatKind::I64 => CoreValue::I64(0),
        });
        push_core(output, coerce_flat(value, kind))?;
    }
    Ok(())
}

fn coerce_flat(value: CoreValue, kind: FlatKind) -> CoreValue {
    match (value, kind) {
        (CoreValue::I32(value), FlatKind::I64) => CoreValue::I64(i64::from(value as u32)),
        (CoreValue::I64(value), FlatKind::I32) => CoreValue::I32(value as i32),
        (value, _) => value,
    }
}

fn push_core(output: &mut Vec<CoreValue>, value: CoreValue) -> Result<(), CodecError> {
    if output.len() >= PROFILE_1_LIMITS.max_canonical_values as usize {
        return Err(CodecError::FlatLimit);
    }
    output.try_reserve(1).map_err(|_| CodecError::Allocation)?;
    output.push(value);
    Ok(())
}

fn sequence_layout(types: &[ValueType]) -> Result<CanonicalLayout, CodecError> {
    let mut size = 0usize;
    let mut alignment = 1usize;
    for ty in types {
        let field = validate_type(ty)?.layout;
        size = align_to(size, field.alignment)?;
        size = size.checked_add(field.size).ok_or(CodecError::ByteLimit)?;
        alignment = alignment.max(field.alignment);
    }
    Ok(CanonicalLayout {
        size: align_to(size, alignment)?,
        alignment,
    })
}

fn variant_payload_pointer(
    base: u32,
    cases: u32,
    payload_alignment: usize,
) -> Result<u32, CodecError> {
    let discriminant = discriminant_layout(cases)?;
    add_pointer(base, align_to(discriminant.size, payload_alignment)?)
}

fn optional_union_alignment<'a>(
    cases: impl IntoIterator<Item = Option<&'a ValueType>>,
) -> Result<usize, CodecError> {
    let mut alignment = 1;
    for case in cases.into_iter().flatten() {
        alignment = alignment.max(validate_type(case)?.layout.alignment);
    }
    Ok(alignment)
}

fn discriminant_layout(cases: u32) -> Result<CanonicalLayout, CodecError> {
    if cases == 0 || cases > PROFILE_1_LIMITS.max_canonical_values {
        return Err(CodecError::InvalidDiscriminant);
    }
    Ok(if cases <= 256 {
        CanonicalLayout {
            size: 1,
            alignment: 1,
        }
    } else if cases <= 65_536 {
        CanonicalLayout {
            size: 2,
            alignment: 2,
        }
    } else {
        CanonicalLayout {
            size: 4,
            alignment: 4,
        }
    })
}

fn write_discriminant<M: GuestMemory>(
    memory: &mut M,
    pointer: u32,
    cases: u32,
    value: u32,
) -> Result<(), CodecError> {
    if value >= cases {
        return Err(CodecError::InvalidDiscriminant);
    }
    match discriminant_layout(cases)?.size {
        1 => write_u8(memory, pointer, value as u8),
        2 => write_u16(memory, pointer, value as u16),
        _ => write_u32(memory, pointer, value),
    }
}

fn read_discriminant<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    cases: u32,
) -> Result<u32, CodecError> {
    let value = match discriminant_layout(cases)?.size {
        1 => u32::from(read_u8(memory, pointer)?),
        2 => u32::from(read_u16(memory, pointer)?),
        _ => read_u32(memory, pointer)?,
    };
    (value < cases)
        .then_some(value)
        .ok_or(CodecError::InvalidDiscriminant)
}

fn write_flags<M: GuestMemory>(
    memory: &mut M,
    pointer: u32,
    count: u32,
    words: &[u32],
) -> Result<(), CodecError> {
    let expected = count.checked_add(31).ok_or(CodecError::InvalidFlags)? / 32;
    if words.len() != expected as usize {
        return Err(CodecError::InvalidFlags);
    }
    if let Some(last) = words.last() {
        let used = count % 32;
        if used != 0 && *last >> used != 0 {
            return Err(CodecError::InvalidFlags);
        }
    }
    match count {
        1..=8 => write_u8(memory, pointer, words[0] as u8),
        9..=16 => write_u16(memory, pointer, words[0] as u16),
        _ => {
            for (index, word) in words.iter().enumerate() {
                write_u32(memory, indexed(pointer, index, 4)?, *word)?;
            }
            Ok(())
        }
    }
}

fn read_flags<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    count: u32,
    budget: &mut Budget,
) -> Result<Vec<u32>, CodecError> {
    let expected = count.checked_add(31).ok_or(CodecError::InvalidFlags)? / 32;
    let mut words = Vec::new();
    if expected != 0 {
        budget.allocation()?;
    }
    words
        .try_reserve_exact(expected as usize)
        .map_err(|_| CodecError::Allocation)?;
    match count {
        1..=8 => words.push(u32::from(read_u8(memory, pointer)?)),
        9..=16 => words.push(u32::from(read_u16(memory, pointer)?)),
        _ => {
            for index in 0..expected as usize {
                words.push(read_u32(memory, indexed(pointer, index, 4)?)?);
            }
        }
    }
    if let Some(last) = words.last() {
        let used = count % 32;
        if used != 0 && *last >> used != 0 {
            return Err(CodecError::InvalidFlags);
        }
    }
    Ok(words)
}

fn write_pair<M: GuestMemory>(
    memory: &mut M,
    pointer: u32,
    payload: u32,
    length: usize,
) -> Result<(), CodecError> {
    write_u32(memory, pointer, payload)?;
    write_u32(
        memory,
        add_pointer(pointer, 4)?,
        u32::try_from(length).map_err(|_| CodecError::ByteLimit)?,
    )
}

fn read_pair<M: GuestMemory>(memory: &M, pointer: u32) -> Result<(u32, usize), CodecError> {
    let payload = read_u32(memory, pointer)?;
    let length = read_u32(memory, add_pointer(pointer, 4)?)?;
    Ok((
        payload,
        usize::try_from(length).map_err(|_| CodecError::ByteLimit)?,
    ))
}

fn read_vec<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    length: usize,
    alignment: usize,
) -> Result<Vec<u8>, CodecError> {
    span_size(memory, pointer, length, alignment)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation)?;
    bytes.resize(length, 0);
    if length != 0 {
        memory.read_exact(pointer, &mut bytes)?;
    }
    Ok(bytes)
}

fn span<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    layout: CanonicalLayout,
) -> Result<(), CodecError> {
    span_size(memory, pointer, layout.size, layout.alignment)
}

fn span_size<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    size: usize,
    alignment: usize,
) -> Result<(), CodecError> {
    checked_span(
        pointer,
        u64::try_from(size).map_err(|_| CodecError::ByteLimit)?,
        1,
        u32::try_from(alignment).map_err(|_| CodecError::Misaligned)?,
        memory.len(),
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
    )?;
    Ok(())
}

fn zero<M: GuestMemory>(memory: &mut M, pointer: u32, size: usize) -> Result<(), CodecError> {
    let zeros = [0_u8; 16];
    let mut offset = 0usize;
    while offset < size {
        let amount = (size - offset).min(zeros.len());
        memory.write_exact(add_pointer(pointer, offset)?, &zeros[..amount])?;
        offset += amount;
    }
    Ok(())
}

fn read_u8<M: GuestMemory>(memory: &M, pointer: u32) -> Result<u8, CodecError> {
    let mut bytes = [0; 1];
    memory.read_exact(pointer, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16<M: GuestMemory>(memory: &M, pointer: u32) -> Result<u16, CodecError> {
    let mut bytes = [0; 2];
    memory.read_exact(pointer, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32<M: GuestMemory>(memory: &M, pointer: u32) -> Result<u32, CodecError> {
    let mut bytes = [0; 4];
    memory.read_exact(pointer, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64<M: GuestMemory>(memory: &M, pointer: u32) -> Result<u64, CodecError> {
    let mut bytes = [0; 8];
    memory.read_exact(pointer, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u8<M: GuestMemory>(memory: &mut M, pointer: u32, value: u8) -> Result<(), CodecError> {
    memory.write_exact(pointer, &[value]).map_err(Into::into)
}

fn write_u16<M: GuestMemory>(memory: &mut M, pointer: u32, value: u16) -> Result<(), CodecError> {
    memory
        .write_exact(pointer, &value.to_le_bytes())
        .map_err(Into::into)
}

fn write_u32<M: GuestMemory>(memory: &mut M, pointer: u32, value: u32) -> Result<(), CodecError> {
    memory
        .write_exact(pointer, &value.to_le_bytes())
        .map_err(Into::into)
}

fn write_u64<M: GuestMemory>(memory: &mut M, pointer: u32, value: u64) -> Result<(), CodecError> {
    memory
        .write_exact(pointer, &value.to_le_bytes())
        .map_err(Into::into)
}

fn indexed(base: u32, index: usize, stride: usize) -> Result<u32, CodecError> {
    add_pointer(base, index.checked_mul(stride).ok_or(CodecError::Overflow)?)
}

fn add_pointer(base: u32, offset: usize) -> Result<u32, CodecError> {
    base.checked_add(u32::try_from(offset).map_err(|_| CodecError::Overflow)?)
        .ok_or(CodecError::Overflow)
}

fn align_to(value: usize, alignment: usize) -> Result<usize, CodecError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(CodecError::Overflow)
}

fn try_box<T>(value: T) -> Result<Box<T>, CodecError> {
    let layout = Layout::new::<T>();
    // SAFETY: `alloc` is called with `Layout::new::<T>()`; a non-null pointer
    // is aligned and valid for one `T`. We initialize it exactly once and hand
    // ownership immediately to `Box::from_raw`.
    let pointer = unsafe { alloc(layout) };
    let pointer = NonNull::<T>::new(pointer.cast()).ok_or(CodecError::Allocation)?;
    // SAFETY: `pointer` denotes fresh storage for one `T`, initialized below.
    unsafe {
        pointer.as_ptr().write(value);
        Ok(Box::from_raw(pointer.as_ptr()))
    }
}
