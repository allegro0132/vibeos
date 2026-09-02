//! Typed, bounded values for the selected Canonical ABI profiles.

use crate::resource::{ResourceTable, ResourceToken, ResourceTypeId};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, num::NonZeroU32};
use vibeos_component_format::PROFILE_1_LIMITS;
#[cfg(feature = "c88-f3-acceptance")]
use vibeos_component_format::{
    PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS, PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
};

/// One Component-level `f32` value represented without using the host FPU.
///
/// Component values have one abstract NaN. Construction therefore collapses
/// every quiet or signaling NaN, including negative NaNs, to the exact fixed
/// positive quiet-NaN bits selected by the Profile-2 candidate contract.
#[cfg(feature = "c88-f3-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalF32(u32);

#[cfg(feature = "c88-f3-acceptance")]
impl CanonicalF32 {
    pub const fn from_bits(bits: u32) -> Self {
        if bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0 {
            Self(PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS)
        } else {
            Self(bits)
        }
    }

    pub const fn to_bits(self) -> u32 {
        self.0
    }
}

/// One Component-level `f64` value represented without using the host FPU.
#[cfg(feature = "c88-f3-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalF64(u64);

#[cfg(feature = "c88-f3-acceptance")]
impl CanonicalF64 {
    pub const fn from_bits(bits: u64) -> Self {
        if bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000
            && bits & 0x000f_ffff_ffff_ffff != 0
        {
            Self(PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS)
        } else {
            Self(bits)
        }
    }

    pub const fn to_bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceOwnership {
    Own,
    Borrow,
}

/// Validator-local identity for one `stream<T>` or `future<T>` definition.
/// This namespace is deliberately disjoint from Component Model resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsyncValueTypeId(NonZeroU32);

impl AsyncValueTypeId {
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointDirection {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointOwner {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointGeneration(NonZeroU32);

impl EndpointGeneration {
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(PartialEq, Eq)]
struct ReadableEndpointSeal {
    incarnation: u64,
    slot: u32,
    generation: EndpointGeneration,
    value_type: AsyncValueTypeId,
    owner: EndpointOwner,
}

/// Opaque linear token for the readable side of a `stream<T>`.
///
/// It has no public constructor and implements neither `Clone` nor `Copy`.
/// In particular, a raw `i32`, writable endpoint, or [`ResourceToken`] cannot
/// be reinterpreted as this token. Ownership is changed only by consuming the
/// token through the endpoint arena; mutating this seal alone would not perform
/// a Canonical ABI handle-table transfer.
#[derive(PartialEq, Eq)]
pub struct ReadableStreamEndpointToken(ReadableEndpointSeal);

/// Opaque linear token for the readable side of a `future<T>`.
#[derive(PartialEq, Eq)]
pub struct ReadableFutureEndpointToken(ReadableEndpointSeal);

macro_rules! impl_readable_endpoint_token {
    ($token:ident, $label:literal) => {
        impl $token {
            #[allow(dead_code)] // Issued by the native async handle arena in the next slice.
            pub(crate) fn issue(
                incarnation: u64,
                slot: u32,
                generation: EndpointGeneration,
                value_type: AsyncValueTypeId,
                owner: EndpointOwner,
            ) -> Result<Self, ValueError> {
                if incarnation == 0 || slot == 0 || slot > PROFILE_1_LIMITS.max_resources {
                    return Err(ValueError::Endpoint);
                }
                Ok(Self(ReadableEndpointSeal {
                    incarnation,
                    slot,
                    generation,
                    value_type,
                    owner,
                }))
            }

            pub const fn value_type(&self) -> AsyncValueTypeId {
                self.0.value_type
            }

            pub const fn generation(&self) -> EndpointGeneration {
                self.0.generation
            }

            pub const fn owner(&self) -> EndpointOwner {
                self.0.owner
            }

            pub const fn direction(&self) -> EndpointDirection {
                EndpointDirection::Read
            }
        }

        impl fmt::Debug for $token {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "(<opaque>)"))
            }
        }
    };
}

impl_readable_endpoint_token!(ReadableStreamEndpointToken, "ReadableStreamEndpointToken");
impl_readable_endpoint_token!(ReadableFutureEndpointToken, "ReadableFutureEndpointToken");

/// A value schema. Deliberately not `Clone`: recursively cloning an untrusted
/// shape would introduce an infallible allocation path.
#[derive(Debug, PartialEq, Eq)]
pub enum ValueType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    #[cfg(feature = "c88-f3-acceptance")]
    F32,
    #[cfg(feature = "c88-f3-acceptance")]
    F64,
    Char,
    String,
    List(Box<ValueType>),
    Tuple(Vec<ValueType>),
    Record(Vec<ValueType>),
    Flags(u32),
    Enum(u32),
    Option(Box<ValueType>),
    Result {
        ok: Option<Box<ValueType>>,
        error: Option<Box<ValueType>>,
    },
    Variant(Vec<Option<ValueType>>),
    Resource {
        resource_type: ResourceTypeId,
        ownership: ResourceOwnership,
    },
    Stream {
        type_id: AsyncValueTypeId,
        element: Option<Box<ValueType>>,
    },
    Future {
        type_id: AsyncValueTypeId,
        payload: Option<Box<ValueType>>,
    },
}

/// An owned host-side value. Deliberately not `Clone`; lifting and lowering
/// construct values through checked, fallible allocation paths.
#[derive(Debug, PartialEq, Eq)]
pub enum CanonicalValue {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    #[cfg(feature = "c88-f3-acceptance")]
    F32(CanonicalF32),
    #[cfg(feature = "c88-f3-acceptance")]
    F64(CanonicalF64),
    Char(char),
    String(String),
    List(Vec<CanonicalValue>),
    Tuple(Vec<CanonicalValue>),
    Record(Vec<CanonicalValue>),
    Flags(Vec<u32>),
    Enum(u32),
    Option(Option<Box<CanonicalValue>>),
    Result(Result<Option<Box<CanonicalValue>>, Option<Box<CanonicalValue>>>),
    Variant {
        case: u32,
        payload: Option<Box<CanonicalValue>>,
    },
    Resource(ResourceToken),
    Stream(ReadableStreamEndpointToken),
    Future(ReadableFutureEndpointToken),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ValueError {
    TypeMismatch = 1,
    InvalidDiscriminant = 2,
    InvalidFlags = 3,
    NestingLimit = 4,
    ValueLimit = 5,
    ByteLimit = 6,
    ListLimit = 7,
    Allocation = 8,
    BorrowEscape = 9,
    Resource = 10,
    Endpoint = 11,
    Ownership = 12,
}

impl ValueError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalLayout {
    pub size: usize,
    pub alignment: usize,
}

impl CanonicalLayout {
    const fn scalar(size: usize) -> Self {
        Self {
            size,
            alignment: size,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeAccount {
    pub nodes: u32,
    pub max_depth: u32,
    pub layout: CanonicalLayout,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValueAccount {
    pub nodes: u32,
    /// Total memory32 Canonical ABI bytes, including flat-layout padding and
    /// recursively allocated string/list payloads.
    pub bytes: usize,
    pub list_elements: u32,
    pub max_depth: u32,
    pub work: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValuePosition {
    Parameter,
    Result,
}

impl ValueAccount {
    fn enter(&mut self, depth: u32) -> Result<(), ValueError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(ValueError::NestingLimit);
        }
        self.nodes = self.nodes.checked_add(1).ok_or(ValueError::ValueLimit)?;
        if self.nodes > PROFILE_1_LIMITS.max_canonical_values {
            return Err(ValueError::ValueLimit);
        }
        self.max_depth = self.max_depth.max(depth);
        self.work = self.work.checked_add(1).ok_or(ValueError::ValueLimit)?;
        Ok(())
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), ValueError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(ValueError::ByteLimit)?;
        if self.bytes > PROFILE_1_LIMITS.max_canonical_value_bytes {
            return Err(ValueError::ByteLimit);
        }
        self.work = self
            .work
            .checked_add(u64::try_from(bytes).map_err(|_| ValueError::ByteLimit)?)
            .ok_or(ValueError::ByteLimit)?;
        Ok(())
    }

    fn charge_list(&mut self, elements: usize) -> Result<(), ValueError> {
        let elements = u32::try_from(elements).map_err(|_| ValueError::ListLimit)?;
        self.list_elements = self
            .list_elements
            .checked_add(elements)
            .ok_or(ValueError::ListLimit)?;
        if self.list_elements > PROFILE_1_LIMITS.max_list_elements {
            return Err(ValueError::ListLimit);
        }
        Ok(())
    }
}

#[derive(Default)]
struct TypeCounter {
    nodes: u32,
    max_depth: u32,
}

impl TypeCounter {
    fn enter(&mut self, depth: u32) -> Result<(), ValueError> {
        if depth > PROFILE_1_LIMITS.max_canonical_nesting {
            return Err(ValueError::NestingLimit);
        }
        self.nodes = self.nodes.checked_add(1).ok_or(ValueError::ValueLimit)?;
        if self.nodes > PROFILE_1_LIMITS.max_canonical_values {
            return Err(ValueError::ValueLimit);
        }
        self.max_depth = self.max_depth.max(depth);
        Ok(())
    }
}

/// Validates every branch of a schema, including branches not selected by a
/// runtime option/result/variant value, and computes its exact memory32 layout.
pub fn validate_type(ty: &ValueType) -> Result<TypeAccount, ValueError> {
    let mut counter = TypeCounter::default();
    let layout = type_at(ty, 1, &mut counter)?;
    Ok(TypeAccount {
        nodes: counter.nodes,
        max_depth: counter.max_depth,
        layout,
    })
}

fn type_at(
    ty: &ValueType,
    depth: u32,
    counter: &mut TypeCounter,
) -> Result<CanonicalLayout, ValueError> {
    counter.enter(depth)?;
    let layout = match ty {
        ValueType::Bool | ValueType::U8 | ValueType::S8 => CanonicalLayout::scalar(1),
        ValueType::U16 | ValueType::S16 => CanonicalLayout::scalar(2),
        ValueType::U32 | ValueType::S32 | ValueType::Char => CanonicalLayout::scalar(4),
        #[cfg(feature = "c88-f3-acceptance")]
        ValueType::F32 => CanonicalLayout::scalar(4),
        ValueType::U64 | ValueType::S64 => CanonicalLayout::scalar(8),
        #[cfg(feature = "c88-f3-acceptance")]
        ValueType::F64 => CanonicalLayout::scalar(8),
        ValueType::String => CanonicalLayout {
            size: 8,
            alignment: 4,
        },
        ValueType::List(item) => {
            type_at(item, depth + 1, counter)?;
            CanonicalLayout {
                size: 8,
                alignment: 4,
            }
        }
        ValueType::Tuple(types) | ValueType::Record(types) => {
            aggregate_layout(types.iter(), depth, counter)?
        }
        ValueType::Flags(count) => flags_layout(*count)?,
        ValueType::Enum(cases) => discriminant_layout(*cases)?,
        ValueType::Option(inner) => {
            let payload = type_at(inner, depth + 1, counter)?;
            variant_layout(discriminant_layout(2)?, payload.size, payload.alignment)?
        }
        ValueType::Result { ok, error } => {
            let mut payload_size = 0;
            let mut payload_alignment = 1;
            if let Some(ok) = ok {
                let layout = type_at(ok, depth + 1, counter)?;
                payload_size = payload_size.max(layout.size);
                payload_alignment = payload_alignment.max(layout.alignment);
            }
            if let Some(error) = error {
                let layout = type_at(error, depth + 1, counter)?;
                payload_size = payload_size.max(layout.size);
                payload_alignment = payload_alignment.max(layout.alignment);
            }
            variant_layout(discriminant_layout(2)?, payload_size, payload_alignment)?
        }
        ValueType::Variant(cases) => {
            if cases.is_empty() || cases.len() > PROFILE_1_LIMITS.max_canonical_values as usize {
                return Err(ValueError::InvalidDiscriminant);
            }
            let mut payload_size = 0;
            let mut payload_alignment = 1;
            for case in cases.iter().flatten() {
                let layout = type_at(case, depth + 1, counter)?;
                payload_size = payload_size.max(layout.size);
                payload_alignment = payload_alignment.max(layout.alignment);
            }
            variant_layout(
                discriminant_layout(cases.len() as u32)?,
                payload_size,
                payload_alignment,
            )?
        }
        ValueType::Resource { .. } => CanonicalLayout::scalar(4),
        ValueType::Stream { element, .. } => {
            if let Some(element) = element {
                type_at(element, depth + 1, counter)?;
                if type_contains_borrow(element) {
                    return Err(ValueError::Ownership);
                }
            }
            CanonicalLayout::scalar(4)
        }
        ValueType::Future { payload, .. } => {
            if let Some(payload) = payload {
                type_at(payload, depth + 1, counter)?;
                if type_contains_borrow(payload) {
                    return Err(ValueError::Ownership);
                }
            }
            CanonicalLayout::scalar(4)
        }
    };
    if layout.size > PROFILE_1_LIMITS.max_canonical_value_bytes {
        return Err(ValueError::ByteLimit);
    }
    Ok(layout)
}

fn type_contains_borrow(value: &ValueType) -> bool {
    match value {
        ValueType::Resource {
            ownership: ResourceOwnership::Borrow,
            ..
        } => true,
        ValueType::List(value) | ValueType::Option(value) => type_contains_borrow(value),
        ValueType::Tuple(values) | ValueType::Record(values) => {
            values.iter().any(type_contains_borrow)
        }
        ValueType::Result { ok, error } => {
            ok.as_deref().is_some_and(type_contains_borrow)
                || error.as_deref().is_some_and(type_contains_borrow)
        }
        ValueType::Variant(cases) => cases.iter().flatten().any(type_contains_borrow),
        ValueType::Stream { element, .. } => element.as_deref().is_some_and(type_contains_borrow),
        ValueType::Future { payload, .. } => payload.as_deref().is_some_and(type_contains_borrow),
        _ => false,
    }
}

fn aggregate_layout<'a>(
    types: impl Iterator<Item = &'a ValueType>,
    depth: u32,
    counter: &mut TypeCounter,
) -> Result<CanonicalLayout, ValueError> {
    let mut size = 0usize;
    let mut alignment = 1usize;
    for ty in types {
        let field = type_at(ty, depth + 1, counter)?;
        size = align_to(size, field.alignment)?;
        size = size.checked_add(field.size).ok_or(ValueError::ByteLimit)?;
        alignment = alignment.max(field.alignment);
    }
    size = align_to(size, alignment)?;
    Ok(CanonicalLayout { size, alignment })
}

fn flags_layout(count: u32) -> Result<CanonicalLayout, ValueError> {
    if count == 0 || count > PROFILE_1_LIMITS.max_canonical_values {
        return Err(ValueError::InvalidFlags);
    }
    Ok(match count {
        1..=8 => CanonicalLayout::scalar(1),
        9..=16 => CanonicalLayout::scalar(2),
        _ => {
            let words = count.checked_add(31).ok_or(ValueError::InvalidFlags)? / 32;
            CanonicalLayout {
                size: usize::try_from(words)
                    .map_err(|_| ValueError::ByteLimit)?
                    .checked_mul(4)
                    .ok_or(ValueError::ByteLimit)?,
                alignment: 4,
            }
        }
    })
}

fn discriminant_layout(cases: u32) -> Result<CanonicalLayout, ValueError> {
    if cases == 0 || cases > PROFILE_1_LIMITS.max_canonical_values {
        return Err(ValueError::InvalidDiscriminant);
    }
    Ok(if cases <= 256 {
        CanonicalLayout::scalar(1)
    } else if cases <= 65_536 {
        CanonicalLayout::scalar(2)
    } else {
        CanonicalLayout::scalar(4)
    })
}

fn variant_layout(
    discriminant: CanonicalLayout,
    payload_size: usize,
    payload_alignment: usize,
) -> Result<CanonicalLayout, ValueError> {
    let alignment = discriminant.alignment.max(payload_alignment);
    let payload_offset = align_to(discriminant.size, payload_alignment)?;
    let size = align_to(
        payload_offset
            .checked_add(payload_size)
            .ok_or(ValueError::ByteLimit)?,
        alignment,
    )?;
    Ok(CanonicalLayout { size, alignment })
}

fn align_to(value: usize, alignment: usize) -> Result<usize, ValueError> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(ValueError::ByteLimit)
}

/// Validates the bounded structural shape of a value. This deliberately does
/// not confer resource or endpoint authority: resources require
/// [`validate_value_with_resources`], while readable endpoints must also pass
/// the complete seal check owned by their async handle arena.
pub fn validate_value(ty: &ValueType, value: &CanonicalValue) -> Result<ValueAccount, ValueError> {
    let type_account = validate_type(ty)?;
    let mut account = ValueAccount::default();
    validate_at(ty, value, 1, Some(type_account.layout), &mut account)?;
    Ok(account)
}

/// Validates shape plus every selected resource against the exact instance
/// table. Borrowed resources are call inputs only and cannot appear in results.
/// Callers must additionally wrap every `own<T>` parameter in an `OwnTransfer`
/// until the call commits or rolls back.
pub fn validate_value_with_resources<A>(
    ty: &ValueType,
    value: &CanonicalValue,
    table: &ResourceTable<A>,
    position: ValuePosition,
) -> Result<ValueAccount, ValueError> {
    let account = validate_value(ty, value)?;
    validate_resource_position_type(ty, position)?;
    validate_resources_at(ty, value, table, position)?;
    Ok(account)
}

/// Checks the complete seal on one readable stream endpoint.
pub fn validate_readable_stream_endpoint(
    token: &ReadableStreamEndpointToken,
    incarnation: u64,
    slot: u32,
    generation: EndpointGeneration,
    value_type: AsyncValueTypeId,
    owner: EndpointOwner,
) -> Result<(), ValueError> {
    validate_readable_endpoint(&token.0, incarnation, slot, generation, value_type, owner)
}

/// Checks the complete seal on one readable future endpoint.
pub fn validate_readable_future_endpoint(
    token: &ReadableFutureEndpointToken,
    incarnation: u64,
    slot: u32,
    generation: EndpointGeneration,
    value_type: AsyncValueTypeId,
    owner: EndpointOwner,
) -> Result<(), ValueError> {
    validate_readable_endpoint(&token.0, incarnation, slot, generation, value_type, owner)
}

fn validate_readable_endpoint(
    token: &ReadableEndpointSeal,
    incarnation: u64,
    slot: u32,
    generation: EndpointGeneration,
    value_type: AsyncValueTypeId,
    owner: EndpointOwner,
) -> Result<(), ValueError> {
    if token.incarnation != incarnation
        || token.slot != slot
        || token.generation != generation
        || token.value_type != value_type
    {
        return Err(ValueError::Endpoint);
    }
    if token.owner != owner {
        return Err(ValueError::Ownership);
    }
    Ok(())
}

fn validate_resource_position_type(
    ty: &ValueType,
    position: ValuePosition,
) -> Result<(), ValueError> {
    match ty {
        ValueType::Resource {
            ownership: ResourceOwnership::Borrow,
            ..
        } if position == ValuePosition::Result => Err(ValueError::BorrowEscape),
        ValueType::List(item) | ValueType::Option(item) => {
            validate_resource_position_type(item, position)
        }
        ValueType::Stream { element, .. } => match element {
            Some(element) => validate_resource_position_type(element, position),
            None => Ok(()),
        },
        ValueType::Future { payload, .. } => match payload {
            Some(payload) => validate_resource_position_type(payload, position),
            None => Ok(()),
        },
        ValueType::Tuple(types) | ValueType::Record(types) => {
            for ty in types {
                validate_resource_position_type(ty, position)?;
            }
            Ok(())
        }
        ValueType::Result { ok, error } => {
            if let Some(ok) = ok {
                validate_resource_position_type(ok, position)?;
            }
            if let Some(error) = error {
                validate_resource_position_type(error, position)?;
            }
            Ok(())
        }
        ValueType::Variant(cases) => {
            for case in cases.iter().flatten() {
                validate_resource_position_type(case, position)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_resources_at<A>(
    ty: &ValueType,
    value: &CanonicalValue,
    table: &ResourceTable<A>,
    position: ValuePosition,
) -> Result<(), ValueError> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership,
            },
            CanonicalValue::Resource(token),
        ) => {
            if *ownership == ResourceOwnership::Borrow && position == ValuePosition::Result {
                return Err(ValueError::BorrowEscape);
            }
            table
                .contains(*token, *resource_type)
                .map(|_| ())
                .map_err(|_| ValueError::Resource)
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                validate_resources_at(item, value, table, position)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            for (ty, value) in types.iter().zip(values) {
                validate_resources_at(ty, value, table, position)?;
            }
            Ok(())
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            validate_resources_at(inner, value, table, position)
        }
        (
            ValueType::Result { ok: Some(ty), .. },
            CanonicalValue::Result(core::result::Result::Ok(Some(value))),
        )
        | (
            ValueType::Result {
                error: Some(ty), ..
            },
            CanonicalValue::Result(core::result::Result::Err(Some(value))),
        ) => validate_resources_at(ty, value, table, position),
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            if let (Some(Some(ty)), Some(value)) = (
                usize::try_from(*case).ok().and_then(|case| cases.get(case)),
                payload,
            ) {
                validate_resources_at(ty, value, table, position)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_at(
    ty: &ValueType,
    value: &CanonicalValue,
    depth: u32,
    flat_layout: Option<CanonicalLayout>,
    account: &mut ValueAccount,
) -> Result<(), ValueError> {
    account.enter(depth)?;
    if let Some(layout) = flat_layout {
        account.charge_bytes(layout.size)?;
    }
    match (ty, value) {
        #[cfg(feature = "c88-f3-acceptance")]
        (ValueType::F32, CanonicalValue::F32(_)) | (ValueType::F64, CanonicalValue::F64(_)) => {
            Ok(())
        }
        (ValueType::Bool, CanonicalValue::Bool(_))
        | (ValueType::U8, CanonicalValue::U8(_))
        | (ValueType::U16, CanonicalValue::U16(_))
        | (ValueType::U32, CanonicalValue::U32(_))
        | (ValueType::U64, CanonicalValue::U64(_))
        | (ValueType::S8, CanonicalValue::S8(_))
        | (ValueType::S16, CanonicalValue::S16(_))
        | (ValueType::S32, CanonicalValue::S32(_))
        | (ValueType::S64, CanonicalValue::S64(_))
        | (ValueType::Char, CanonicalValue::Char(_))
        | (ValueType::Resource { .. }, CanonicalValue::Resource(_)) => Ok(()),
        (ValueType::Stream { type_id, .. }, CanonicalValue::Stream(token))
            if token.value_type() == *type_id =>
        {
            Ok(())
        }
        (ValueType::Future { type_id, .. }, CanonicalValue::Future(token))
            if token.value_type() == *type_id =>
        {
            Ok(())
        }
        (ValueType::Stream { .. }, CanonicalValue::Stream(_))
        | (ValueType::Future { .. }, CanonicalValue::Future(_)) => Err(ValueError::Endpoint),
        (ValueType::String, CanonicalValue::String(value)) => {
            if value.len() > PROFILE_1_LIMITS.max_string_bytes {
                return Err(ValueError::ByteLimit);
            }
            account.charge_bytes(value.len())
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            account.charge_list(values.len())?;
            let item_layout = validate_type(item)?.layout;
            for value in values {
                validate_at(item, value, depth + 1, Some(item_layout), account)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            if types.len() != values.len() {
                return Err(ValueError::TypeMismatch);
            }
            for (ty, value) in types.iter().zip(values) {
                // Every field's flat storage is already included in the
                // enclosing aggregate layout. Nested payloads are not.
                validate_at(ty, value, depth + 1, None, account)?;
            }
            Ok(())
        }
        (ValueType::Flags(count), CanonicalValue::Flags(words)) => {
            let expected = count.checked_add(31).ok_or(ValueError::InvalidFlags)? / 32;
            if words.len() != expected as usize {
                return Err(ValueError::InvalidFlags);
            }
            if let Some(last) = words.last() {
                let used = count % 32;
                if used != 0 && *last >> used != 0 {
                    return Err(ValueError::InvalidFlags);
                }
            }
            Ok(())
        }
        (ValueType::Enum(cases), CanonicalValue::Enum(case)) if *cases != 0 && case < cases => {
            Ok(())
        }
        (ValueType::Option(inner), CanonicalValue::Option(value)) => {
            if let Some(value) = value {
                validate_at(inner, value, depth + 1, None, account)?;
            }
            Ok(())
        }
        (
            ValueType::Result { ok, error: _ },
            CanonicalValue::Result(core::result::Result::Ok(value)),
        ) => validate_optional(ok.as_deref(), value.as_deref(), depth, account),
        (
            ValueType::Result { ok: _, error },
            CanonicalValue::Result(core::result::Result::Err(value)),
        ) => validate_optional(error.as_deref(), value.as_deref(), depth, account),
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let case = usize::try_from(*case).map_err(|_| ValueError::InvalidDiscriminant)?;
            let expected = cases.get(case).ok_or(ValueError::InvalidDiscriminant)?;
            validate_optional(expected.as_ref(), payload.as_deref(), depth, account)
        }
        (ValueType::Enum(_), CanonicalValue::Enum(_)) => Err(ValueError::InvalidDiscriminant),
        _ => Err(ValueError::TypeMismatch),
    }
}

fn validate_optional(
    ty: Option<&ValueType>,
    value: Option<&CanonicalValue>,
    depth: u32,
    account: &mut ValueAccount,
) -> Result<(), ValueError> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => validate_at(ty, value, depth + 1, None, account),
        _ => Err(ValueError::TypeMismatch),
    }
}

/// Fallibly copies a host string only after all configured limits are checked.
pub fn try_string_value(value: &str) -> Result<CanonicalValue, ValueError> {
    if value.len() > PROFILE_1_LIMITS.max_string_bytes
        || value.len().checked_add(8).ok_or(ValueError::ByteLimit)?
            > PROFILE_1_LIMITS.max_canonical_value_bytes
    {
        return Err(ValueError::ByteLimit);
    }
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| ValueError::Allocation)?;
    owned.push_str(value);
    Ok(CanonicalValue::String(owned))
}

/// Fallibly constructs a list while enforcing element, node, and aggregate
/// byte budgets before each vector growth.
pub fn try_list_value<I>(item_type: &ValueType, values: I) -> Result<CanonicalValue, ValueError>
where
    I: IntoIterator<Item = CanonicalValue>,
{
    let item_layout = validate_type(item_type)?.layout;
    let mut result = Vec::new();
    let mut nodes = 1u32;
    let mut bytes = 8usize;
    for value in values {
        if result.len() >= PROFILE_1_LIMITS.max_list_elements as usize {
            return Err(ValueError::ListLimit);
        }
        let account = validate_value(item_type, &value)?;
        nodes = nodes
            .checked_add(account.nodes)
            .ok_or(ValueError::ValueLimit)?;
        if nodes > PROFILE_1_LIMITS.max_canonical_values {
            return Err(ValueError::ValueLimit);
        }
        // `account.bytes` already includes the item's flat layout.
        debug_assert!(account.bytes >= item_layout.size);
        bytes = bytes
            .checked_add(account.bytes)
            .ok_or(ValueError::ByteLimit)?;
        if bytes > PROFILE_1_LIMITS.max_canonical_value_bytes {
            return Err(ValueError::ByteLimit);
        }
        result.try_reserve(1).map_err(|_| ValueError::Allocation)?;
        result.push(value);
    }
    Ok(CanonicalValue::List(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn async_type(value: u32) -> AsyncValueTypeId {
        AsyncValueTypeId::new(value).unwrap()
    }

    fn generation(value: u32) -> EndpointGeneration {
        EndpointGeneration::new(value).unwrap()
    }

    fn stream_token(
        value_type: AsyncValueTypeId,
        owner: EndpointOwner,
    ) -> ReadableStreamEndpointToken {
        ReadableStreamEndpointToken::issue(0xfeed, 7, generation(3), value_type, owner).unwrap()
    }

    fn future_token(
        value_type: AsyncValueTypeId,
        owner: EndpointOwner,
    ) -> ReadableFutureEndpointToken {
        ReadableFutureEndpointToken::issue(0xbeef, 9, generation(5), value_type, owner).unwrap()
    }

    #[test]
    fn endpoint_issuer_rejects_sentinels_and_out_of_profile_slots() {
        let ty = async_type(1);
        assert_eq!(
            ReadableStreamEndpointToken::issue(0, 1, generation(1), ty, EndpointOwner::Host).err(),
            Some(ValueError::Endpoint)
        );
        assert_eq!(
            ReadableStreamEndpointToken::issue(1, 0, generation(1), ty, EndpointOwner::Host).err(),
            Some(ValueError::Endpoint)
        );
        assert_eq!(
            ReadableStreamEndpointToken::issue(
                1,
                PROFILE_1_LIMITS.max_resources + 1,
                generation(1),
                ty,
                EndpointOwner::Host,
            )
            .err(),
            Some(ValueError::Endpoint)
        );
        assert!(EndpointGeneration::new(0).is_none());
        assert!(AsyncValueTypeId::new(0).is_none());
    }

    #[test]
    fn endpoint_seal_checks_incarnation_slot_generation_type_and_owner() {
        let ty = async_type(2);
        let token = stream_token(ty, EndpointOwner::Host);
        assert_eq!(
            validate_readable_stream_endpoint(
                &token,
                0xfeed,
                7,
                generation(3),
                ty,
                EndpointOwner::Host,
            ),
            Ok(())
        );
        for result in [
            validate_readable_stream_endpoint(
                &token,
                0xf00d,
                7,
                generation(3),
                ty,
                EndpointOwner::Host,
            ),
            validate_readable_stream_endpoint(
                &token,
                0xfeed,
                8,
                generation(3),
                ty,
                EndpointOwner::Host,
            ),
            validate_readable_stream_endpoint(
                &token,
                0xfeed,
                7,
                generation(4),
                ty,
                EndpointOwner::Host,
            ),
            validate_readable_stream_endpoint(
                &token,
                0xfeed,
                7,
                generation(3),
                async_type(3),
                EndpointOwner::Host,
            ),
        ] {
            assert_eq!(result, Err(ValueError::Endpoint));
        }
        assert_eq!(
            validate_readable_stream_endpoint(
                &token,
                0xfeed,
                7,
                generation(3),
                ty,
                EndpointOwner::Guest,
            ),
            Err(ValueError::Ownership)
        );
        let debug = alloc::format!("{token:?}");
        assert!(!debug.contains("feed"));
        assert!(!debug.contains("slot"));
    }

    #[test]
    fn endpoint_kind_and_type_identity_are_not_structurally_interchangeable() {
        let stream_type = async_type(1);
        let other_stream_type = async_type(2);
        let stream = ValueType::Stream {
            type_id: stream_type,
            element: Some(Box::new(ValueType::U8)),
        };
        assert_eq!(
            validate_value(
                &stream,
                &CanonicalValue::Stream(stream_token(stream_type, EndpointOwner::Host)),
            )
            .unwrap()
            .bytes,
            4
        );
        assert_eq!(
            validate_value(
                &stream,
                &CanonicalValue::Stream(stream_token(other_stream_type, EndpointOwner::Host)),
            ),
            Err(ValueError::Endpoint)
        );
        assert_eq!(
            validate_value(
                &stream,
                &CanonicalValue::Future(future_token(stream_type, EndpointOwner::Host)),
            ),
            Err(ValueError::TypeMismatch)
        );
    }

    #[test]
    fn async_payloads_containing_borrows_fail_closed() {
        let ty = ValueType::Stream {
            type_id: async_type(1),
            element: Some(Box::new(ValueType::Option(Box::new(ValueType::Resource {
                resource_type: ResourceTypeId(1),
                ownership: ResourceOwnership::Borrow,
            })))),
        };
        assert_eq!(validate_type(&ty), Err(ValueError::Ownership));
    }

    #[test]
    fn nesting_limit_precedes_the_recursive_endpoint_borrow_scan() {
        let mut payload = ValueType::Resource {
            resource_type: ResourceTypeId(1),
            ownership: ResourceOwnership::Borrow,
        };
        for _ in 0..PROFILE_1_LIMITS.max_canonical_nesting {
            payload = ValueType::Option(Box::new(payload));
        }
        let value = ValueType::Future {
            type_id: async_type(1),
            payload: Some(Box::new(payload)),
        };
        assert_eq!(validate_type(&value), Err(ValueError::NestingLimit));
    }
}
