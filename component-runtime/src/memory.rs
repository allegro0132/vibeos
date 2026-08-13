//! Copy-only access to hostile guest linear memory.

use alloc::{string::String, vec::Vec};
use core::ops::Range;
use vibeos_component_format::PROFILE_1_LIMITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AbiError {
    LengthLimit = 1,
    ElementLimit = 2,
    Overflow = 3,
    Misaligned = 4,
    OutOfBounds = 5,
    InvalidUtf8 = 6,
    InvalidBool = 7,
    InvalidChar = 8,
    InvalidDiscriminant = 9,
    BadRealloc = 10,
    AllocationLimit = 11,
    CleanupLimit = 12,
    WorkBudget = 13,
    Reentry = 14,
    Poisoned = 15,
    CleanupFailed = 16,
    NonMonotonicGrowth = 17,
}

impl AbiError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

pub trait GuestMemory {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_exact(&self, pointer: u32, destination: &mut [u8]) -> Result<(), AbiError>;
    fn write_exact(&mut self, pointer: u32, source: &[u8]) -> Result<(), AbiError>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct VecMemory {
    bytes: Vec<u8>,
    maximum: usize,
}

impl VecMemory {
    pub fn new(initial: usize, maximum: usize) -> Result<Self, AbiError> {
        const WASM_PAGE_BYTES: u64 = 65_536;
        let initial = u64::try_from(initial).map_err(|_| AbiError::LengthLimit)?;
        let maximum = u64::try_from(maximum).map_err(|_| AbiError::LengthLimit)?;
        let max_initial = u64::from(PROFILE_1_LIMITS.max_initial_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .ok_or(AbiError::LengthLimit)?;
        let max_effective = u64::from(PROFILE_1_LIMITS.max_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .ok_or(AbiError::LengthLimit)?;
        if initial > maximum || initial > max_initial || maximum > max_effective {
            return Err(AbiError::LengthLimit);
        }
        let initial = usize::try_from(initial).map_err(|_| AbiError::LengthLimit)?;
        let maximum = usize::try_from(maximum).map_err(|_| AbiError::LengthLimit)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(initial)
            .map_err(|_| AbiError::LengthLimit)?;
        bytes.resize(initial, 0);
        Ok(Self { bytes, maximum })
    }

    pub fn grow_to(&mut self, length: usize) -> Result<(), AbiError> {
        if length < self.bytes.len() {
            return Err(AbiError::NonMonotonicGrowth);
        }
        if length > self.maximum {
            return Err(AbiError::OutOfBounds);
        }
        self.bytes
            .try_reserve_exact(length.saturating_sub(self.bytes.len()))
            .map_err(|_| AbiError::LengthLimit)?;
        self.bytes.resize(length, 0);
        Ok(())
    }
}

impl GuestMemory for VecMemory {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact(&self, pointer: u32, destination: &mut [u8]) -> Result<(), AbiError> {
        let range = checked_span(
            pointer,
            destination.len() as u64,
            1,
            1,
            self.len(),
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        )?;
        destination.copy_from_slice(&self.bytes[range]);
        Ok(())
    }

    fn write_exact(&mut self, pointer: u32, source: &[u8]) -> Result<(), AbiError> {
        let range = checked_span(
            pointer,
            source.len() as u64,
            1,
            1,
            self.len(),
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
            PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        )?;
        self.bytes[range].copy_from_slice(source);
        Ok(())
    }
}

pub fn checked_span(
    pointer: u32,
    count: u64,
    stride: u32,
    alignment: u32,
    memory_len: u64,
    element_limit: u64,
    byte_limit: u64,
) -> Result<Range<usize>, AbiError> {
    const MEMORY32_BYTES: u64 = u32::MAX as u64 + 1;
    if count > element_limit {
        return Err(AbiError::ElementLimit);
    }
    // Canonical lists may have zero-sized element layouts. They still charge
    // their element count and must carry a valid, aligned pointer.
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(AbiError::Misaligned);
    }
    if pointer & (alignment - 1) != 0 {
        return Err(AbiError::Misaligned);
    }
    let bytes = count
        .checked_mul(u64::from(stride))
        .ok_or(AbiError::Overflow)?;
    if bytes > byte_limit {
        return Err(AbiError::LengthLimit);
    }
    let end = u64::from(pointer)
        .checked_add(bytes)
        .ok_or(AbiError::Overflow)?;
    if end > MEMORY32_BYTES || end > memory_len {
        return Err(AbiError::OutOfBounds);
    }
    let start = usize::try_from(pointer).map_err(|_| AbiError::OutOfBounds)?;
    let end = usize::try_from(end).map_err(|_| AbiError::OutOfBounds)?;
    Ok(start..end)
}

pub fn lift_bytes<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    length: u32,
) -> Result<Vec<u8>, AbiError> {
    checked_span(
        pointer,
        u64::from(length),
        1,
        1,
        memory.len(),
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length as usize)
        .map_err(|_| AbiError::LengthLimit)?;
    bytes.resize(length as usize, 0);
    memory.read_exact(pointer, &mut bytes)?;
    Ok(bytes)
}

pub fn lift_utf8<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    length: u32,
) -> Result<String, AbiError> {
    if length as usize > PROFILE_1_LIMITS.max_string_bytes {
        return Err(AbiError::LengthLimit);
    }
    let bytes = lift_bytes(memory, pointer, length)?;
    String::from_utf8(bytes).map_err(|_| AbiError::InvalidUtf8)
}

pub fn lift_bool(raw: i32) -> Result<bool, AbiError> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AbiError::InvalidBool),
    }
}

pub fn lift_char(raw: i32) -> Result<char, AbiError> {
    u32::try_from(raw)
        .ok()
        .and_then(char::from_u32)
        .ok_or(AbiError::InvalidChar)
}

pub fn lift_discriminant(raw: i32, cases: u32) -> Result<u32, AbiError> {
    let value = u32::try_from(raw).map_err(|_| AbiError::InvalidDiscriminant)?;
    (value < cases)
        .then_some(value)
        .ok_or(AbiError::InvalidDiscriminant)
}

fn read_array<const N: usize, M: GuestMemory>(
    memory: &M,
    pointer: u32,
    alignment: u32,
) -> Result<[u8; N], AbiError> {
    checked_span(pointer, 1, N as u32, alignment, memory.len(), 1, N as u64)?;
    let mut bytes = [0; N];
    memory.read_exact(pointer, &mut bytes)?;
    Ok(bytes)
}

fn write_array<const N: usize, M: GuestMemory>(
    memory: &mut M,
    pointer: u32,
    alignment: u32,
    bytes: [u8; N],
) -> Result<(), AbiError> {
    checked_span(pointer, 1, N as u32, alignment, memory.len(), 1, N as u64)?;
    memory.write_exact(pointer, &bytes)
}

macro_rules! integer_accessors {
    ($(($lift:ident, $lower:ident, $ty:ty, $size:expr)),* $(,)?) => {$ (
        pub fn $lift<M: GuestMemory>(memory: &M, pointer: u32) -> Result<$ty, AbiError> {
            Ok(<$ty>::from_le_bytes(read_array::<$size, _>(memory, pointer, $size as u32)?))
        }

        pub fn $lower<M: GuestMemory>(
            memory: &mut M,
            pointer: u32,
            value: $ty,
        ) -> Result<(), AbiError> {
            write_array(memory, pointer, $size as u32, value.to_le_bytes())
        }
    )* };
}

integer_accessors!(
    (lift_u8, lower_u8, u8, 1),
    (lift_u16, lower_u16, u16, 2),
    (lift_u32, lower_u32, u32, 4),
    (lift_u64, lower_u64, u64, 8),
    (lift_s8, lower_s8, i8, 1),
    (lift_s16, lower_s16, i16, 2),
    (lift_s32, lower_s32, i32, 4),
    (lift_s64, lower_s64, i64, 8),
);

pub fn lift_u32_list<M: GuestMemory>(
    memory: &M,
    pointer: u32,
    length: u32,
) -> Result<Vec<u32>, AbiError> {
    let range = checked_span(
        pointer,
        u64::from(length),
        4,
        4,
        memory.len(),
        PROFILE_1_LIMITS.max_list_elements as u64,
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
    )?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(range.len())
        .map_err(|_| AbiError::LengthLimit)?;
    raw.resize(range.len(), 0);
    memory.read_exact(pointer, &mut raw)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(length as usize)
        .map_err(|_| AbiError::LengthLimit)?;
    for bytes in raw.chunks_exact(4) {
        values.push(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    Ok(values)
}

pub fn lower_u32_list<M: GuestMemory>(
    memory: &mut M,
    pointer: u32,
    values: &[u32],
) -> Result<(), AbiError> {
    let count = u64::try_from(values.len()).map_err(|_| AbiError::ElementLimit)?;
    checked_span(
        pointer,
        count,
        4,
        4,
        memory.len(),
        PROFILE_1_LIMITS.max_list_elements as u64,
        PROFILE_1_LIMITS.max_canonical_value_bytes as u64,
    )?;
    for (index, value) in values.iter().enumerate() {
        let offset = u32::try_from(index.checked_mul(4).ok_or(AbiError::Overflow)?)
            .map_err(|_| AbiError::Overflow)?;
        lower_u32(
            memory,
            pointer.checked_add(offset).ok_or(AbiError::Overflow)?,
            *value,
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub pointer: u32,
    pub size: u32,
    pub alignment: u32,
}

#[derive(Debug, Default)]
pub(crate) struct AllocationJournal {
    allocations: Vec<Allocation>,
}

impl AllocationJournal {
    pub(crate) fn reserve_one(&mut self) -> Result<(), AbiError> {
        if self.allocations.len() >= PROFILE_1_LIMITS.max_cleanup_actions as usize {
            return Err(AbiError::CleanupLimit);
        }
        self.allocations
            .try_reserve(1)
            .map_err(|_| AbiError::CleanupLimit)
    }

    pub(crate) fn record_reserved(&mut self, allocation: Allocation) -> Result<(), AbiError> {
        if self.allocations.len() == self.allocations.capacity() {
            return Err(AbiError::CleanupLimit);
        }
        self.allocations.push(allocation);
        Ok(())
    }

    pub(crate) fn overlaps(&self, candidate: Allocation) -> bool {
        let candidate_start = u64::from(candidate.pointer);
        let candidate_end = candidate_start + u64::from(candidate.size);
        self.allocations.iter().any(|allocation| {
            let start = u64::from(allocation.pointer);
            let end = start + u64::from(allocation.size);
            candidate_start < end && start < candidate_end
        })
    }

    pub(crate) fn pop(&mut self) -> Option<Allocation> {
        self.allocations.pop()
    }

    pub(crate) fn clear(&mut self) {
        self.allocations.clear();
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }
}
