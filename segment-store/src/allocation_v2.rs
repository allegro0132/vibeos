//! Canonical M7.5 allocation-map payload.
//!
//! Version 1 recorded only an unavailable prefix.  Version 2 records every
//! admitted segment in a two-bit map and carries an exact retirement-generation
//! table for segments which cannot be recycled until an older reader epoch has
//! quiesced.  The packed form is retained in memory, so decode memory is bounded
//! by the same one-extent limit as the authenticated payload.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::codec::AllocationState;

pub const ALLOCATION_V2_VERSION: u16 = 2;
pub const ALLOCATION_V2_HEADER_LEN: usize = 0x80;
pub const RETIRED_SEGMENT_ENTRY_LEN: usize = 0x10;
/// Allocation metadata remains one Storage V2 metadata extent (256 pages).
pub const MAX_ALLOCATION_V2_PAYLOAD_LEN: usize = 256 * 4096;
/// Maximum admitted segments when none is retired.
pub const MAX_ALLOCATION_V2_SEGMENTS: usize =
    (MAX_ALLOCATION_V2_PAYLOAD_LEN - ALLOCATION_V2_HEADER_LEN) * 4;

const ALLOCATION_MAGIC: &[u8; 8] = b"VIBEALC2";
const SEGMENT_STATE_BITS: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SegmentAllocation {
    Free = 0,
    Allocated = 1,
    Retired = 2,
}

impl SegmentAllocation {
    fn from_raw(raw: u8) -> Result<Self, AllocationV2Error> {
        match raw {
            0 => Ok(Self::Free),
            1 => Ok(Self::Allocated),
            2 => Ok(Self::Retired),
            _ => Err(AllocationV2Error::InvalidState),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredSegment {
    pub segment_no: u64,
    /// Checkpoint/extent-map generation after which this segment was removed
    /// from the live map.  It may be recycled only after older readers drain.
    pub retire_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationV2 {
    pub checkpoint_generation: u64,
    pub admitted_segments: u64,
    pub next_segment_generation: u64,
    pub cleaner_reserve_segments: u32,
    bitmap: Vec<u8>,
    retired: Vec<RetiredSegment>,
}

/// One immutable allocation-map transition.  Each list must be strictly
/// sorted, unique, and disjoint from the other two lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationTransition<'a> {
    /// New checkpoint generation which will own the rebuilt map.
    pub checkpoint_generation: u64,
    /// First segment generation not yet assigned after this transaction.
    pub next_segment_generation: u64,
    /// Exact `Free -> Allocated` transitions.
    pub allocate: &'a [u64],
    /// Exact `Allocated -> Retired` transitions.  Their retire generation is
    /// the new checkpoint generation.
    pub retire: &'a [u64],
    /// Exact `Retired -> Free` transitions after reader quiescence.
    pub reclaim: &'a [u64],
}

impl AllocationV2 {
    pub fn new(
        checkpoint_generation: u64,
        next_segment_generation: u64,
        cleaner_reserve_segments: u32,
        states: &[SegmentAllocation],
        retired: &[RetiredSegment],
    ) -> Result<Self, AllocationV2Error> {
        if states.is_empty() || states.len() > MAX_ALLOCATION_V2_SEGMENTS {
            return Err(AllocationV2Error::OutOfBounds);
        }
        let bitmap_len = bitmap_len(states.len() as u64)?;
        let mut bitmap = vec![0_u8; bitmap_len];
        for (index, state) in states.iter().copied().enumerate() {
            set_raw_state(&mut bitmap, index, state as u8);
        }
        let mut retired_copy = Vec::new();
        retired_copy
            .try_reserve_exact(retired.len())
            .map_err(|_| AllocationV2Error::OutOfBounds)?;
        retired_copy.extend_from_slice(retired);
        let value = Self {
            checkpoint_generation,
            admitted_segments: states.len() as u64,
            next_segment_generation,
            cleaner_reserve_segments,
            bitmap,
            retired: retired_copy,
        };
        validate_allocation(&value)?;
        Ok(value)
    }

    /// Converts the frozen M7.3 prefix representation without reinterpreting
    /// its unavailable prefix: prefix entries become Allocated and the exact
    /// suffix becomes Free.  Version 1 has no retired state.
    pub fn from_v1_prefix(value: AllocationState) -> Result<Self, AllocationV2Error> {
        let admitted =
            usize::try_from(value.admitted_segments).map_err(|_| AllocationV2Error::OutOfBounds)?;
        let allocated = usize::try_from(value.allocated_prefix_segments)
            .map_err(|_| AllocationV2Error::OutOfBounds)?;
        if admitted == 0 || admitted > MAX_ALLOCATION_V2_SEGMENTS || allocated > admitted {
            return Err(AllocationV2Error::OutOfBounds);
        }
        let mut bitmap = vec![0_u8; bitmap_len(value.admitted_segments)?];
        let full_bytes = allocated / 4;
        bitmap[..full_bytes].fill(0x55);
        for index in full_bytes * 4..allocated {
            set_raw_state(&mut bitmap, index, SegmentAllocation::Allocated as u8);
        }
        let converted = Self {
            checkpoint_generation: value.checkpoint_generation,
            admitted_segments: value.admitted_segments,
            next_segment_generation: value.next_segment_generation,
            cleaner_reserve_segments: value.cleaner_reserve_segments,
            bitmap,
            retired: Vec::new(),
        };
        validate_allocation(&converted)?;
        Ok(converted)
    }

    pub fn segment_state(&self, segment_no: u64) -> Option<SegmentAllocation> {
        if segment_no >= self.admitted_segments {
            return None;
        }
        let index = usize::try_from(segment_no).ok()?;
        SegmentAllocation::from_raw(raw_state(&self.bitmap, index)).ok()
    }

    pub fn retire_generation(&self, segment_no: u64) -> Option<u64> {
        self.retired
            .binary_search_by_key(&segment_no, |entry| entry.segment_no)
            .ok()
            .map(|index| self.retired[index].retire_generation)
    }

    pub fn retired_segments(&self) -> &[RetiredSegment] {
        &self.retired
    }

    /// Exact packed-map bytes.  Exposed for bounded accounting, not mutation.
    pub fn packed_bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.bitmap.capacity().checked_add(
            self.retired
                .capacity()
                .checked_mul(core::mem::size_of::<RetiredSegment>())?,
        )
    }

    pub fn counts(&self) -> Result<AllocationCounts, AllocationV2Error> {
        count_states(self)
    }

    /// Rebuilds this map for a newer checkpoint without mutating the selected
    /// map.  All requested state preconditions are checked before any result is
    /// returned.  The rebuilt retirement table is canonicalized by segment
    /// number and revalidated together with the cleaner reserve.
    pub fn apply_transition(
        &self,
        transition: AllocationTransition<'_>,
    ) -> Result<Self, AllocationV2Error> {
        validate_allocation(self)?;
        if transition.checkpoint_generation <= self.checkpoint_generation
            || transition.next_segment_generation < self.next_segment_generation
            || (!transition.allocate.is_empty()
                && transition.next_segment_generation == self.next_segment_generation)
        {
            return Err(AllocationV2Error::InvalidTransition);
        }
        validate_transition_list(transition.allocate)?;
        validate_transition_list(transition.retire)?;
        validate_transition_list(transition.reclaim)?;
        if lists_intersect(transition.allocate, transition.retire)
            || lists_intersect(transition.allocate, transition.reclaim)
            || lists_intersect(transition.retire, transition.reclaim)
        {
            return Err(AllocationV2Error::InvalidTransition);
        }
        for (segments, expected) in [
            (transition.allocate, SegmentAllocation::Free),
            (transition.retire, SegmentAllocation::Allocated),
            (transition.reclaim, SegmentAllocation::Retired),
        ] {
            for segment_no in segments {
                if self.segment_state(*segment_no) != Some(expected) {
                    return Err(AllocationV2Error::InvalidTransition);
                }
            }
        }

        let mut bitmap = self.bitmap.clone();
        for segment_no in transition.allocate {
            replace_raw_state(
                &mut bitmap,
                *segment_no as usize,
                SegmentAllocation::Allocated as u8,
            );
        }
        for segment_no in transition.retire {
            replace_raw_state(
                &mut bitmap,
                *segment_no as usize,
                SegmentAllocation::Retired as u8,
            );
        }
        for segment_no in transition.reclaim {
            replace_raw_state(
                &mut bitmap,
                *segment_no as usize,
                SegmentAllocation::Free as u8,
            );
        }

        let retained_count = self
            .retired
            .len()
            .checked_sub(transition.reclaim.len())
            .ok_or(AllocationV2Error::InvalidTransition)?;
        let rebuilt_count = retained_count
            .checked_add(transition.retire.len())
            .ok_or(AllocationV2Error::ArithmeticOverflow)?;
        let mut retired = Vec::new();
        retired
            .try_reserve_exact(rebuilt_count)
            .map_err(|_| AllocationV2Error::OutOfBounds)?;
        for entry in &self.retired {
            if transition.reclaim.binary_search(&entry.segment_no).is_err() {
                retired.push(*entry);
            }
        }
        for segment_no in transition.retire {
            retired.push(RetiredSegment {
                segment_no: *segment_no,
                retire_generation: transition.checkpoint_generation,
            });
        }
        retired.sort_unstable_by_key(|entry| entry.segment_no);

        let rebuilt = Self {
            checkpoint_generation: transition.checkpoint_generation,
            admitted_segments: self.admitted_segments,
            next_segment_generation: transition.next_segment_generation,
            cleaner_reserve_segments: self.cleaner_reserve_segments,
            bitmap,
            retired,
        };
        validate_allocation(&rebuilt)?;
        Ok(rebuilt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationCounts {
    pub free: u64,
    pub allocated: u64,
    pub retired: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationV2Error {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    InvalidState,
    InvalidTransition,
    NonZeroReserved,
    OutOfBounds,
    RetirementMismatch,
    UnsortedOrDuplicate,
}

impl fmt::Display for AllocationV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "allocation-v2 arithmetic overflowed",
            Self::InvalidField => "allocation-v2 contains an invalid field",
            Self::InvalidLength => "allocation-v2 has a non-canonical length",
            Self::InvalidMagic => "allocation-v2 magic is invalid",
            Self::InvalidState => "allocation-v2 contains an invalid two-bit state",
            Self::InvalidTransition => "allocation-v2 transition preconditions are invalid",
            Self::NonZeroReserved => "allocation-v2 reserved bytes or tail bits are non-zero",
            Self::OutOfBounds => "allocation-v2 exceeds its fixed metadata bound",
            Self::RetirementMismatch => "allocation-v2 retirement table does not match its map",
            Self::UnsortedOrDuplicate => "allocation-v2 retirement table is not strictly sorted",
        })
    }
}

impl core::error::Error for AllocationV2Error {}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed field"))
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}

fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn bitmap_len(admitted_segments: u64) -> Result<usize, AllocationV2Error> {
    let bytes = admitted_segments
        .checked_add(3)
        .ok_or(AllocationV2Error::ArithmeticOverflow)?
        / 4;
    usize::try_from(bytes).map_err(|_| AllocationV2Error::OutOfBounds)
}

fn raw_state(bitmap: &[u8], index: usize) -> u8 {
    (bitmap[index / 4] >> ((index % 4) * 2)) & 0x03
}

fn set_raw_state(bitmap: &mut [u8], index: usize, state: u8) {
    let shift = (index % 4) * 2;
    bitmap[index / 4] |= state << shift;
}

fn replace_raw_state(bitmap: &mut [u8], index: usize, state: u8) {
    let shift = (index % 4) * 2;
    bitmap[index / 4] = (bitmap[index / 4] & !(0x03 << shift)) | (state << shift);
}

fn validate_transition_list(segments: &[u64]) -> Result<(), AllocationV2Error> {
    if segments.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(AllocationV2Error::InvalidTransition)
    } else {
        Ok(())
    }
}

fn lists_intersect(left: &[u64], right: &[u64]) -> bool {
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Greater => right_index += 1,
            core::cmp::Ordering::Equal => return true,
        }
    }
    false
}

fn encoded_len(bitmap_bytes: usize, retired_count: usize) -> Result<usize, AllocationV2Error> {
    ALLOCATION_V2_HEADER_LEN
        .checked_add(bitmap_bytes)
        .and_then(|length| {
            retired_count
                .checked_mul(RETIRED_SEGMENT_ENTRY_LEN)
                .and_then(|table| length.checked_add(table))
        })
        .ok_or(AllocationV2Error::ArithmeticOverflow)
}

fn validate_tail_bits(value: &AllocationV2) -> Result<(), AllocationV2Error> {
    let remainder = (value.admitted_segments % 4) as u8;
    if remainder == 0 {
        return Ok(());
    }
    let used_bits = remainder * 2;
    let unused_mask = !((1_u8 << used_bits) - 1);
    if value.bitmap.last().copied().unwrap_or(0) & unused_mask != 0 {
        Err(AllocationV2Error::NonZeroReserved)
    } else {
        Ok(())
    }
}

fn count_states(value: &AllocationV2) -> Result<AllocationCounts, AllocationV2Error> {
    let admitted =
        usize::try_from(value.admitted_segments).map_err(|_| AllocationV2Error::OutOfBounds)?;
    let mut counts = AllocationCounts {
        free: 0,
        allocated: 0,
        retired: 0,
    };
    for index in 0..admitted {
        match SegmentAllocation::from_raw(raw_state(&value.bitmap, index))? {
            SegmentAllocation::Free => counts.free += 1,
            SegmentAllocation::Allocated => counts.allocated += 1,
            SegmentAllocation::Retired => counts.retired += 1,
        }
    }
    let total = counts
        .free
        .checked_add(counts.allocated)
        .and_then(|count| count.checked_add(counts.retired))
        .ok_or(AllocationV2Error::ArithmeticOverflow)?;
    if total != value.admitted_segments {
        return Err(AllocationV2Error::InvalidField);
    }
    Ok(counts)
}

fn validate_allocation(value: &AllocationV2) -> Result<AllocationCounts, AllocationV2Error> {
    if value.checkpoint_generation == 0
        || value.admitted_segments == 0
        || value.next_segment_generation == 0
        || value.cleaner_reserve_segments == 0
        || u64::from(value.cleaner_reserve_segments) >= value.admitted_segments
    {
        return Err(AllocationV2Error::InvalidField);
    }
    let admitted =
        usize::try_from(value.admitted_segments).map_err(|_| AllocationV2Error::OutOfBounds)?;
    if admitted > MAX_ALLOCATION_V2_SEGMENTS
        || value.bitmap.len() != bitmap_len(value.admitted_segments)?
        || encoded_len(value.bitmap.len(), value.retired.len())? > MAX_ALLOCATION_V2_PAYLOAD_LEN
    {
        return Err(AllocationV2Error::OutOfBounds);
    }
    validate_tail_bits(value)?;
    let counts = count_states(value)?;
    if counts
        .free
        .checked_add(counts.retired)
        .ok_or(AllocationV2Error::ArithmeticOverflow)?
        < u64::from(value.cleaner_reserve_segments)
        || counts.retired != value.retired.len() as u64
    {
        return Err(AllocationV2Error::RetirementMismatch);
    }
    let mut previous = None;
    for entry in &value.retired {
        if previous.is_some_and(|segment_no| segment_no >= entry.segment_no) {
            return Err(AllocationV2Error::UnsortedOrDuplicate);
        }
        if entry.segment_no >= value.admitted_segments
            || entry.retire_generation == 0
            || entry.retire_generation > value.checkpoint_generation
            || value.segment_state(entry.segment_no) != Some(SegmentAllocation::Retired)
        {
            return Err(AllocationV2Error::RetirementMismatch);
        }
        previous = Some(entry.segment_no);
    }
    Ok(counts)
}

pub fn encode_allocation_v2(value: &AllocationV2) -> Result<Vec<u8>, AllocationV2Error> {
    let counts = validate_allocation(value)?;
    let encoded_len = encoded_len(value.bitmap.len(), value.retired.len())?;
    let retirement_offset = ALLOCATION_V2_HEADER_LEN
        .checked_add(value.bitmap.len())
        .ok_or(AllocationV2Error::ArithmeticOverflow)?;
    let mut out = vec![0_u8; encoded_len];
    out[0x00..0x08].copy_from_slice(ALLOCATION_MAGIC);
    put_u16(&mut out, 0x08, ALLOCATION_V2_VERSION);
    put_u16(&mut out, 0x0a, ALLOCATION_V2_HEADER_LEN as u16);
    put_u64(&mut out, 0x10, value.checkpoint_generation);
    put_u64(&mut out, 0x18, value.admitted_segments);
    put_u64(&mut out, 0x20, value.next_segment_generation);
    put_u32(&mut out, 0x28, value.cleaner_reserve_segments);
    put_u16(&mut out, 0x2c, SEGMENT_STATE_BITS);
    put_u16(&mut out, 0x2e, RETIRED_SEGMENT_ENTRY_LEN as u16);
    put_u64(&mut out, 0x30, ALLOCATION_V2_HEADER_LEN as u64);
    put_u64(&mut out, 0x38, value.bitmap.len() as u64);
    put_u64(&mut out, 0x40, retirement_offset as u64);
    put_u64(&mut out, 0x48, value.retired.len() as u64);
    put_u64(&mut out, 0x50, counts.free);
    put_u64(&mut out, 0x58, counts.allocated);
    put_u64(&mut out, 0x60, counts.retired);
    put_u64(&mut out, 0x68, encoded_len as u64);
    out[ALLOCATION_V2_HEADER_LEN..retirement_offset].copy_from_slice(&value.bitmap);
    for (index, entry) in value.retired.iter().enumerate() {
        let offset = retirement_offset + index * RETIRED_SEGMENT_ENTRY_LEN;
        put_u64(&mut out, offset, entry.segment_no);
        put_u64(&mut out, offset + 8, entry.retire_generation);
    }
    Ok(out)
}

pub fn decode_allocation_v2(input: &[u8]) -> Result<AllocationV2, AllocationV2Error> {
    if input.len() < ALLOCATION_V2_HEADER_LEN || input.len() > MAX_ALLOCATION_V2_PAYLOAD_LEN {
        return Err(AllocationV2Error::InvalidLength);
    }
    if &input[0x00..0x08] != ALLOCATION_MAGIC {
        return Err(AllocationV2Error::InvalidMagic);
    }
    if get_u16(input, 0x08) != ALLOCATION_V2_VERSION
        || get_u16(input, 0x0a) as usize != ALLOCATION_V2_HEADER_LEN
        || get_u16(input, 0x2c) != SEGMENT_STATE_BITS
        || get_u16(input, 0x2e) as usize != RETIRED_SEGMENT_ENTRY_LEN
        || get_u64(input, 0x30) != ALLOCATION_V2_HEADER_LEN as u64
    {
        return Err(AllocationV2Error::InvalidField);
    }
    if get_u32(input, 0x0c) != 0 || !is_zero(&input[0x70..0x80]) {
        return Err(AllocationV2Error::NonZeroReserved);
    }

    let admitted_segments = get_u64(input, 0x18);
    let expected_bitmap_len = bitmap_len(admitted_segments)?;
    let declared_bitmap_len =
        usize::try_from(get_u64(input, 0x38)).map_err(|_| AllocationV2Error::InvalidLength)?;
    let retirement_offset = ALLOCATION_V2_HEADER_LEN
        .checked_add(expected_bitmap_len)
        .ok_or(AllocationV2Error::ArithmeticOverflow)?;
    let retired_count =
        usize::try_from(get_u64(input, 0x48)).map_err(|_| AllocationV2Error::InvalidLength)?;
    let expected_len = encoded_len(expected_bitmap_len, retired_count)?;
    if declared_bitmap_len != expected_bitmap_len
        || get_u64(input, 0x40) != retirement_offset as u64
        || get_u64(input, 0x68) != expected_len as u64
        || expected_len > MAX_ALLOCATION_V2_PAYLOAD_LEN
        || input.len() != expected_len
    {
        return Err(AllocationV2Error::InvalidLength);
    }

    let mut bitmap = Vec::new();
    bitmap
        .try_reserve_exact(expected_bitmap_len)
        .map_err(|_| AllocationV2Error::OutOfBounds)?;
    bitmap.extend_from_slice(&input[ALLOCATION_V2_HEADER_LEN..retirement_offset]);
    let mut retired = Vec::new();
    retired
        .try_reserve_exact(retired_count)
        .map_err(|_| AllocationV2Error::OutOfBounds)?;
    for index in 0..retired_count {
        let offset = retirement_offset + index * RETIRED_SEGMENT_ENTRY_LEN;
        retired.push(RetiredSegment {
            segment_no: get_u64(input, offset),
            retire_generation: get_u64(input, offset + 8),
        });
    }
    let value = AllocationV2 {
        checkpoint_generation: get_u64(input, 0x10),
        admitted_segments,
        next_segment_generation: get_u64(input, 0x20),
        cleaner_reserve_segments: get_u32(input, 0x28),
        bitmap,
        retired,
    };
    let counts = validate_allocation(&value)?;
    if counts.free != get_u64(input, 0x50)
        || counts.allocated != get_u64(input, 0x58)
        || counts.retired != get_u64(input, 0x60)
    {
        return Err(AllocationV2Error::InvalidField);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AllocationV2 {
        AllocationV2::new(
            9,
            41,
            1,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Retired,
                SegmentAllocation::Free,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 1,
                retire_generation: 8,
            }],
        )
        .unwrap()
    }

    #[test]
    fn golden_round_trip_and_exact_two_bit_order() {
        let value = sample();
        let encoded = encode_allocation_v2(&value).unwrap();
        assert_eq!(&encoded[0x00..0x08], b"VIBEALC2");
        assert_eq!(&encoded[0x08..0x0a], &2_u16.to_le_bytes());
        assert_eq!(encoded.len(), 0x80 + 2 + 0x10);
        // state pairs, least-significant first: 01,10,00,01 / 00
        assert_eq!(&encoded[0x80..0x82], &[0x49, 0x00]);
        assert_eq!(
            &encoded[0x82..0x92],
            &[1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(decode_allocation_v2(&encoded).unwrap(), value);
    }

    #[test]
    fn corrupt_state_tail_counts_reserved_and_retirement_fail_closed() {
        let encoded = encode_allocation_v2(&sample()).unwrap();
        for (offset, xor) in [(0x0c, 1), (0x70, 1), (0x81, 0x04), (0x50, 1)] {
            let mut corrupt = encoded.clone();
            corrupt[offset] ^= xor;
            assert!(
                decode_allocation_v2(&corrupt).is_err(),
                "offset {offset:#x}"
            );
        }
        let mut bad_state = encoded.clone();
        bad_state[0x80] = (bad_state[0x80] & !0x0c) | 0x0c;
        assert_eq!(
            decode_allocation_v2(&bad_state),
            Err(AllocationV2Error::InvalidState)
        );
        for generation in [0_u64, 10] {
            let mut corrupt = encoded.clone();
            corrupt[0x8a..0x92].copy_from_slice(&generation.to_le_bytes());
            assert_eq!(
                decode_allocation_v2(&corrupt),
                Err(AllocationV2Error::RetirementMismatch)
            );
        }
        assert_eq!(
            decode_allocation_v2(&encoded[..encoded.len() - 1]),
            Err(AllocationV2Error::InvalidLength)
        );
    }

    #[test]
    fn prefix_conversion_is_exact_and_reserve_remains_free() {
        let v1 = AllocationState {
            checkpoint_generation: 7,
            admitted_segments: 9,
            allocated_prefix_segments: 5,
            next_segment_generation: 14,
            cleaner_reserve_segments: 2,
        };
        let converted = AllocationV2::from_v1_prefix(v1).unwrap();
        for segment_no in 0..5 {
            assert_eq!(
                converted.segment_state(segment_no),
                Some(SegmentAllocation::Allocated)
            );
        }
        for segment_no in 5..9 {
            assert_eq!(
                converted.segment_state(segment_no),
                Some(SegmentAllocation::Free)
            );
        }
        assert!(converted.retired_segments().is_empty());
        assert_eq!(converted.packed_bitmap(), &[0x55, 0x01, 0x00]);
    }

    #[test]
    fn fixed_payload_boundary_and_overflow_headers_are_rejected() {
        let states = vec![SegmentAllocation::Free; MAX_ALLOCATION_V2_SEGMENTS];
        let value = AllocationV2::new(1, 1, 1, &states, &[]).unwrap();
        assert_eq!(
            encode_allocation_v2(&value).unwrap().len(),
            MAX_ALLOCATION_V2_PAYLOAD_LEN
        );
        let too_many = vec![SegmentAllocation::Free; MAX_ALLOCATION_V2_SEGMENTS + 1];
        assert_eq!(
            AllocationV2::new(1, 1, 1, &too_many, &[]),
            Err(AllocationV2Error::OutOfBounds)
        );

        let mut encoded = encode_allocation_v2(&sample()).unwrap();
        encoded[0x18..0x20].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode_allocation_v2(&encoded),
            Err(AllocationV2Error::ArithmeticOverflow | AllocationV2Error::InvalidLength)
        ));
    }

    #[test]
    fn immutable_transition_rebuilds_all_three_states_and_retirement_order() {
        let original = AllocationV2::new(
            6,
            20,
            1,
            &[
                SegmentAllocation::Free,
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Retired,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 3,
                retire_generation: 5,
            }],
        )
        .unwrap();
        let rebuilt = original
            .apply_transition(AllocationTransition {
                checkpoint_generation: 7,
                next_segment_generation: 22,
                allocate: &[0],
                retire: &[1],
                reclaim: &[3],
            })
            .unwrap();

        assert_eq!(original.segment_state(0), Some(SegmentAllocation::Free));
        assert_eq!(original.segment_state(3), Some(SegmentAllocation::Retired));
        assert_eq!(rebuilt.checkpoint_generation, 7);
        assert_eq!(rebuilt.next_segment_generation, 22);
        assert_eq!(rebuilt.segment_state(0), Some(SegmentAllocation::Allocated));
        assert_eq!(rebuilt.segment_state(1), Some(SegmentAllocation::Retired));
        assert_eq!(rebuilt.segment_state(3), Some(SegmentAllocation::Free));
        assert_eq!(rebuilt.retire_generation(1), Some(7));
        assert_eq!(rebuilt.retire_generation(3), None);
        assert_eq!(
            decode_allocation_v2(&encode_allocation_v2(&rebuilt).unwrap()).unwrap(),
            rebuilt
        );
    }

    #[test]
    fn transition_rejects_wrong_states_lists_and_generations() {
        let value = sample();
        for transition in [
            AllocationTransition {
                checkpoint_generation: 9,
                next_segment_generation: 42,
                allocate: &[],
                retire: &[],
                reclaim: &[],
            },
            AllocationTransition {
                checkpoint_generation: 10,
                next_segment_generation: 41,
                allocate: &[2],
                retire: &[],
                reclaim: &[],
            },
            AllocationTransition {
                checkpoint_generation: 10,
                next_segment_generation: 42,
                allocate: &[2, 2],
                retire: &[],
                reclaim: &[],
            },
            AllocationTransition {
                checkpoint_generation: 10,
                next_segment_generation: 42,
                allocate: &[2],
                retire: &[2],
                reclaim: &[],
            },
            AllocationTransition {
                checkpoint_generation: 10,
                next_segment_generation: 42,
                allocate: &[0],
                retire: &[],
                reclaim: &[],
            },
        ] {
            assert_eq!(
                value.apply_transition(transition),
                Err(AllocationV2Error::InvalidTransition)
            );
        }

        // A relocation checkpoint may temporarily consume the free reserve,
        // but only when the same transaction retires enough source capacity.
        let relocation = value
            .apply_transition(AllocationTransition {
                checkpoint_generation: 10,
                next_segment_generation: 42,
                allocate: &[2, 4],
                retire: &[0],
                reclaim: &[],
            })
            .unwrap();
        assert_eq!(relocation.counts().unwrap().free, 0);
        assert!(relocation.counts().unwrap().retired >= 1);
    }
}
