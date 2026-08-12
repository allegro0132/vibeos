//! Canonical persistent GC-root-set payload.
//!
//! A zero-entry payload is a real, canonical empty root set.  A null physical
//! pointer is deliberately not represented here: checkpoint policy owns the
//! distinction between "no root-set object" and "an explicit empty root set".

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub const PERSISTENT_ROOT_SET_VERSION: u16 = 1;
pub const PERSISTENT_ROOT_SET_HEADER_LEN: usize = 0x40;
pub const PERSISTENT_ROOT_ENTRY_LEN: usize = 0x20;
pub const MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN: usize = 256 * 4096;
pub const MAX_PERSISTENT_ROOT_ENTRIES: usize = (MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN
    - PERSISTENT_ROOT_SET_HEADER_LEN)
    / PERSISTENT_ROOT_ENTRY_LEN;

const ROOT_SET_MAGIC: &[u8; 8] = b"VIBERST2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentRootEntry {
    pub object_id: u128,
    pub commit_generation: u64,
    pub object_kind: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentRootSet {
    pub checkpoint_generation: u64,
    entries: Vec<PersistentRootEntry>,
}

impl PersistentRootSet {
    pub fn new(
        checkpoint_generation: u64,
        entries: Vec<PersistentRootEntry>,
    ) -> Result<Self, RootCodecError> {
        let value = Self {
            checkpoint_generation,
            entries,
        };
        validate_root_set(&value)?;
        Ok(value)
    }

    pub fn entries(&self) -> &[PersistentRootEntry] {
        &self.entries
    }

    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.entries
            .capacity()
            .checked_mul(core::mem::size_of::<PersistentRootEntry>())
    }

    pub fn into_entries(self) -> Vec<PersistentRootEntry> {
        self.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCodecError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    NonZeroReserved,
    OutOfBounds,
    UnsortedOrDuplicate,
}

impl fmt::Display for RootCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "persistent root-set arithmetic overflowed",
            Self::InvalidField => "persistent root-set contains an invalid field",
            Self::InvalidLength => "persistent root-set has a non-canonical length",
            Self::InvalidMagic => "persistent root-set magic is invalid",
            Self::NonZeroReserved => "persistent root-set reserved bytes or flags are non-zero",
            Self::OutOfBounds => "persistent root-set exceeds its fixed metadata bound",
            Self::UnsortedOrDuplicate => {
                "persistent root-set entries are not strictly ordered by ObjectId"
            }
        })
    }
}

impl core::error::Error for RootCodecError {}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u128(out: &mut [u8], offset: usize, value: u128) {
    out[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
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

fn get_u128(input: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(input[offset..offset + 16].try_into().expect("fixed field"))
}

fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn encoded_len(entry_count: usize) -> Result<usize, RootCodecError> {
    PERSISTENT_ROOT_SET_HEADER_LEN
        .checked_add(
            entry_count
                .checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
                .ok_or(RootCodecError::ArithmeticOverflow)?,
        )
        .ok_or(RootCodecError::ArithmeticOverflow)
}

fn validate_root_set(value: &PersistentRootSet) -> Result<(), RootCodecError> {
    if value.checkpoint_generation == 0 {
        return Err(RootCodecError::InvalidField);
    }
    if value.entries.len() > MAX_PERSISTENT_ROOT_ENTRIES
        || encoded_len(value.entries.len())? > MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN
    {
        return Err(RootCodecError::OutOfBounds);
    }
    let mut previous = None;
    for entry in &value.entries {
        if entry.object_id == 0
            || entry.object_kind == 0
            || entry.commit_generation == 0
            || entry.commit_generation > value.checkpoint_generation
        {
            return Err(RootCodecError::InvalidField);
        }
        if previous.is_some_and(|object_id| object_id >= entry.object_id) {
            return Err(RootCodecError::UnsortedOrDuplicate);
        }
        previous = Some(entry.object_id);
    }
    Ok(())
}

pub fn encode_persistent_root_set(value: &PersistentRootSet) -> Result<Vec<u8>, RootCodecError> {
    validate_root_set(value)?;
    let encoded_len = encoded_len(value.entries.len())?;
    let mut out = vec![0_u8; encoded_len];
    out[0x00..0x08].copy_from_slice(ROOT_SET_MAGIC);
    put_u16(&mut out, 0x08, PERSISTENT_ROOT_SET_VERSION);
    put_u16(&mut out, 0x0a, PERSISTENT_ROOT_SET_HEADER_LEN as u16);
    put_u64(&mut out, 0x10, value.checkpoint_generation);
    put_u32(&mut out, 0x18, value.entries.len() as u32);
    put_u32(&mut out, 0x1c, PERSISTENT_ROOT_ENTRY_LEN as u32);
    put_u64(&mut out, 0x20, PERSISTENT_ROOT_SET_HEADER_LEN as u64);
    put_u64(&mut out, 0x28, encoded_len as u64);
    for (index, entry) in value.entries.iter().enumerate() {
        let offset = PERSISTENT_ROOT_SET_HEADER_LEN + index * PERSISTENT_ROOT_ENTRY_LEN;
        put_u128(&mut out, offset, entry.object_id);
        put_u64(&mut out, offset + 0x10, entry.commit_generation);
        put_u32(&mut out, offset + 0x18, entry.object_kind);
        // entry flags at +0x1c are zero in refs/root schema v1.
    }
    Ok(out)
}

pub fn decode_persistent_root_set(input: &[u8]) -> Result<PersistentRootSet, RootCodecError> {
    if input.len() < PERSISTENT_ROOT_SET_HEADER_LEN
        || input.len() > MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN
    {
        return Err(RootCodecError::InvalidLength);
    }
    if &input[0x00..0x08] != ROOT_SET_MAGIC {
        return Err(RootCodecError::InvalidMagic);
    }
    if get_u16(input, 0x08) != PERSISTENT_ROOT_SET_VERSION
        || get_u16(input, 0x0a) as usize != PERSISTENT_ROOT_SET_HEADER_LEN
        || get_u32(input, 0x1c) as usize != PERSISTENT_ROOT_ENTRY_LEN
        || get_u64(input, 0x20) != PERSISTENT_ROOT_SET_HEADER_LEN as u64
    {
        return Err(RootCodecError::InvalidField);
    }
    if get_u32(input, 0x0c) != 0 || !is_zero(&input[0x30..0x40]) {
        return Err(RootCodecError::NonZeroReserved);
    }
    let entry_count =
        usize::try_from(get_u32(input, 0x18)).map_err(|_| RootCodecError::InvalidLength)?;
    let expected_len = encoded_len(entry_count)?;
    if entry_count > MAX_PERSISTENT_ROOT_ENTRIES
        || expected_len > MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN
        || get_u64(input, 0x28) != expected_len as u64
        || input.len() != expected_len
    {
        return Err(RootCodecError::InvalidLength);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| RootCodecError::OutOfBounds)?;
    for index in 0..entry_count {
        let offset = PERSISTENT_ROOT_SET_HEADER_LEN + index * PERSISTENT_ROOT_ENTRY_LEN;
        if get_u32(input, offset + 0x1c) != 0 {
            return Err(RootCodecError::NonZeroReserved);
        }
        entries.push(PersistentRootEntry {
            object_id: get_u128(input, offset),
            commit_generation: get_u64(input, offset + 0x10),
            object_kind: get_u32(input, offset + 0x18),
        });
    }
    PersistentRootSet::new(get_u64(input, 0x10), entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PersistentRootSet {
        PersistentRootSet::new(
            12,
            vec![
                PersistentRootEntry {
                    object_id: 1,
                    commit_generation: 7,
                    object_kind: 3,
                },
                PersistentRootEntry {
                    object_id: 0x102,
                    commit_generation: 12,
                    object_kind: 9,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn golden_round_trip_and_explicit_empty_are_canonical() {
        let value = sample();
        let encoded = encode_persistent_root_set(&value).unwrap();
        assert_eq!(&encoded[0x00..0x08], b"VIBERST2");
        assert_eq!(encoded.len(), 0x80);
        assert_eq!(&encoded[0x40..0x50], &1_u128.to_le_bytes());
        assert_eq!(&encoded[0x50..0x58], &7_u64.to_le_bytes());
        assert_eq!(&encoded[0x58..0x5c], &3_u32.to_le_bytes());
        assert_eq!(decode_persistent_root_set(&encoded).unwrap(), value);

        let empty = PersistentRootSet::new(12, Vec::new()).unwrap();
        let empty_bytes = encode_persistent_root_set(&empty).unwrap();
        assert_eq!(empty_bytes.len(), PERSISTENT_ROOT_SET_HEADER_LEN);
        assert_eq!(decode_persistent_root_set(&empty_bytes).unwrap(), empty);
    }

    #[test]
    fn corruption_unsorted_duplicate_flags_reserved_and_suffix_fail_closed() {
        let encoded = encode_persistent_root_set(&sample()).unwrap();
        for offset in [0x0c, 0x30, 0x5c] {
            let mut corrupt = encoded.clone();
            corrupt[offset] = 1;
            assert_eq!(
                decode_persistent_root_set(&corrupt),
                Err(RootCodecError::NonZeroReserved),
                "offset {offset:#x}"
            );
        }
        for second_id in [0_u128, 1] {
            let mut corrupt = encoded.clone();
            corrupt[0x60..0x70].copy_from_slice(&second_id.to_le_bytes());
            assert!(decode_persistent_root_set(&corrupt).is_err());
        }
        let mut suffix = encoded.clone();
        suffix.push(0);
        assert_eq!(
            decode_persistent_root_set(&suffix),
            Err(RootCodecError::InvalidLength)
        );
    }

    #[test]
    fn generation_and_kind_are_bound_to_the_root_snapshot() {
        for entry in [
            PersistentRootEntry {
                object_id: 1,
                commit_generation: 0,
                object_kind: 1,
            },
            PersistentRootEntry {
                object_id: 1,
                commit_generation: 13,
                object_kind: 1,
            },
            PersistentRootEntry {
                object_id: 1,
                commit_generation: 1,
                object_kind: 0,
            },
        ] {
            assert_eq!(
                PersistentRootSet::new(12, vec![entry]),
                Err(RootCodecError::InvalidField)
            );
        }
    }

    #[test]
    fn maximum_table_fits_exactly_and_one_more_is_bounded() {
        let mut entries = Vec::new();
        entries.reserve_exact(MAX_PERSISTENT_ROOT_ENTRIES);
        for index in 0..MAX_PERSISTENT_ROOT_ENTRIES {
            entries.push(PersistentRootEntry {
                object_id: index as u128 + 1,
                commit_generation: 1,
                object_kind: 1,
            });
        }
        let value = PersistentRootSet::new(1, entries.clone()).unwrap();
        assert_eq!(
            encode_persistent_root_set(&value).unwrap().len(),
            PERSISTENT_ROOT_SET_HEADER_LEN
                + MAX_PERSISTENT_ROOT_ENTRIES * PERSISTENT_ROOT_ENTRY_LEN
        );
        entries.push(PersistentRootEntry {
            object_id: MAX_PERSISTENT_ROOT_ENTRIES as u128 + 1,
            commit_generation: 1,
            object_kind: 1,
        });
        assert_eq!(
            PersistentRootSet::new(1, entries),
            Err(RootCodecError::OutOfBounds)
        );
    }
}
