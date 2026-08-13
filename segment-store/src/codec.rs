//! Canonical catalog and allocation payload codecs.
//!
//! These payloads are authenticated by Storage V2 extent descriptors, but the
//! payload decoder still rejects every non-canonical representation before a
//! value can enter recovery state.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_segment_format::{
    decode_physical_pointer, encode_physical_pointer, ExtentKind, FormatError, PhysicalPointer,
    StoreUuid, MAX_EXTENT_PAYLOAD_PAGES, PAGE_SIZE, POINTER_SIZE,
};

pub const CATALOG_SNAPSHOT_HEADER_LEN: usize = 0x40;
pub const CATALOG_DELTA_HEADER_LEN: usize = 0xa0;
pub const CATALOG_ENTRY_LEN: usize = 0xb0;
pub const CATALOG_DELTA_PAYLOAD_LEN: usize = CATALOG_DELTA_HEADER_LEN + CATALOG_ENTRY_LEN;
pub const ALLOCATION_PAYLOAD_LEN: usize = 0x40;

const CATALOG_MAGIC: &[u8; 8] = b"VIBECAT2";
const ALLOCATION_MAGIC: &[u8; 8] = b"VIBEALC2";
const PAYLOAD_VERSION: u16 = 1;
const MAX_METADATA_PAYLOAD_LEN: usize = MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CatalogPayloadKind {
    Snapshot = 1,
    Delta = 2,
}

impl CatalogPayloadKind {
    fn from_raw(raw: u16) -> Result<Self, CodecError> {
        match raw {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Delta),
            _ => Err(CodecError::InvalidField),
        }
    }

    const fn header_len(self) -> usize {
        match self {
            Self::Snapshot => CATALOG_SNAPSHOT_HEADER_LEN,
            Self::Delta => CATALOG_DELTA_HEADER_LEN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub object_id: u128,
    pub object_kind: u32,
    pub exact_len: u64,
    pub commit_generation: u64,
    pub content_root: [u8; 32],
    pub blob: PhysicalPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationState {
    pub checkpoint_generation: u64,
    pub admitted_segments: u64,
    /// Every physical segment below this cursor is unavailable to the normal
    /// allocator. Recovery may reuse only the tail at or above this cursor,
    /// after the canonical final-seal zero gate.
    pub allocated_prefix_segments: u64,
    pub next_segment_generation: u64,
    pub cleaner_reserve_segments: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogPayload {
    pub kind: CatalogPayloadKind,
    pub checkpoint_generation: u64,
    pub chain_count: u64,
    pub previous_delta: PhysicalPointer,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    InvalidPointer,
    NonZeroReserved,
    Format(FormatError),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "catalog payload arithmetic overflowed",
            Self::InvalidField => "catalog payload contains an invalid field",
            Self::InvalidLength => "catalog payload has a non-canonical length",
            Self::InvalidMagic => "catalog payload magic is invalid",
            Self::InvalidPointer => "catalog payload pointer is invalid",
            Self::NonZeroReserved => "catalog payload reserved bytes are non-zero",
            Self::Format(_) => "catalog payload contains a malformed physical pointer",
        })
    }
}

impl From<FormatError> for CodecError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

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
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixed-width slice"),
    )
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed-width slice"),
    )
}

fn get_u128(input: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(
        input[offset..offset + 16]
            .try_into()
            .expect("fixed-width slice"),
    )
}

fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn empty_sha256() -> [u8; 32] {
    Sha256::digest(b"")
        .as_slice()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

fn expected_catalog_len(kind: CatalogPayloadKind, entry_count: usize) -> Result<usize, CodecError> {
    kind.header_len()
        .checked_add(
            entry_count
                .checked_mul(CATALOG_ENTRY_LEN)
                .ok_or(CodecError::ArithmeticOverflow)?,
        )
        .ok_or(CodecError::ArithmeticOverflow)
}

fn validate_blob_pointer(
    pointer: PhysicalPointer,
    store_uuid: StoreUuid,
    exact_len: u64,
    content_root: [u8; 32],
) -> Result<(), CodecError> {
    match pointer {
        PhysicalPointer::Null => {
            if exact_len != 0 || content_root != empty_sha256() {
                return Err(CodecError::InvalidPointer);
            }
        }
        PhysicalPointer::Value(value) => {
            if exact_len == 0
                || value.store_uuid != store_uuid
                || value.extent_kind != ExtentKind::Blob
                || value.exact_byte_len != exact_len
                || value.payload_sha256 != content_root
            {
                return Err(CodecError::InvalidPointer);
            }
            // Exercise the canonical pointer validator on encode as well as
            // decode. It checks page rounding, descriptor/payload adjacency,
            // non-zero generation/ordinal, and append-area containment.
            let mut encoded = [0; POINTER_SIZE];
            encode_physical_pointer(pointer, &mut encoded)?;
        }
    }
    Ok(())
}

fn validate_entry(
    entry: &CatalogEntry,
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    kind: CatalogPayloadKind,
) -> Result<(), CodecError> {
    if entry.object_id == 0
        || entry.object_kind == 0
        || entry.commit_generation == 0
        || entry.commit_generation > checkpoint_generation
        || (kind == CatalogPayloadKind::Delta && entry.commit_generation != checkpoint_generation)
    {
        return Err(CodecError::InvalidField);
    }
    validate_blob_pointer(entry.blob, store_uuid, entry.exact_len, entry.content_root)
}

fn validate_delta_pointer(
    pointer: PhysicalPointer,
    store_uuid: StoreUuid,
    chain_count: u64,
) -> Result<(), CodecError> {
    match (chain_count, pointer) {
        (1, PhysicalPointer::Null) => Ok(()),
        (2.., PhysicalPointer::Value(value))
            if value.store_uuid == store_uuid
                && value.extent_kind == ExtentKind::CatalogDelta
                && value.exact_byte_len == CATALOG_DELTA_PAYLOAD_LEN as u64 =>
        {
            let mut encoded = [0; POINTER_SIZE];
            encode_physical_pointer(pointer, &mut encoded)?;
            Ok(())
        }
        _ => Err(CodecError::InvalidPointer),
    }
}

fn validate_catalog(payload: &CatalogPayload, store_uuid: StoreUuid) -> Result<(), CodecError> {
    if payload.checkpoint_generation == 0 || payload.entries.is_empty() {
        return Err(CodecError::InvalidField);
    }
    let expected_len = expected_catalog_len(payload.kind, payload.entries.len())?;
    if expected_len > MAX_METADATA_PAYLOAD_LEN {
        return Err(CodecError::InvalidLength);
    }
    match payload.kind {
        CatalogPayloadKind::Snapshot => {
            let count =
                u64::try_from(payload.entries.len()).map_err(|_| CodecError::ArithmeticOverflow)?;
            if payload.chain_count != count || payload.previous_delta != PhysicalPointer::Null {
                return Err(CodecError::InvalidField);
            }
            if payload
                .entries
                .windows(2)
                .any(|pair| pair[0].object_id >= pair[1].object_id)
            {
                return Err(CodecError::InvalidField);
            }
        }
        CatalogPayloadKind::Delta => {
            if payload.entries.len() != 1 || payload.chain_count == 0 {
                return Err(CodecError::InvalidField);
            }
            validate_delta_pointer(payload.previous_delta, store_uuid, payload.chain_count)?;
        }
    }
    for entry in &payload.entries {
        validate_entry(
            entry,
            store_uuid,
            payload.checkpoint_generation,
            payload.kind,
        )?;
    }
    Ok(())
}

fn write_pointer(
    out: &mut [u8],
    offset: usize,
    pointer: PhysicalPointer,
) -> Result<(), CodecError> {
    let mut encoded = [0; POINTER_SIZE];
    encode_physical_pointer(pointer, &mut encoded)?;
    out[offset..offset + POINTER_SIZE].copy_from_slice(&encoded);
    Ok(())
}

fn read_pointer(input: &[u8], offset: usize) -> Result<PhysicalPointer, CodecError> {
    let mut encoded = [0; POINTER_SIZE];
    encoded.copy_from_slice(&input[offset..offset + POINTER_SIZE]);
    decode_physical_pointer(&encoded).map_err(Into::into)
}

fn encode_entry(
    entry: &CatalogEntry,
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    kind: CatalogPayloadKind,
    out: &mut [u8],
) -> Result<(), CodecError> {
    validate_entry(entry, store_uuid, checkpoint_generation, kind)?;
    out.fill(0);
    put_u128(out, 0x00, entry.object_id);
    put_u32(out, 0x10, entry.object_kind);
    put_u64(out, 0x18, entry.exact_len);
    put_u64(out, 0x20, entry.commit_generation);
    out[0x28..0x48].copy_from_slice(&entry.content_root);
    write_pointer(out, 0x48, entry.blob)
}

fn decode_entry(
    input: &[u8],
    store_uuid: StoreUuid,
    checkpoint_generation: u64,
    kind: CatalogPayloadKind,
) -> Result<CatalogEntry, CodecError> {
    if get_u32(input, 0x14) != 0 || !is_zero(&input[0xa8..0xb0]) {
        return Err(CodecError::NonZeroReserved);
    }
    let mut content_root = [0; 32];
    content_root.copy_from_slice(&input[0x28..0x48]);
    let entry = CatalogEntry {
        object_id: get_u128(input, 0x00),
        object_kind: get_u32(input, 0x10),
        exact_len: get_u64(input, 0x18),
        commit_generation: get_u64(input, 0x20),
        content_root,
        blob: read_pointer(input, 0x48)?,
    };
    validate_entry(&entry, store_uuid, checkpoint_generation, kind)?;
    Ok(entry)
}

pub fn encode_catalog(
    payload: &CatalogPayload,
    store_uuid: StoreUuid,
) -> Result<Vec<u8>, CodecError> {
    validate_catalog(payload, store_uuid)?;
    let encoded_len = expected_catalog_len(payload.kind, payload.entries.len())?;
    let mut out = vec![0; encoded_len];
    out[0..8].copy_from_slice(CATALOG_MAGIC);
    put_u16(&mut out, 0x08, PAYLOAD_VERSION);
    put_u16(&mut out, 0x0a, payload.kind as u16);
    put_u32(
        &mut out,
        0x0c,
        u32::try_from(payload.kind.header_len()).map_err(|_| CodecError::ArithmeticOverflow)?,
    );
    put_u64(&mut out, 0x10, payload.checkpoint_generation);
    put_u32(
        &mut out,
        0x18,
        u32::try_from(payload.entries.len()).map_err(|_| CodecError::ArithmeticOverflow)?,
    );
    put_u32(&mut out, 0x1c, CATALOG_ENTRY_LEN as u32);
    put_u64(&mut out, 0x20, payload.chain_count);
    if payload.kind == CatalogPayloadKind::Delta {
        write_pointer(&mut out, 0x28, payload.previous_delta)?;
    }
    let entries_offset = payload.kind.header_len();
    for (index, entry) in payload.entries.iter().enumerate() {
        let offset = entries_offset
            .checked_add(
                index
                    .checked_mul(CATALOG_ENTRY_LEN)
                    .ok_or(CodecError::ArithmeticOverflow)?,
            )
            .ok_or(CodecError::ArithmeticOverflow)?;
        encode_entry(
            entry,
            store_uuid,
            payload.checkpoint_generation,
            payload.kind,
            &mut out[offset..offset + CATALOG_ENTRY_LEN],
        )?;
    }
    Ok(out)
}

pub fn decode_catalog(bytes: &[u8], store_uuid: StoreUuid) -> Result<CatalogPayload, CodecError> {
    if bytes.len() < CATALOG_SNAPSHOT_HEADER_LEN {
        return Err(CodecError::InvalidLength);
    }
    if &bytes[0..8] != CATALOG_MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    if get_u16(bytes, 0x08) != PAYLOAD_VERSION {
        return Err(CodecError::InvalidField);
    }
    let kind = CatalogPayloadKind::from_raw(get_u16(bytes, 0x0a))?;
    if get_u32(bytes, 0x0c) as usize != kind.header_len()
        || get_u32(bytes, 0x1c) as usize != CATALOG_ENTRY_LEN
    {
        return Err(CodecError::InvalidField);
    }
    let entry_count =
        usize::try_from(get_u32(bytes, 0x18)).map_err(|_| CodecError::ArithmeticOverflow)?;
    let expected_len = expected_catalog_len(kind, entry_count)?;
    if expected_len > MAX_METADATA_PAYLOAD_LEN || bytes.len() != expected_len {
        return Err(CodecError::InvalidLength);
    }
    let checkpoint_generation = get_u64(bytes, 0x10);
    let chain_count = get_u64(bytes, 0x20);
    let previous_delta = match kind {
        CatalogPayloadKind::Snapshot => {
            if !is_zero(&bytes[0x28..0x40]) {
                return Err(CodecError::NonZeroReserved);
            }
            PhysicalPointer::Null
        }
        CatalogPayloadKind::Delta => {
            if !is_zero(&bytes[0x88..0xa0]) {
                return Err(CodecError::NonZeroReserved);
            }
            read_pointer(bytes, 0x28)?
        }
    };
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| CodecError::InvalidLength)?;
    let entries_offset = kind.header_len();
    for index in 0..entry_count {
        let offset = entries_offset
            .checked_add(
                index
                    .checked_mul(CATALOG_ENTRY_LEN)
                    .ok_or(CodecError::ArithmeticOverflow)?,
            )
            .ok_or(CodecError::ArithmeticOverflow)?;
        entries.push(decode_entry(
            &bytes[offset..offset + CATALOG_ENTRY_LEN],
            store_uuid,
            checkpoint_generation,
            kind,
        )?);
    }
    let payload = CatalogPayload {
        kind,
        checkpoint_generation,
        chain_count,
        previous_delta,
        entries,
    };
    validate_catalog(&payload, store_uuid)?;
    Ok(payload)
}

fn validate_allocation(state: AllocationState) -> Result<(), CodecError> {
    let unavailable = state
        .allocated_prefix_segments
        .checked_add(u64::from(state.cleaner_reserve_segments))
        .ok_or(CodecError::ArithmeticOverflow)?;
    if state.checkpoint_generation == 0
        || state.admitted_segments == 0
        || state.next_segment_generation == 0
        || state.cleaner_reserve_segments == 0
        || u64::from(state.cleaner_reserve_segments) >= state.admitted_segments
        || state.allocated_prefix_segments > state.admitted_segments
        || unavailable > state.admitted_segments
    {
        return Err(CodecError::InvalidField);
    }
    Ok(())
}

pub fn encode_allocation(
    state: AllocationState,
) -> Result<[u8; ALLOCATION_PAYLOAD_LEN], CodecError> {
    validate_allocation(state)?;
    let mut out = [0; ALLOCATION_PAYLOAD_LEN];
    out[0..8].copy_from_slice(ALLOCATION_MAGIC);
    put_u16(&mut out, 0x08, PAYLOAD_VERSION);
    put_u16(&mut out, 0x0a, ALLOCATION_PAYLOAD_LEN as u16);
    put_u64(&mut out, 0x10, state.checkpoint_generation);
    put_u64(&mut out, 0x18, state.admitted_segments);
    put_u64(&mut out, 0x20, state.allocated_prefix_segments);
    put_u64(&mut out, 0x28, state.next_segment_generation);
    put_u32(&mut out, 0x30, state.cleaner_reserve_segments);
    Ok(out)
}

pub fn decode_allocation(bytes: &[u8]) -> Result<AllocationState, CodecError> {
    if bytes.len() != ALLOCATION_PAYLOAD_LEN {
        return Err(CodecError::InvalidLength);
    }
    if &bytes[0..8] != ALLOCATION_MAGIC {
        return Err(CodecError::InvalidMagic);
    }
    if get_u16(bytes, 0x08) != PAYLOAD_VERSION
        || get_u16(bytes, 0x0a) as usize != ALLOCATION_PAYLOAD_LEN
    {
        return Err(CodecError::InvalidField);
    }
    if get_u32(bytes, 0x0c) != 0 || !is_zero(&bytes[0x34..0x40]) {
        return Err(CodecError::NonZeroReserved);
    }
    let state = AllocationState {
        checkpoint_generation: get_u64(bytes, 0x10),
        admitted_segments: get_u64(bytes, 0x18),
        allocated_prefix_segments: get_u64(bytes, 0x20),
        next_segment_generation: get_u64(bytes, 0x28),
        cleaner_reserve_segments: get_u32(bytes, 0x30),
    };
    validate_allocation(state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_segment_format::PointerValue;

    fn uuid(value: u8) -> StoreUuid {
        StoreUuid::new([value; 16]).unwrap()
    }

    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).as_slice().try_into().unwrap()
    }

    fn pointer(
        store_uuid: StoreUuid,
        kind: ExtentKind,
        exact_len: u64,
        digest: [u8; 32],
        ordinal: u32,
    ) -> PhysicalPointer {
        PhysicalPointer::Value(PointerValue {
            store_uuid,
            segment_no: 1,
            segment_generation: 7,
            descriptor_relative_page: 2,
            payload_relative_page: 4,
            payload_pages: u32::try_from(exact_len.div_ceil(PAGE_SIZE as u64)).unwrap(),
            ordinal,
            exact_byte_len: exact_len,
            extent_kind: kind,
            payload_sha256: digest,
        })
    }

    fn entry(store_uuid: StoreUuid, object_id: u128, generation: u64) -> CatalogEntry {
        let bytes = [object_id as u8; 17];
        let digest = hash(&bytes);
        CatalogEntry {
            object_id,
            object_kind: 9,
            exact_len: bytes.len() as u64,
            commit_generation: generation,
            content_root: digest,
            blob: pointer(
                store_uuid,
                ExtentKind::Blob,
                bytes.len() as u64,
                digest,
                u32::try_from(object_id).unwrap(),
            ),
        }
    }

    fn delta_pointer(store_uuid: StoreUuid) -> PhysicalPointer {
        pointer(
            store_uuid,
            ExtentKind::CatalogDelta,
            CATALOG_DELTA_PAYLOAD_LEN as u64,
            [0x55; 32],
            3,
        )
    }

    #[test]
    fn snapshot_round_trip_and_exact_offsets() {
        let store_uuid = uuid(1);
        let payload = CatalogPayload {
            kind: CatalogPayloadKind::Snapshot,
            checkpoint_generation: 8,
            chain_count: 2,
            previous_delta: PhysicalPointer::Null,
            entries: vec![entry(store_uuid, 1, 7), entry(store_uuid, 2, 8)],
        };
        let encoded = encode_catalog(&payload, store_uuid).unwrap();
        assert_eq!(encoded.len(), 0x40 + 2 * 0xb0);
        assert_eq!(&encoded[0x00..0x08], b"VIBECAT2");
        assert_eq!(get_u16(&encoded, 0x08), 1);
        assert_eq!(get_u16(&encoded, 0x0a), 1);
        assert_eq!(get_u32(&encoded, 0x0c), 0x40);
        assert_eq!(get_u64(&encoded, 0x10), 8);
        assert_eq!(get_u32(&encoded, 0x18), 2);
        assert_eq!(get_u32(&encoded, 0x1c), 0xb0);
        assert_eq!(get_u64(&encoded, 0x20), 2);
        assert!(is_zero(&encoded[0x28..0x40]));
        assert_eq!(get_u128(&encoded, 0x40), 1);
        assert_eq!(get_u32(&encoded, 0x50), 9);
        assert_eq!(get_u64(&encoded, 0x58), 17);
        assert_eq!(decode_catalog(&encoded, store_uuid).unwrap(), payload);
    }

    #[test]
    fn delta_round_trip_and_exact_offsets() {
        let store_uuid = uuid(2);
        let payload = CatalogPayload {
            kind: CatalogPayloadKind::Delta,
            checkpoint_generation: 9,
            chain_count: 2,
            previous_delta: delta_pointer(store_uuid),
            entries: vec![entry(store_uuid, 9, 9)],
        };
        let encoded = encode_catalog(&payload, store_uuid).unwrap();
        assert_eq!(encoded.len(), CATALOG_DELTA_PAYLOAD_LEN);
        assert_eq!(get_u16(&encoded, 0x0a), 2);
        assert_eq!(get_u32(&encoded, 0x0c), 0xa0);
        assert_eq!(get_u32(&encoded, 0x18), 1);
        assert_eq!(get_u64(&encoded, 0x20), 2);
        assert!(!is_zero(&encoded[0x28..0x88]));
        assert!(is_zero(&encoded[0x88..0xa0]));
        assert_eq!(decode_catalog(&encoded, store_uuid).unwrap(), payload);

        let first = CatalogPayload {
            chain_count: 1,
            previous_delta: PhysicalPointer::Null,
            ..payload
        };
        assert_eq!(
            decode_catalog(&encode_catalog(&first, store_uuid).unwrap(), store_uuid).unwrap(),
            first
        );
    }

    #[test]
    fn empty_object_is_canonical() {
        let store_uuid = uuid(3);
        let payload = CatalogPayload {
            kind: CatalogPayloadKind::Delta,
            checkpoint_generation: 1,
            chain_count: 1,
            previous_delta: PhysicalPointer::Null,
            entries: vec![CatalogEntry {
                object_id: 1,
                object_kind: 1,
                exact_len: 0,
                commit_generation: 1,
                content_root: empty_sha256(),
                blob: PhysicalPointer::Null,
            }],
        };
        let encoded = encode_catalog(&payload, store_uuid).unwrap();
        assert_eq!(decode_catalog(&encoded, store_uuid).unwrap(), payload);

        let mut wrong_root = payload.clone();
        wrong_root.entries[0].content_root = [0; 32];
        assert_eq!(
            encode_catalog(&wrong_root, store_uuid),
            Err(CodecError::InvalidPointer)
        );
        let mut non_null = payload.clone();
        non_null.entries[0] = entry(store_uuid, 1, 1);
        non_null.entries[0].exact_len = 0;
        assert_eq!(
            encode_catalog(&non_null, store_uuid),
            Err(CodecError::InvalidPointer)
        );
    }

    #[test]
    fn rejects_catalog_semantic_mismatches() {
        let store_uuid = uuid(4);
        let base_entry = entry(store_uuid, 1, 3);
        let delta = |entry, chain_count, previous_delta| CatalogPayload {
            kind: CatalogPayloadKind::Delta,
            checkpoint_generation: 3,
            chain_count,
            previous_delta,
            entries: vec![entry],
        };

        let mut wrong_uuid = base_entry;
        wrong_uuid.blob = pointer(uuid(5), ExtentKind::Blob, 17, base_entry.content_root, 1);
        assert_eq!(
            encode_catalog(&delta(wrong_uuid, 1, PhysicalPointer::Null), store_uuid),
            Err(CodecError::InvalidPointer)
        );
        let mut wrong_kind = base_entry;
        wrong_kind.blob = pointer(
            store_uuid,
            ExtentKind::Catalog,
            17,
            base_entry.content_root,
            1,
        );
        assert_eq!(
            encode_catalog(&delta(wrong_kind, 1, PhysicalPointer::Null), store_uuid),
            Err(CodecError::InvalidPointer)
        );
        let mut wrong_hash = base_entry;
        wrong_hash.content_root = [0x99; 32];
        assert_eq!(
            encode_catalog(&delta(wrong_hash, 1, PhysicalPointer::Null), store_uuid),
            Err(CodecError::InvalidPointer)
        );
        let mut old_delta_entry = base_entry;
        old_delta_entry.commit_generation = 2;
        assert_eq!(
            encode_catalog(
                &delta(old_delta_entry, 1, PhysicalPointer::Null),
                store_uuid
            ),
            Err(CodecError::InvalidField)
        );
        assert_eq!(
            encode_catalog(&delta(base_entry, 2, PhysicalPointer::Null), store_uuid),
            Err(CodecError::InvalidPointer)
        );
        assert_eq!(
            encode_catalog(&delta(base_entry, 1, delta_pointer(store_uuid)), store_uuid),
            Err(CodecError::InvalidPointer)
        );
    }

    #[test]
    fn snapshot_requires_sorted_unique_entries() {
        let store_uuid = uuid(6);
        for ids in [[2, 1], [1, 1]] {
            let payload = CatalogPayload {
                kind: CatalogPayloadKind::Snapshot,
                checkpoint_generation: 4,
                chain_count: 2,
                previous_delta: PhysicalPointer::Null,
                entries: vec![entry(store_uuid, ids[0], 4), entry(store_uuid, ids[1], 4)],
            };
            assert_eq!(
                encode_catalog(&payload, store_uuid),
                Err(CodecError::InvalidField)
            );
        }
    }

    #[test]
    fn sealed_payload_corruption_fails_closed() {
        let store_uuid = uuid(7);
        let payload = CatalogPayload {
            kind: CatalogPayloadKind::Delta,
            checkpoint_generation: 2,
            chain_count: 1,
            previous_delta: PhysicalPointer::Null,
            entries: vec![entry(store_uuid, 1, 2)],
        };
        let canonical = encode_catalog(&payload, store_uuid).unwrap();
        for offset in [0, 8, 10, 12, 16, 24, 28, 0x88, 0xa0 + 0x14, 0xa0 + 0xa8] {
            let mut corrupt = canonical.clone();
            corrupt[offset] ^= 1;
            assert!(
                decode_catalog(&corrupt, store_uuid).is_err(),
                "offset {offset:#x}"
            );
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            decode_catalog(&trailing, store_uuid),
            Err(CodecError::InvalidLength)
        );
        assert_eq!(
            decode_catalog(&canonical[..canonical.len() - 1], store_uuid),
            Err(CodecError::InvalidLength)
        );
    }

    #[test]
    fn allocation_round_trip_and_exact_offsets() {
        let state = AllocationState {
            checkpoint_generation: 11,
            admitted_segments: 32,
            allocated_prefix_segments: 7,
            next_segment_generation: 19,
            cleaner_reserve_segments: 2,
        };
        let encoded = encode_allocation(state).unwrap();
        assert_eq!(&encoded[0x00..0x08], b"VIBEALC2");
        assert_eq!(get_u16(&encoded, 0x08), 1);
        assert_eq!(get_u16(&encoded, 0x0a), 0x40);
        assert_eq!(get_u32(&encoded, 0x0c), 0);
        assert_eq!(get_u64(&encoded, 0x10), 11);
        assert_eq!(get_u64(&encoded, 0x18), 32);
        assert_eq!(get_u64(&encoded, 0x20), 7);
        assert_eq!(get_u64(&encoded, 0x28), 19);
        assert_eq!(get_u32(&encoded, 0x30), 2);
        assert!(is_zero(&encoded[0x34..0x40]));
        assert_eq!(decode_allocation(&encoded).unwrap(), state);
    }

    #[test]
    fn allocation_rejects_reserve_and_prefix_amplification() {
        let valid = AllocationState {
            checkpoint_generation: 1,
            admitted_segments: 10,
            allocated_prefix_segments: 7,
            next_segment_generation: 8,
            cleaner_reserve_segments: 2,
        };
        for state in [
            AllocationState {
                checkpoint_generation: 0,
                ..valid
            },
            AllocationState {
                cleaner_reserve_segments: 0,
                ..valid
            },
            AllocationState {
                allocated_prefix_segments: 9,
                ..valid
            },
            AllocationState {
                next_segment_generation: 0,
                ..valid
            },
        ] {
            assert_eq!(encode_allocation(state), Err(CodecError::InvalidField));
        }
    }

    #[test]
    fn allocation_reserved_and_length_corruption_fail_closed() {
        let valid = AllocationState {
            checkpoint_generation: 1,
            admitted_segments: 10,
            allocated_prefix_segments: 1,
            next_segment_generation: 2,
            cleaner_reserve_segments: 2,
        };
        let canonical = encode_allocation(valid).unwrap();
        for offset in [0, 8, 10, 12, 0x34, 0x3f] {
            let mut corrupt = canonical;
            corrupt[offset] ^= 1;
            assert!(decode_allocation(&corrupt).is_err(), "offset {offset:#x}");
        }
        assert_eq!(
            decode_allocation(&canonical[..canonical.len() - 1]),
            Err(CodecError::InvalidLength)
        );
    }
}
