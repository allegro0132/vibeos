//! Canonical M7.4 Blob-CAS catalog payload codecs.
//!
//! The codec deliberately keeps capability identity (`ObjectId -> BlobKey`)
//! separate from physical identity (`BlobKey -> BlobManifest`).  A `BlobKey`
//! is data, not authority; this module exposes no lookup or enumeration API.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use vibeos_blob_format::{BlobError, BlobGeometry, HEADER_SIZE};
use vibeos_segment_format::{
    decode_physical_pointer, encode_physical_pointer, validate_pointer, ExtentKind, FormatError,
    PhysicalPointer, PointerValue, StoreUuid, HASH_ALGORITHM_SHA256, MAX_EXTENT_PAYLOAD_PAGES,
    PAGE_SIZE, POINTER_SIZE,
};

pub const CAS_CODEC_VERSION: u16 = 1;
/// Snapshot/delta version which admits the M7.5 typed-reference tag.
pub const CAS_GC_CODEC_VERSION: u16 = 2;
/// Raw object bytes have no GC edges.
pub const REFERENCE_CODEC_RAW: u16 = 0;
/// Canonical `VIBEREF1` child-reference payload.
pub const REFERENCE_CODEC_TYPED_V1: u16 = 1;
/// Dedicated canonical `FsRootV1`/`FsBtreeNodeV1` child extraction.
pub const REFERENCE_CODEC_FS_V1: u16 = 2;
pub const MAX_BLOB_CONTENT_LEN: u64 = 64 * 1024 * 1024;
pub const MAX_BLOB_EXTENTS: usize = 66;
pub const CANONICAL_CONTENT_EXTENT_LEN: u64 = MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64;
pub const MAX_METADATA_PAYLOAD_LEN: usize = MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE;

pub const BLOB_KEY_LEN: usize = 0x40;
pub const OBJECT_MAPPING_LEN: usize = 0x60;
pub const BLOB_MAPPING_LEN: usize = 0xa0;
pub const BLOB_MANIFEST_HEADER_LEN: usize = 0x80;
pub const MANIFEST_EXTENT_LEN: usize = 0x80;
pub const CAS_SNAPSHOT_HEADER_LEN: usize = 0x80;
pub const CAS_DELTA_HEADER_LEN: usize = 0xa0;
pub const CAS_DELTA_REUSE_LEN: usize = CAS_DELTA_HEADER_LEN + OBJECT_MAPPING_LEN;
pub const CAS_DELTA_NEW_BLOB_LEN: usize = CAS_DELTA_REUSE_LEN + BLOB_MAPPING_LEN;
pub const MAX_MANIFEST_EXTENTS: usize =
    (MAX_METADATA_PAYLOAD_LEN - BLOB_MANIFEST_HEADER_LEN) / MANIFEST_EXTENT_LEN;

const CAS_MAGIC: &[u8; 8] = b"VIBECAS2";
const BLOB_MANIFEST_MAGIC: &[u8; 8] = b"VIBEBMF2";
const CAS_KIND_SNAPSHOT: u16 = 1;
const CAS_KIND_DELTA: u16 = 2;
const DELTA_FLAG_NEW_BLOB: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasCodecError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    InvalidPointer,
    NonZeroReserved,
    OutOfBounds,
    UnsortedOrDuplicate,
    MissingBlobMapping,
    OrphanBlobMapping,
    OverlappingPointer,
    Blob(BlobError),
    Format(FormatError),
}

impl fmt::Display for CasCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "CAS payload arithmetic overflowed",
            Self::InvalidField => "CAS payload contains an invalid field",
            Self::InvalidLength => "CAS payload has a non-canonical length",
            Self::InvalidMagic => "CAS payload magic is invalid",
            Self::InvalidPointer => "CAS payload pointer is invalid",
            Self::NonZeroReserved => "CAS payload reserved bytes are non-zero",
            Self::OutOfBounds => "CAS payload exceeds an admitted bound",
            Self::UnsortedOrDuplicate => "CAS table is not strictly ordered",
            Self::MissingBlobMapping => "CAS object has no BlobKey mapping",
            Self::OrphanBlobMapping => "CAS BlobKey mapping has no Object mapping",
            Self::OverlappingPointer => "CAS physical pointers overlap",
            Self::Blob(_) => "CAS payload has invalid canonical Blob geometry",
            Self::Format(_) => "CAS payload contains a malformed physical pointer",
        })
    }
}

impl From<FormatError> for CasCodecError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl From<BlobError> for CasCodecError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

/// Bounds inherited from the selected checkpoint.  Every decoded pointer is
/// checked against these values before it can enter mounted state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasCodecContext {
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
}

impl CasCodecContext {
    pub fn new(
        store_uuid: StoreUuid,
        admitted_segments: u64,
        next_segment_generation: u64,
    ) -> Result<Self, CasCodecError> {
        if admitted_segments == 0 || next_segment_generation == 0 {
            return Err(CasCodecError::OutOfBounds);
        }
        Ok(Self {
            store_uuid,
            admitted_segments,
            next_segment_generation,
        })
    }

    pub const fn store_uuid(self) -> StoreUuid {
        self.store_uuid
    }

    pub const fn admitted_segments(self) -> u64 {
        self.admitted_segments
    }

    pub const fn next_segment_generation(self) -> u64 {
        self.next_segment_generation
    }
}

/// The tagged, non-authorizing identity of one canonical Blob.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlobKey {
    hash_algorithm: u16,
    object_kind: u32,
    exact_len: u64,
    merkle_root: [u8; 32],
}

impl BlobKey {
    pub fn new(
        hash_algorithm: u16,
        object_kind: u32,
        exact_len: u64,
        merkle_root: [u8; 32],
    ) -> Result<Self, CasCodecError> {
        let value = Self {
            hash_algorithm,
            object_kind,
            exact_len,
            merkle_root,
        };
        validate_blob_key(value)?;
        Ok(value)
    }

    pub fn sha256(
        object_kind: u32,
        exact_len: u64,
        merkle_root: [u8; 32],
    ) -> Result<Self, CasCodecError> {
        Self::new(HASH_ALGORITHM_SHA256, object_kind, exact_len, merkle_root)
    }

    pub const fn hash_algorithm(self) -> u16 {
        self.hash_algorithm
    }

    pub const fn object_kind(self) -> u32 {
        self.object_kind
    }

    pub const fn exact_len(self) -> u64 {
        self.exact_len
    }

    pub const fn merkle_root(self) -> [u8; 32] {
        self.merkle_root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectMapping {
    pub object_id: u128,
    pub blob_key: BlobKey,
    pub commit_generation: u64,
    /// Persisted interpretation of the object payload for GC traversal.
    ///
    /// This belongs to the independently revocable Object mapping rather than
    /// the deduplicated Blob mapping: identical bytes may be admitted as raw
    /// data in one object and as a typed manifest in another.
    pub reference_codec: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMapping {
    pub blob_key: BlobKey,
    pub manifest: PhysicalPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestExtent {
    pub extent_index: u32,
    pub extent_count: u32,
    pub encoded_offset: u64,
    pub payload_byte_len: u64,
    pub pointer: PhysicalPointer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobManifest {
    pub blob_key: BlobKey,
    pub encoded_blob_len: u64,
    pub extents: Vec<ManifestExtent>,
}

/// One self-contained checkpoint of the two separately encoded indexes.
/// Objects are ordered by ObjectId; Blobs are ordered by canonical BlobKey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CasSnapshot {
    pub checkpoint_generation: u64,
    pub objects: Vec<ObjectMapping>,
    pub blobs: Vec<BlobMapping>,
}

/// One atomic catalog replay record.  It always grants a new ObjectId.  A new
/// physical Blob mapping is present only when complete-Blob deduplication did
/// not find an already verified Blob.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasDelta {
    pub checkpoint_generation: u64,
    pub chain_count: u32,
    pub previous_delta: PhysicalPointer,
    pub object: ObjectMapping,
    pub new_blob: Option<BlobMapping>,
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
            .expect("fixed-width CAS field"),
    )
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("fixed-width CAS field"),
    )
}

fn get_u128(input: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(
        input[offset..offset + 16]
            .try_into()
            .expect("fixed-width CAS field"),
    )
}

fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn checked_table_len(header: usize, count: usize, entry: usize) -> Result<usize, CasCodecError> {
    header
        .checked_add(
            count
                .checked_mul(entry)
                .ok_or(CasCodecError::ArithmeticOverflow)?,
        )
        .ok_or(CasCodecError::ArithmeticOverflow)
}

fn validate_blob_key(value: BlobKey) -> Result<(), CasCodecError> {
    if value.hash_algorithm != HASH_ALGORITHM_SHA256
        || value.object_kind == 0
        || value.exact_len > MAX_BLOB_CONTENT_LEN
    {
        Err(CasCodecError::InvalidField)
    } else {
        Ok(())
    }
}

/// Exact encoded size of the frozen canonical Blob envelope for a content
/// length.  This repeats geometry, not hashing domains, so media codecs can
/// reject gaps and suffixes without depending on an allocating Blob encoder.
pub fn canonical_blob_encoded_len(exact_len: u64) -> Result<u64, CasCodecError> {
    u64::try_from(BlobGeometry::for_len(exact_len)?.encoded_len())
        .map_err(|_| CasCodecError::ArithmeticOverflow)
}

fn write_blob_key(value: BlobKey, out: &mut [u8]) -> Result<(), CasCodecError> {
    if out.len() != BLOB_KEY_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    validate_blob_key(value)?;
    out.fill(0);
    put_u16(out, 0x00, value.hash_algorithm);
    put_u32(out, 0x04, value.object_kind);
    put_u64(out, 0x08, value.exact_len);
    out[0x10..0x30].copy_from_slice(&value.merkle_root);
    Ok(())
}

pub fn encode_blob_key(value: BlobKey) -> Result<[u8; BLOB_KEY_LEN], CasCodecError> {
    let mut out = [0; BLOB_KEY_LEN];
    write_blob_key(value, &mut out)?;
    Ok(out)
}

pub fn decode_blob_key(input: &[u8]) -> Result<BlobKey, CasCodecError> {
    if input.len() != BLOB_KEY_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    if get_u16(input, 0x02) != 0 || !is_zero(&input[0x30..0x40]) {
        return Err(CasCodecError::NonZeroReserved);
    }
    let mut merkle_root = [0; 32];
    merkle_root.copy_from_slice(&input[0x10..0x30]);
    BlobKey::new(
        get_u16(input, 0x00),
        get_u32(input, 0x04),
        get_u64(input, 0x08),
        merkle_root,
    )
}

fn validate_context_pointer(
    pointer: PhysicalPointer,
    context: CasCodecContext,
    expected_kind: ExtentKind,
) -> Result<PointerValue, CasCodecError> {
    let PhysicalPointer::Value(value) = pointer else {
        return Err(CasCodecError::InvalidPointer);
    };
    validate_pointer(
        pointer,
        context.store_uuid,
        context.admitted_segments,
        expected_kind,
    )?;
    if value.segment_generation >= context.next_segment_generation {
        return Err(CasCodecError::OutOfBounds);
    }
    Ok(value)
}

fn write_pointer(
    pointer: PhysicalPointer,
    context: CasCodecContext,
    expected_kind: ExtentKind,
    out: &mut [u8],
) -> Result<PointerValue, CasCodecError> {
    if out.len() != POINTER_SIZE {
        return Err(CasCodecError::InvalidLength);
    }
    let value = validate_context_pointer(pointer, context, expected_kind)?;
    let mut encoded = [0; POINTER_SIZE];
    encode_physical_pointer(pointer, &mut encoded)?;
    out.copy_from_slice(&encoded);
    Ok(value)
}

fn read_pointer(
    input: &[u8],
    context: CasCodecContext,
    expected_kind: ExtentKind,
) -> Result<(PhysicalPointer, PointerValue), CasCodecError> {
    if input.len() != POINTER_SIZE {
        return Err(CasCodecError::InvalidLength);
    }
    let mut encoded = [0; POINTER_SIZE];
    encoded.copy_from_slice(input);
    let pointer = decode_physical_pointer(&encoded)?;
    let value = validate_context_pointer(pointer, context, expected_kind)?;
    Ok((pointer, value))
}

fn pointers_conflict(left: PointerValue, right: PointerValue) -> bool {
    if left.store_uuid != right.store_uuid || left.segment_no != right.segment_no {
        return false;
    }
    // One physical segment has exactly one generation and unique ordinals.
    if left.segment_generation != right.segment_generation || left.ordinal == right.ordinal {
        return true;
    }
    let left_end = left
        .payload_relative_page
        .saturating_add(left.payload_pages);
    let right_end = right
        .payload_relative_page
        .saturating_add(right.payload_pages);
    left.descriptor_relative_page < right_end && right.descriptor_relative_page < left_end
}

fn validate_object_mapping(
    value: ObjectMapping,
    checkpoint_generation: u64,
) -> Result<(), CasCodecError> {
    validate_blob_key(value.blob_key)?;
    if value.object_id == 0
        || value.commit_generation == 0
        || value.commit_generation > checkpoint_generation
        || !matches!(
            value.reference_codec,
            REFERENCE_CODEC_RAW | REFERENCE_CODEC_TYPED_V1 | REFERENCE_CODEC_FS_V1
        )
    {
        return Err(CasCodecError::InvalidField);
    }
    Ok(())
}

fn write_object_mapping(
    value: ObjectMapping,
    checkpoint_generation: u64,
    codec_version: u16,
    out: &mut [u8],
) -> Result<(), CasCodecError> {
    if out.len() != OBJECT_MAPPING_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    validate_object_mapping(value, checkpoint_generation)?;
    out.fill(0);
    put_u128(out, 0x00, value.object_id);
    write_blob_key(value.blob_key, &mut out[0x10..0x50])?;
    put_u64(out, 0x50, value.commit_generation);
    match codec_version {
        CAS_CODEC_VERSION if value.reference_codec == REFERENCE_CODEC_RAW => {}
        CAS_GC_CODEC_VERSION => put_u16(out, 0x58, value.reference_codec),
        _ => return Err(CasCodecError::InvalidField),
    }
    Ok(())
}

fn read_object_mapping(
    input: &[u8],
    checkpoint_generation: u64,
    codec_version: u16,
) -> Result<ObjectMapping, CasCodecError> {
    if input.len() != OBJECT_MAPPING_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    let reference_codec = match codec_version {
        CAS_CODEC_VERSION => {
            if !is_zero(&input[0x58..0x60]) {
                return Err(CasCodecError::NonZeroReserved);
            }
            REFERENCE_CODEC_RAW
        }
        CAS_GC_CODEC_VERSION => {
            if !is_zero(&input[0x5a..0x60]) {
                return Err(CasCodecError::NonZeroReserved);
            }
            get_u16(input, 0x58)
        }
        _ => return Err(CasCodecError::InvalidField),
    };
    let value = ObjectMapping {
        object_id: get_u128(input, 0x00),
        blob_key: decode_blob_key(&input[0x10..0x50])?,
        commit_generation: get_u64(input, 0x50),
        reference_codec,
    };
    validate_object_mapping(value, checkpoint_generation)?;
    Ok(value)
}

fn manifest_extent_count_from_pointer(value: PointerValue) -> Result<usize, CasCodecError> {
    let exact_len =
        usize::try_from(value.exact_byte_len).map_err(|_| CasCodecError::InvalidLength)?;
    if exact_len <= BLOB_MANIFEST_HEADER_LEN
        || exact_len > MAX_METADATA_PAYLOAD_LEN
        || !(exact_len - BLOB_MANIFEST_HEADER_LEN).is_multiple_of(MANIFEST_EXTENT_LEN)
    {
        return Err(CasCodecError::InvalidPointer);
    }
    let count = (exact_len - BLOB_MANIFEST_HEADER_LEN) / MANIFEST_EXTENT_LEN;
    if count == 0 || count > MAX_MANIFEST_EXTENTS {
        return Err(CasCodecError::InvalidPointer);
    }
    Ok(count)
}

fn validate_blob_mapping(
    value: BlobMapping,
    context: CasCodecContext,
) -> Result<PointerValue, CasCodecError> {
    validate_blob_key(value.blob_key)?;
    let pointer = validate_context_pointer(value.manifest, context, ExtentKind::Catalog)?;
    let declared_count = manifest_extent_count_from_pointer(pointer)?;
    let content_count = usize::try_from(value.blob_key.exact_len)
        .map_err(|_| CasCodecError::ArithmeticOverflow)?
        .div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
    if declared_count != content_count + 2 {
        return Err(CasCodecError::InvalidPointer);
    }
    Ok(pointer)
}

fn write_blob_mapping(
    value: BlobMapping,
    context: CasCodecContext,
    out: &mut [u8],
) -> Result<PointerValue, CasCodecError> {
    if out.len() != BLOB_MAPPING_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    let pointer = validate_blob_mapping(value, context)?;
    out.fill(0);
    write_blob_key(value.blob_key, &mut out[0x00..0x40])?;
    write_pointer(
        value.manifest,
        context,
        ExtentKind::Catalog,
        &mut out[0x40..0xa0],
    )?;
    Ok(pointer)
}

fn read_blob_mapping(
    input: &[u8],
    context: CasCodecContext,
) -> Result<(BlobMapping, PointerValue), CasCodecError> {
    if input.len() != BLOB_MAPPING_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    let blob_key = decode_blob_key(&input[0x00..0x40])?;
    let (manifest, pointer) = read_pointer(&input[0x40..0xa0], context, ExtentKind::Catalog)?;
    let value = BlobMapping { blob_key, manifest };
    validate_blob_mapping(value, context)?;
    Ok((value, pointer))
}

fn validate_manifest(value: &BlobManifest, context: CasCodecContext) -> Result<(), CasCodecError> {
    validate_blob_key(value.blob_key)?;
    if value.encoded_blob_len != canonical_blob_encoded_len(value.blob_key.exact_len)?
        || value.extents.is_empty()
        || value.extents.len() > MAX_BLOB_EXTENTS
    {
        return Err(CasCodecError::InvalidField);
    }
    checked_table_len(
        BLOB_MANIFEST_HEADER_LEN,
        value.extents.len(),
        MANIFEST_EXTENT_LEN,
    )?
    .le(&MAX_METADATA_PAYLOAD_LEN)
    .then_some(())
    .ok_or(CasCodecError::InvalidLength)?;

    let content_extent_count = usize::try_from(value.blob_key.exact_len)
        .map_err(|_| CasCodecError::ArithmeticOverflow)?
        .div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
    let expected_extent_count = content_extent_count
        .checked_add(2)
        .ok_or(CasCodecError::ArithmeticOverflow)?;
    if value.extents.len() != expected_extent_count {
        return Err(CasCodecError::InvalidField);
    }
    let extent_count =
        u32::try_from(expected_extent_count).map_err(|_| CasCodecError::ArithmeticOverflow)?;
    let mut expected_offset = 0_u64;
    for (index, extent) in value.extents.iter().enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| CasCodecError::ArithmeticOverflow)?;
        let expected_payload_len = if index == 0 {
            HEADER_SIZE as u64
        } else if index <= content_extent_count {
            value
                .blob_key
                .exact_len
                .saturating_sub((index as u64 - 1) * CANONICAL_CONTENT_EXTENT_LEN)
                .min(CANONICAL_CONTENT_EXTENT_LEN)
        } else {
            value
                .encoded_blob_len
                .checked_sub(expected_offset)
                .ok_or(CasCodecError::ArithmeticOverflow)?
        };
        if extent.extent_index != expected_index
            || extent.extent_count != extent_count
            || extent.encoded_offset != expected_offset
            || extent.payload_byte_len != expected_payload_len
        {
            return Err(CasCodecError::InvalidField);
        }
        let pointer = validate_context_pointer(extent.pointer, context, ExtentKind::Blob)?;
        if pointer.exact_byte_len != extent.payload_byte_len {
            return Err(CasCodecError::InvalidPointer);
        }
        for previous in &value.extents[..index] {
            let previous = validate_context_pointer(previous.pointer, context, ExtentKind::Blob)?;
            if pointers_conflict(previous, pointer) {
                return Err(CasCodecError::OverlappingPointer);
            }
        }
        expected_offset = expected_offset
            .checked_add(extent.payload_byte_len)
            .ok_or(CasCodecError::ArithmeticOverflow)?;
    }
    if expected_offset != value.encoded_blob_len {
        return Err(CasCodecError::InvalidLength);
    }
    Ok(())
}

fn write_manifest_extent(
    value: ManifestExtent,
    context: CasCodecContext,
    out: &mut [u8],
) -> Result<(), CasCodecError> {
    if out.len() != MANIFEST_EXTENT_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    out.fill(0);
    put_u32(out, 0x00, value.extent_index);
    put_u32(out, 0x04, value.extent_count);
    put_u64(out, 0x08, value.encoded_offset);
    put_u64(out, 0x10, value.payload_byte_len);
    write_pointer(
        value.pointer,
        context,
        ExtentKind::Blob,
        &mut out[0x18..0x78],
    )?;
    Ok(())
}

fn read_manifest_extent(
    input: &[u8],
    context: CasCodecContext,
) -> Result<ManifestExtent, CasCodecError> {
    if input.len() != MANIFEST_EXTENT_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    if !is_zero(&input[0x78..0x80]) {
        return Err(CasCodecError::NonZeroReserved);
    }
    let (pointer, _) = read_pointer(&input[0x18..0x78], context, ExtentKind::Blob)?;
    Ok(ManifestExtent {
        extent_index: get_u32(input, 0x00),
        extent_count: get_u32(input, 0x04),
        encoded_offset: get_u64(input, 0x08),
        payload_byte_len: get_u64(input, 0x10),
        pointer,
    })
}

pub fn encode_blob_manifest(
    value: &BlobManifest,
    context: CasCodecContext,
) -> Result<Vec<u8>, CasCodecError> {
    validate_manifest(value, context)?;
    let encoded_len = checked_table_len(
        BLOB_MANIFEST_HEADER_LEN,
        value.extents.len(),
        MANIFEST_EXTENT_LEN,
    )?;
    let mut out = vec![0; encoded_len];
    out[0x00..0x08].copy_from_slice(BLOB_MANIFEST_MAGIC);
    put_u16(&mut out, 0x08, CAS_CODEC_VERSION);
    put_u16(&mut out, 0x0a, BLOB_MANIFEST_HEADER_LEN as u16);
    put_u16(&mut out, 0x0c, MANIFEST_EXTENT_LEN as u16);
    write_blob_key(value.blob_key, &mut out[0x10..0x50])?;
    put_u64(&mut out, 0x50, value.encoded_blob_len);
    put_u32(
        &mut out,
        0x58,
        u32::try_from(value.extents.len()).map_err(|_| CasCodecError::ArithmeticOverflow)?,
    );
    put_u64(&mut out, 0x60, BLOB_MANIFEST_HEADER_LEN as u64);
    put_u64(
        &mut out,
        0x68,
        u64::try_from(encoded_len).map_err(|_| CasCodecError::ArithmeticOverflow)?,
    );
    for (index, extent) in value.extents.iter().enumerate() {
        let offset = BLOB_MANIFEST_HEADER_LEN + index * MANIFEST_EXTENT_LEN;
        write_manifest_extent(
            *extent,
            context,
            &mut out[offset..offset + MANIFEST_EXTENT_LEN],
        )?;
    }
    Ok(out)
}

pub fn decode_blob_manifest(
    input: &[u8],
    context: CasCodecContext,
) -> Result<BlobManifest, CasCodecError> {
    if input.len() < BLOB_MANIFEST_HEADER_LEN || input.len() > MAX_METADATA_PAYLOAD_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    if &input[0x00..0x08] != BLOB_MANIFEST_MAGIC {
        return Err(CasCodecError::InvalidMagic);
    }
    if get_u16(input, 0x08) != CAS_CODEC_VERSION
        || get_u16(input, 0x0a) as usize != BLOB_MANIFEST_HEADER_LEN
        || get_u16(input, 0x0c) as usize != MANIFEST_EXTENT_LEN
        || get_u16(input, 0x0e) != 0
        || get_u32(input, 0x5c) != 0
        || get_u64(input, 0x60) != BLOB_MANIFEST_HEADER_LEN as u64
    {
        return Err(CasCodecError::InvalidField);
    }
    if !is_zero(&input[0x70..0x80]) {
        return Err(CasCodecError::NonZeroReserved);
    }
    let extent_count =
        usize::try_from(get_u32(input, 0x58)).map_err(|_| CasCodecError::InvalidLength)?;
    let expected_len =
        checked_table_len(BLOB_MANIFEST_HEADER_LEN, extent_count, MANIFEST_EXTENT_LEN)?;
    if extent_count == 0
        || extent_count > MAX_MANIFEST_EXTENTS
        || get_u64(input, 0x68) != expected_len as u64
        || input.len() != expected_len
    {
        return Err(CasCodecError::InvalidLength);
    }
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(extent_count)
        .map_err(|_| CasCodecError::InvalidLength)?;
    for index in 0..extent_count {
        let offset = BLOB_MANIFEST_HEADER_LEN + index * MANIFEST_EXTENT_LEN;
        extents.push(read_manifest_extent(
            &input[offset..offset + MANIFEST_EXTENT_LEN],
            context,
        )?);
    }
    let value = BlobManifest {
        blob_key: decode_blob_key(&input[0x10..0x50])?,
        encoded_blob_len: get_u64(input, 0x50),
        extents,
    };
    validate_manifest(&value, context)?;
    Ok(value)
}

fn validate_snapshot(value: &CasSnapshot, context: CasCodecContext) -> Result<(), CasCodecError> {
    if value.checkpoint_generation == 0 {
        return Err(CasCodecError::InvalidField);
    }
    for pair in value.objects.windows(2) {
        if pair[0].object_id >= pair[1].object_id {
            return Err(CasCodecError::UnsortedOrDuplicate);
        }
    }
    for pair in value.blobs.windows(2) {
        if pair[0].blob_key >= pair[1].blob_key {
            return Err(CasCodecError::UnsortedOrDuplicate);
        }
    }
    for (index, blob) in value.blobs.iter().enumerate() {
        let pointer = validate_blob_mapping(*blob, context)?;
        for previous in &value.blobs[..index] {
            let previous = validate_blob_mapping(*previous, context)?;
            if pointers_conflict(previous, pointer) {
                return Err(CasCodecError::OverlappingPointer);
            }
        }
    }
    for object in &value.objects {
        validate_object_mapping(*object, value.checkpoint_generation)?;
        if value
            .blobs
            .binary_search_by_key(&object.blob_key, |entry| entry.blob_key)
            .is_err()
        {
            return Err(CasCodecError::MissingBlobMapping);
        }
    }
    for blob in &value.blobs {
        if !value
            .objects
            .iter()
            .any(|object| object.blob_key == blob.blob_key)
        {
            return Err(CasCodecError::OrphanBlobMapping);
        }
    }
    let object_end = checked_table_len(
        CAS_SNAPSHOT_HEADER_LEN,
        value.objects.len(),
        OBJECT_MAPPING_LEN,
    )?;
    let total = checked_table_len(object_end, value.blobs.len(), BLOB_MAPPING_LEN)?;
    if total > MAX_METADATA_PAYLOAD_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    Ok(())
}

pub fn encode_cas_snapshot(
    value: &CasSnapshot,
    context: CasCodecContext,
) -> Result<Vec<u8>, CasCodecError> {
    validate_snapshot(value, context)?;
    let object_offset = CAS_SNAPSHOT_HEADER_LEN;
    let blob_offset = checked_table_len(object_offset, value.objects.len(), OBJECT_MAPPING_LEN)?;
    let encoded_len = checked_table_len(blob_offset, value.blobs.len(), BLOB_MAPPING_LEN)?;
    let codec_version = if value
        .objects
        .iter()
        .any(|object| object.reference_codec != REFERENCE_CODEC_RAW)
    {
        CAS_GC_CODEC_VERSION
    } else {
        CAS_CODEC_VERSION
    };
    let mut out = vec![0; encoded_len];
    out[0x00..0x08].copy_from_slice(CAS_MAGIC);
    put_u16(&mut out, 0x08, codec_version);
    put_u16(&mut out, 0x0a, CAS_KIND_SNAPSHOT);
    put_u32(&mut out, 0x0c, CAS_SNAPSHOT_HEADER_LEN as u32);
    put_u64(&mut out, 0x10, value.checkpoint_generation);
    put_u32(
        &mut out,
        0x18,
        u32::try_from(value.objects.len()).map_err(|_| CasCodecError::ArithmeticOverflow)?,
    );
    put_u32(
        &mut out,
        0x1c,
        u32::try_from(value.blobs.len()).map_err(|_| CasCodecError::ArithmeticOverflow)?,
    );
    put_u32(&mut out, 0x20, OBJECT_MAPPING_LEN as u32);
    put_u32(&mut out, 0x24, BLOB_MAPPING_LEN as u32);
    put_u64(&mut out, 0x28, object_offset as u64);
    put_u64(&mut out, 0x30, blob_offset as u64);
    put_u64(&mut out, 0x38, encoded_len as u64);
    for (index, object) in value.objects.iter().enumerate() {
        let offset = object_offset + index * OBJECT_MAPPING_LEN;
        write_object_mapping(
            *object,
            value.checkpoint_generation,
            codec_version,
            &mut out[offset..offset + OBJECT_MAPPING_LEN],
        )?;
    }
    for (index, blob) in value.blobs.iter().enumerate() {
        let offset = blob_offset + index * BLOB_MAPPING_LEN;
        write_blob_mapping(*blob, context, &mut out[offset..offset + BLOB_MAPPING_LEN])?;
    }
    Ok(out)
}

pub fn decode_cas_snapshot(
    input: &[u8],
    context: CasCodecContext,
) -> Result<CasSnapshot, CasCodecError> {
    if input.len() < CAS_SNAPSHOT_HEADER_LEN || input.len() > MAX_METADATA_PAYLOAD_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    if &input[0x00..0x08] != CAS_MAGIC {
        return Err(CasCodecError::InvalidMagic);
    }
    let codec_version = get_u16(input, 0x08);
    if !matches!(codec_version, CAS_CODEC_VERSION | CAS_GC_CODEC_VERSION)
        || get_u16(input, 0x0a) != CAS_KIND_SNAPSHOT
        || get_u32(input, 0x0c) as usize != CAS_SNAPSHOT_HEADER_LEN
        || get_u32(input, 0x20) as usize != OBJECT_MAPPING_LEN
        || get_u32(input, 0x24) as usize != BLOB_MAPPING_LEN
        || get_u64(input, 0x28) != CAS_SNAPSHOT_HEADER_LEN as u64
    {
        return Err(CasCodecError::InvalidField);
    }
    if !is_zero(&input[0x40..0x80]) {
        return Err(CasCodecError::NonZeroReserved);
    }
    let object_count =
        usize::try_from(get_u32(input, 0x18)).map_err(|_| CasCodecError::InvalidLength)?;
    let blob_count =
        usize::try_from(get_u32(input, 0x1c)).map_err(|_| CasCodecError::InvalidLength)?;
    let blob_offset = checked_table_len(CAS_SNAPSHOT_HEADER_LEN, object_count, OBJECT_MAPPING_LEN)?;
    let expected_len = checked_table_len(blob_offset, blob_count, BLOB_MAPPING_LEN)?;
    if expected_len > MAX_METADATA_PAYLOAD_LEN
        || get_u64(input, 0x30) != blob_offset as u64
        || get_u64(input, 0x38) != expected_len as u64
        || input.len() != expected_len
    {
        return Err(CasCodecError::InvalidLength);
    }
    let checkpoint_generation = get_u64(input, 0x10);
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(object_count)
        .map_err(|_| CasCodecError::InvalidLength)?;
    for index in 0..object_count {
        let offset = CAS_SNAPSHOT_HEADER_LEN + index * OBJECT_MAPPING_LEN;
        objects.push(read_object_mapping(
            &input[offset..offset + OBJECT_MAPPING_LEN],
            checkpoint_generation,
            codec_version,
        )?);
    }
    let mut blobs = Vec::new();
    blobs
        .try_reserve_exact(blob_count)
        .map_err(|_| CasCodecError::InvalidLength)?;
    for index in 0..blob_count {
        let offset = blob_offset + index * BLOB_MAPPING_LEN;
        blobs.push(read_blob_mapping(&input[offset..offset + BLOB_MAPPING_LEN], context)?.0);
    }
    let value = CasSnapshot {
        checkpoint_generation,
        objects,
        blobs,
    };
    validate_snapshot(&value, context)?;
    Ok(value)
}

fn validate_previous_delta(
    chain_count: u32,
    previous_delta: PhysicalPointer,
    context: CasCodecContext,
) -> Result<Option<PointerValue>, CasCodecError> {
    match (chain_count, previous_delta) {
        (0, _) => Err(CasCodecError::InvalidField),
        (1, PhysicalPointer::Null) => Ok(None),
        (2.., pointer) => {
            let value = validate_context_pointer(pointer, context, ExtentKind::CatalogDelta)?;
            let len =
                usize::try_from(value.exact_byte_len).map_err(|_| CasCodecError::InvalidPointer)?;
            if len == CAS_DELTA_REUSE_LEN || len == CAS_DELTA_NEW_BLOB_LEN {
                Ok(Some(value))
            } else {
                Err(CasCodecError::InvalidPointer)
            }
        }
        _ => Err(CasCodecError::InvalidPointer),
    }
}

fn validate_delta(value: CasDelta, context: CasCodecContext) -> Result<(), CasCodecError> {
    if value.checkpoint_generation == 0 {
        return Err(CasCodecError::InvalidField);
    }
    let previous = validate_previous_delta(value.chain_count, value.previous_delta, context)?;
    validate_object_mapping(value.object, value.checkpoint_generation)?;
    if value.object.commit_generation != value.checkpoint_generation {
        return Err(CasCodecError::InvalidField);
    }
    if let Some(blob) = value.new_blob {
        let manifest = validate_blob_mapping(blob, context)?;
        if blob.blob_key != value.object.blob_key {
            return Err(CasCodecError::MissingBlobMapping);
        }
        if previous.is_some_and(|pointer| pointers_conflict(pointer, manifest)) {
            return Err(CasCodecError::OverlappingPointer);
        }
    }
    Ok(())
}

pub fn encode_cas_delta(
    value: CasDelta,
    context: CasCodecContext,
) -> Result<Vec<u8>, CasCodecError> {
    validate_delta(value, context)?;
    let encoded_len = if value.new_blob.is_some() {
        CAS_DELTA_NEW_BLOB_LEN
    } else {
        CAS_DELTA_REUSE_LEN
    };
    let codec_version = if value.object.reference_codec == REFERENCE_CODEC_RAW {
        CAS_CODEC_VERSION
    } else {
        CAS_GC_CODEC_VERSION
    };
    let mut out = vec![0; encoded_len];
    out[0x00..0x08].copy_from_slice(CAS_MAGIC);
    put_u16(&mut out, 0x08, codec_version);
    put_u16(&mut out, 0x0a, CAS_KIND_DELTA);
    put_u32(&mut out, 0x0c, CAS_DELTA_HEADER_LEN as u32);
    put_u64(&mut out, 0x10, value.checkpoint_generation);
    put_u32(&mut out, 0x18, value.chain_count);
    put_u32(
        &mut out,
        0x1c,
        if value.new_blob.is_some() {
            DELTA_FLAG_NEW_BLOB
        } else {
            0
        },
    );
    put_u32(&mut out, 0x20, OBJECT_MAPPING_LEN as u32);
    put_u32(&mut out, 0x24, BLOB_MAPPING_LEN as u32);
    if value.chain_count > 1 {
        write_pointer(
            value.previous_delta,
            context,
            ExtentKind::CatalogDelta,
            &mut out[0x30..0x90],
        )?;
    }
    put_u64(&mut out, 0x90, encoded_len as u64);
    write_object_mapping(
        value.object,
        value.checkpoint_generation,
        codec_version,
        &mut out[CAS_DELTA_HEADER_LEN..CAS_DELTA_REUSE_LEN],
    )?;
    if let Some(blob) = value.new_blob {
        write_blob_mapping(
            blob,
            context,
            &mut out[CAS_DELTA_REUSE_LEN..CAS_DELTA_NEW_BLOB_LEN],
        )?;
    }
    Ok(out)
}

pub fn decode_cas_delta(input: &[u8], context: CasCodecContext) -> Result<CasDelta, CasCodecError> {
    if input.len() != CAS_DELTA_REUSE_LEN && input.len() != CAS_DELTA_NEW_BLOB_LEN {
        return Err(CasCodecError::InvalidLength);
    }
    if &input[0x00..0x08] != CAS_MAGIC {
        return Err(CasCodecError::InvalidMagic);
    }
    let codec_version = get_u16(input, 0x08);
    if !matches!(codec_version, CAS_CODEC_VERSION | CAS_GC_CODEC_VERSION)
        || get_u16(input, 0x0a) != CAS_KIND_DELTA
        || get_u32(input, 0x0c) as usize != CAS_DELTA_HEADER_LEN
        || get_u32(input, 0x20) as usize != OBJECT_MAPPING_LEN
        || get_u32(input, 0x24) as usize != BLOB_MAPPING_LEN
        || get_u64(input, 0x90) != input.len() as u64
    {
        return Err(CasCodecError::InvalidField);
    }
    if !is_zero(&input[0x28..0x30]) || !is_zero(&input[0x98..0xa0]) {
        return Err(CasCodecError::NonZeroReserved);
    }
    let flags = get_u32(input, 0x1c);
    let has_blob = match flags {
        0 if input.len() == CAS_DELTA_REUSE_LEN => false,
        DELTA_FLAG_NEW_BLOB if input.len() == CAS_DELTA_NEW_BLOB_LEN => true,
        _ => return Err(CasCodecError::InvalidField),
    };
    let chain_count = get_u32(input, 0x18);
    let previous_delta = if chain_count == 1 {
        if !is_zero(&input[0x30..0x90]) {
            return Err(CasCodecError::InvalidPointer);
        }
        PhysicalPointer::Null
    } else {
        read_pointer(&input[0x30..0x90], context, ExtentKind::CatalogDelta)?.0
    };
    let checkpoint_generation = get_u64(input, 0x10);
    let object = read_object_mapping(
        &input[CAS_DELTA_HEADER_LEN..CAS_DELTA_REUSE_LEN],
        checkpoint_generation,
        codec_version,
    )?;
    let new_blob = if has_blob {
        Some(read_blob_mapping(&input[CAS_DELTA_REUSE_LEN..CAS_DELTA_NEW_BLOB_LEN], context)?.0)
    } else {
        None
    };
    let value = CasDelta {
        checkpoint_generation,
        chain_count,
        previous_delta,
        object,
        new_blob,
    };
    validate_delta(value, context)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(value: u8) -> StoreUuid {
        StoreUuid::new([value; 16]).unwrap()
    }

    fn context() -> CasCodecContext {
        CasCodecContext::new(uuid(7), 32, 100).unwrap()
    }

    fn key(kind: u32, len: u64, root: u8) -> BlobKey {
        BlobKey::sha256(kind, len, [root; 32]).unwrap()
    }

    fn pointer(
        segment: u64,
        generation: u64,
        descriptor: u32,
        ordinal: u32,
        len: u64,
        kind: ExtentKind,
        digest: u8,
    ) -> PhysicalPointer {
        PhysicalPointer::Value(PointerValue {
            store_uuid: uuid(7),
            segment_no: segment,
            segment_generation: generation,
            descriptor_relative_page: descriptor,
            payload_relative_page: descriptor + 2,
            payload_pages: u32::try_from(len.div_ceil(PAGE_SIZE as u64)).unwrap(),
            ordinal,
            exact_byte_len: len,
            extent_kind: kind,
            payload_sha256: [digest; 32],
        })
    }

    fn manifest_pointer(segment: u64, extent_count: usize, digest: u8) -> PhysicalPointer {
        pointer(
            segment,
            11 + segment,
            2,
            1,
            (BLOB_MANIFEST_HEADER_LEN + extent_count * MANIFEST_EXTENT_LEN) as u64,
            ExtentKind::Catalog,
            digest,
        )
    }

    fn canonical_manifest(blob_key: BlobKey, first_segment: u64) -> BlobManifest {
        let geometry = BlobGeometry::for_len(blob_key.exact_len()).unwrap();
        let content_count = usize::try_from(blob_key.exact_len())
            .unwrap()
            .div_ceil(CANONICAL_CONTENT_EXTENT_LEN as usize);
        let extent_count = content_count + 2;
        let mut extents = Vec::new();
        let mut offset = 0_u64;
        for index in 0..extent_count {
            let len = if index == 0 {
                HEADER_SIZE as u64
            } else if index <= content_count {
                blob_key
                    .exact_len()
                    .saturating_sub((index as u64 - 1) * CANONICAL_CONTENT_EXTENT_LEN)
                    .min(CANONICAL_CONTENT_EXTENT_LEN)
            } else {
                geometry.tree_len() as u64
            };
            extents.push(ManifestExtent {
                extent_index: index as u32,
                extent_count: extent_count as u32,
                encoded_offset: offset,
                payload_byte_len: len,
                pointer: pointer(
                    first_segment + index as u64,
                    10 + first_segment + index as u64,
                    2,
                    1,
                    len,
                    ExtentKind::Blob,
                    index as u8 + 1,
                ),
            });
            offset += len;
        }
        BlobManifest {
            blob_key,
            encoded_blob_len: geometry.encoded_len() as u64,
            extents,
        }
    }

    #[test]
    fn blob_key_layout_and_geometry_are_canonical() {
        let value = key(0x424c_4f42, 4097, 0xa5);
        let encoded = encode_blob_key(value).unwrap();
        assert_eq!(&encoded[0x00..0x02], &HASH_ALGORITHM_SHA256.to_le_bytes());
        assert_eq!(&encoded[0x04..0x08], &0x424c_4f42_u32.to_le_bytes());
        assert_eq!(&encoded[0x08..0x10], &4097_u64.to_le_bytes());
        assert_eq!(&encoded[0x10..0x30], &[0xa5; 32]);
        assert!(is_zero(&encoded[0x30..0x40]));
        assert_eq!(decode_blob_key(&encoded).unwrap(), value);
        assert_eq!(canonical_blob_encoded_len(0).unwrap(), 160);
        assert_eq!(canonical_blob_encoded_len(4096).unwrap(), 4_256);
        assert_eq!(canonical_blob_encoded_len(4097).unwrap(), 4_321);

        let mut corrupt = encoded;
        corrupt[0x02] = 1;
        assert_eq!(
            decode_blob_key(&corrupt),
            Err(CasCodecError::NonZeroReserved)
        );
        assert_eq!(
            BlobKey::new(2, 1, 0, [0; 32]),
            Err(CasCodecError::InvalidField)
        );
        assert_eq!(
            BlobKey::sha256(0, 0, [0; 32]),
            Err(CasCodecError::InvalidField)
        );
        assert_eq!(
            BlobKey::sha256(1, MAX_BLOB_CONTENT_LEN + 1, [0; 32]),
            Err(CasCodecError::InvalidField)
        );
    }

    #[test]
    fn manifest_roundtrip_requires_exact_contiguous_coverage() {
        let blob_key = key(3, 1_100_000, 9);
        let value = canonical_manifest(blob_key, 1);
        let encoded = encode_blob_manifest(&value, context()).unwrap();
        assert_eq!(
            encoded.len(),
            BLOB_MANIFEST_HEADER_LEN + 4 * MANIFEST_EXTENT_LEN
        );
        assert_eq!(decode_blob_manifest(&encoded, context()).unwrap(), value);

        let mut gap = value.clone();
        gap.extents[1].encoded_offset += 1;
        assert_eq!(
            encode_blob_manifest(&gap, context()),
            Err(CasCodecError::InvalidField)
        );
        let mut wrong_count = value.clone();
        wrong_count.extents[1].extent_count = 3;
        assert_eq!(
            encode_blob_manifest(&wrong_count, context()),
            Err(CasCodecError::InvalidField)
        );
        let mut wrong_kind = value.clone();
        let PhysicalPointer::Value(ref mut physical) = wrong_kind.extents[0].pointer else {
            unreachable!()
        };
        physical.extent_kind = ExtentKind::Catalog;
        assert!(encode_blob_manifest(&wrong_kind, context()).is_err());
        let mut outside = value.clone();
        let PhysicalPointer::Value(ref mut physical) = outside.extents[0].pointer else {
            unreachable!()
        };
        physical.segment_no = context().admitted_segments();
        assert_eq!(
            encode_blob_manifest(&outside, context()),
            Err(CasCodecError::Format(FormatError::InvalidPointer))
        );
    }

    #[test]
    fn manifest_rejects_pointer_overlap_reserved_bytes_and_suffixes() {
        let blob_key = key(4, 16, 4);
        let mut overlapping = canonical_manifest(blob_key, 3);
        overlapping.extents[1].pointer = pointer(3, 13, 3, 2, 16, ExtentKind::Blob, 2);
        assert_eq!(
            encode_blob_manifest(&overlapping, context()),
            Err(CasCodecError::OverlappingPointer)
        );

        overlapping = canonical_manifest(blob_key, 3);
        let encoded = encode_blob_manifest(&overlapping, context()).unwrap();
        let mut reserved = encoded.clone();
        reserved[0x70] = 1;
        assert_eq!(
            decode_blob_manifest(&reserved, context()),
            Err(CasCodecError::NonZeroReserved)
        );
        let mut suffix = encoded;
        suffix.push(0);
        assert_eq!(
            decode_blob_manifest(&suffix, context()),
            Err(CasCodecError::InvalidLength)
        );

        let mut noncanonical_split = canonical_manifest(key(4, 1_100_000, 5), 8);
        noncanonical_split.extents[1].payload_byte_len -= PAGE_SIZE as u64;
        assert_eq!(
            encode_blob_manifest(&noncanonical_split, context()),
            Err(CasCodecError::InvalidField)
        );
    }

    #[test]
    fn snapshot_roundtrip_keeps_tables_separate_and_ordered() {
        let first_key = key(1, 10, 1);
        let second_key = key(1, 20, 2);
        let first_blob = BlobMapping {
            blob_key: first_key,
            manifest: manifest_pointer(5, 3, 5),
        };
        let second_blob = BlobMapping {
            blob_key: second_key,
            manifest: manifest_pointer(6, 3, 6),
        };
        let value = CasSnapshot {
            checkpoint_generation: 8,
            objects: vec![
                ObjectMapping {
                    object_id: 1,
                    blob_key: first_key,
                    commit_generation: 7,
                    reference_codec: REFERENCE_CODEC_RAW,
                },
                ObjectMapping {
                    object_id: 2,
                    blob_key: first_key,
                    commit_generation: 8,
                    reference_codec: REFERENCE_CODEC_RAW,
                },
                ObjectMapping {
                    object_id: 3,
                    blob_key: second_key,
                    commit_generation: 8,
                    reference_codec: REFERENCE_CODEC_RAW,
                },
            ],
            blobs: vec![first_blob, second_blob],
        };
        let encoded = encode_cas_snapshot(&value, context()).unwrap();
        assert_eq!(decode_cas_snapshot(&encoded, context()).unwrap(), value);

        let mut unsorted_objects = value.clone();
        unsorted_objects.objects.swap(0, 1);
        assert_eq!(
            encode_cas_snapshot(&unsorted_objects, context()),
            Err(CasCodecError::UnsortedOrDuplicate)
        );
        let mut unsorted_blobs = value.clone();
        unsorted_blobs.blobs.swap(0, 1);
        assert_eq!(
            encode_cas_snapshot(&unsorted_blobs, context()),
            Err(CasCodecError::UnsortedOrDuplicate)
        );
        let mut missing = value.clone();
        missing.blobs.pop();
        assert_eq!(
            encode_cas_snapshot(&missing, context()),
            Err(CasCodecError::MissingBlobMapping)
        );
        let mut orphan = value.clone();
        orphan.objects.retain(|object| object.blob_key == first_key);
        assert_eq!(
            encode_cas_snapshot(&orphan, context()),
            Err(CasCodecError::OrphanBlobMapping)
        );
    }

    #[test]
    fn snapshot_rejects_aliasing_manifests_and_header_mutations() {
        let first_key = key(1, 10, 1);
        let second_key = key(1, 20, 2);
        let same_pointer = manifest_pointer(5, 3, 5);
        let value = CasSnapshot {
            checkpoint_generation: 8,
            objects: vec![],
            blobs: vec![
                BlobMapping {
                    blob_key: first_key,
                    manifest: same_pointer,
                },
                BlobMapping {
                    blob_key: second_key,
                    manifest: same_pointer,
                },
            ],
        };
        assert_eq!(
            encode_cas_snapshot(&value, context()),
            Err(CasCodecError::OverlappingPointer)
        );

        let valid = CasSnapshot {
            checkpoint_generation: 1,
            objects: vec![],
            blobs: vec![],
        };
        let encoded = encode_cas_snapshot(&valid, context()).unwrap();
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_cas_snapshot(&bad_magic, context()),
            Err(CasCodecError::InvalidMagic)
        );
        let mut reserved = encoded.clone();
        reserved[0x40] = 1;
        assert_eq!(
            decode_cas_snapshot(&reserved, context()),
            Err(CasCodecError::NonZeroReserved)
        );
        let mut suffix = encoded;
        suffix.push(0);
        assert_eq!(
            decode_cas_snapshot(&suffix, context()),
            Err(CasCodecError::InvalidLength)
        );
    }

    #[test]
    fn typed_reference_tag_requires_v2_and_v1_remains_byte_compatible() {
        let blob_key = key(1, 20, 2);
        let blob = BlobMapping {
            blob_key,
            manifest: manifest_pointer(6, 3, 6),
        };
        let mut snapshot = CasSnapshot {
            checkpoint_generation: 8,
            objects: vec![ObjectMapping {
                object_id: 1,
                blob_key,
                commit_generation: 8,
                reference_codec: REFERENCE_CODEC_RAW,
            }],
            blobs: vec![blob],
        };
        let v1 = encode_cas_snapshot(&snapshot, context()).unwrap();
        assert_eq!(get_u16(&v1, 0x08), CAS_CODEC_VERSION);
        assert!(is_zero(
            &v1[CAS_SNAPSHOT_HEADER_LEN + 0x58..CAS_SNAPSHOT_HEADER_LEN + 0x60]
        ));
        assert_eq!(decode_cas_snapshot(&v1, context()).unwrap(), snapshot);

        snapshot.objects[0].reference_codec = REFERENCE_CODEC_TYPED_V1;
        let v2 = encode_cas_snapshot(&snapshot, context()).unwrap();
        assert_eq!(get_u16(&v2, 0x08), CAS_GC_CODEC_VERSION);
        assert_eq!(
            get_u16(&v2, CAS_SNAPSHOT_HEADER_LEN + 0x58),
            REFERENCE_CODEC_TYPED_V1
        );
        assert_eq!(decode_cas_snapshot(&v2, context()).unwrap(), snapshot);

        let mut bad_reserved = v2.clone();
        bad_reserved[CAS_SNAPSHOT_HEADER_LEN + 0x5a] = 1;
        assert_eq!(
            decode_cas_snapshot(&bad_reserved, context()),
            Err(CasCodecError::NonZeroReserved)
        );
        let mut unknown = snapshot;
        unknown.objects[0].reference_codec = 3;
        assert_eq!(
            encode_cas_snapshot(&unknown, context()),
            Err(CasCodecError::InvalidField)
        );
    }

    #[test]
    fn delta_roundtrip_covers_new_and_deduplicated_blobs() {
        let blob_key = key(9, 123, 9);
        let object = ObjectMapping {
            object_id: 42,
            blob_key,
            commit_generation: 5,
            reference_codec: REFERENCE_CODEC_RAW,
        };
        let new_blob = BlobMapping {
            blob_key,
            manifest: manifest_pointer(8, 3, 8),
        };
        let first = CasDelta {
            checkpoint_generation: 5,
            chain_count: 1,
            previous_delta: PhysicalPointer::Null,
            object,
            new_blob: Some(new_blob),
        };
        let encoded = encode_cas_delta(first, context()).unwrap();
        assert_eq!(encoded.len(), CAS_DELTA_NEW_BLOB_LEN);
        assert_eq!(decode_cas_delta(&encoded, context()).unwrap(), first);

        let previous = pointer(
            9,
            40,
            2,
            1,
            CAS_DELTA_NEW_BLOB_LEN as u64,
            ExtentKind::CatalogDelta,
            9,
        );
        let reuse = CasDelta {
            checkpoint_generation: 6,
            chain_count: 2,
            previous_delta: previous,
            object: ObjectMapping {
                object_id: 43,
                blob_key,
                commit_generation: 6,
                reference_codec: REFERENCE_CODEC_RAW,
            },
            new_blob: None,
        };
        let encoded = encode_cas_delta(reuse, context()).unwrap();
        assert_eq!(encoded.len(), CAS_DELTA_REUSE_LEN);
        assert_eq!(decode_cas_delta(&encoded, context()).unwrap(), reuse);
    }

    #[test]
    fn delta_rejects_chain_key_and_generation_mismatches() {
        let blob_key = key(2, 2, 2);
        let mut value = CasDelta {
            checkpoint_generation: 7,
            chain_count: 1,
            previous_delta: PhysicalPointer::Null,
            object: ObjectMapping {
                object_id: 1,
                blob_key,
                commit_generation: 7,
                reference_codec: REFERENCE_CODEC_RAW,
            },
            new_blob: Some(BlobMapping {
                blob_key,
                manifest: manifest_pointer(10, 3, 10),
            }),
        };
        value.object.commit_generation = 6;
        assert_eq!(
            encode_cas_delta(value, context()),
            Err(CasCodecError::InvalidField)
        );
        value.object.commit_generation = 7;
        value.new_blob.as_mut().unwrap().blob_key = key(3, 2, 2);
        assert_eq!(
            encode_cas_delta(value, context()),
            Err(CasCodecError::MissingBlobMapping)
        );
        value.new_blob.as_mut().unwrap().blob_key = blob_key;
        value.chain_count = 2;
        assert_eq!(
            encode_cas_delta(value, context()),
            Err(CasCodecError::InvalidPointer)
        );

        value.previous_delta = pointer(
            10,
            21,
            2,
            1,
            CAS_DELTA_NEW_BLOB_LEN as u64,
            ExtentKind::CatalogDelta,
            10,
        );
        assert_eq!(
            encode_cas_delta(value, context()),
            Err(CasCodecError::OverlappingPointer)
        );
    }
}
