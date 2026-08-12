#![no_std]

use core::fmt;
use sha2::{Digest, Sha256};

pub const PAGE_SIZE: usize = 4096;
pub const ANCHOR_PAGES: u64 = 16;
pub const SEGMENT_PAGES: u64 = 1024;
pub const DATA_FIRST_PAGE: u32 = 2;
pub const DATA_END_PAGE: u32 = 1020;
pub const SUMMARY_BODY_PAGE: u32 = 1020;
pub const SUMMARY_SEAL_PAGE: u32 = 1021;
pub const SEGMENT_SEAL_BODY_PAGE: u32 = 1022;
pub const SEGMENT_SEAL_PAGE: u32 = 1023;
pub const MAX_EXTENT_PAYLOAD_PAGES: u32 = 256;
pub const POINTER_SIZE: usize = 0x60;
pub const FORMAT_VERSION: u16 = 1;
pub const HASH_ALGORITHM_SHA256: u16 = 1;
pub const ANCHOR_SEGMENT_NO: u64 = u64::MAX;

pub type Page = [u8; PAGE_SIZE];

const BODY_MAGIC: &[u8; 8] = b"VIBESG2\0";
const SEAL_MAGIC: &[u8; 8] = b"VIBESL2\0";
const TERMINAL_MARKER: &[u8; 16] = b"VIBESG2-SEALED!!";
const HEADER_LEN: u16 = 0x80;
const PAYLOAD_OFFSET: usize = 0x80;
const TRAILER_OFFSET: usize = 0xfd0;

pub const DESCRIPTOR_CHAIN_DOMAIN: &[u8] = b"VIBESG2-DESC-v1";
pub const DATA_CHAIN_DOMAIN: &[u8] = b"VIBESG2-DATA-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RecordKind {
    Superblock = 1,
    Checkpoint = 2,
    SegmentHeader = 3,
    Extent = 4,
    SegmentSummary = 5,
    SegmentSeal = 6,
}

impl RecordKind {
    fn from_raw(raw: u16) -> Result<Self, FormatError> {
        match raw {
            1 => Ok(Self::Superblock),
            2 => Ok(Self::Checkpoint),
            3 => Ok(Self::SegmentHeader),
            4 => Ok(Self::Extent),
            5 => Ok(Self::SegmentSummary),
            6 => Ok(Self::SegmentSeal),
            _ => Err(FormatError::UnknownRecordKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ExtentKind {
    Blob = 1,
    Catalog = 2,
    Authority = 3,
    Allocation = 4,
    CatalogDelta = 5,
}

impl ExtentKind {
    fn from_raw(raw: u16) -> Result<Self, FormatError> {
        match raw {
            1 => Ok(Self::Blob),
            2 => Ok(Self::Catalog),
            3 => Ok(Self::Authority),
            4 => Ok(Self::Allocation),
            5 => Ok(Self::CatalogDelta),
            _ => Err(FormatError::UnknownExtentKind),
        }
    }

    const fn index(self) -> usize {
        self as usize - 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    ZeroUuid,
    InvalidField,
    InvalidGeometry,
    InvalidBinding,
    InvalidPointer,
    PointerKindMismatch,
    ArithmeticOverflow,
    UnknownRecordKind,
    UnknownExtentKind,
    WrongRecordKind,
    InvalidMagic,
    InvalidVersion,
    InvalidHeaderLength,
    InvalidPayloadLength,
    NonZeroReserved,
    ChecksumMismatch,
    DigestMismatch,
    CopyMismatch,
    BindingMismatch,
    ConflictingGeneration,
    BrokenGenerationChain,
    AllocationAmplification,
    WrongSlot,
    DuplicateOrOverlappingRecord,
    IncompleteSegment,
}

pub type EncodeError = FormatError;
pub type DecodeError = FormatError;

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Storage V2 format error: {self:?}")
    }
}

impl core::error::Error for FormatError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreUuid([u8; 16]);

impl StoreUuid {
    pub fn new(bytes: [u8; 16]) -> Result<Self, FormatError> {
        if bytes == [0; 16] {
            Err(FormatError::ZeroUuid)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatGeometry {
    pub page_size: u32,
    pub anchor_pages: u32,
    pub segment_pages: u32,
    pub data_first_page: u32,
    pub data_end_page: u32,
    pub summary_body_page: u32,
    pub summary_seal_page: u32,
    pub segment_seal_body_page: u32,
    pub segment_seal_page: u32,
    pub max_extent_payload_pages: u32,
}

impl FormatGeometry {
    pub const STORAGE_V2: Self = Self {
        page_size: PAGE_SIZE as u32,
        anchor_pages: ANCHOR_PAGES as u32,
        segment_pages: SEGMENT_PAGES as u32,
        data_first_page: DATA_FIRST_PAGE,
        data_end_page: DATA_END_PAGE,
        summary_body_page: SUMMARY_BODY_PAGE,
        summary_seal_page: SUMMARY_SEAL_PAGE,
        segment_seal_body_page: SEGMENT_SEAL_BODY_PAGE,
        segment_seal_page: SEGMENT_SEAL_PAGE,
        max_extent_payload_pages: MAX_EXTENT_PAYLOAD_PAGES,
    };

    pub const fn is_storage_v2(self) -> bool {
        self.page_size == PAGE_SIZE as u32
            && self.anchor_pages == ANCHOR_PAGES as u32
            && self.segment_pages == SEGMENT_PAGES as u32
            && self.data_first_page == DATA_FIRST_PAGE
            && self.data_end_page == DATA_END_PAGE
            && self.summary_body_page == SUMMARY_BODY_PAGE
            && self.summary_seal_page == SUMMARY_SEAL_PAGE
            && self.segment_seal_body_page == SEGMENT_SEAL_BODY_PAGE
            && self.segment_seal_page == SEGMENT_SEAL_PAGE
            && self.max_extent_payload_pages == MAX_EXTENT_PAYLOAD_PAGES
    }
}

impl Default for FormatGeometry {
    fn default() -> Self {
        Self::STORAGE_V2
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordBinding {
    pub store_uuid: StoreUuid,
    pub generation: u64,
    pub segment_no: u64,
    pub ordinal: u32,
    pub self_page: u64,
    pub target_checkpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerValue {
    pub store_uuid: StoreUuid,
    pub segment_no: u64,
    pub segment_generation: u64,
    pub descriptor_relative_page: u32,
    pub payload_relative_page: u32,
    pub payload_pages: u32,
    pub ordinal: u32,
    pub exact_byte_len: u64,
    pub extent_kind: ExtentKind,
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalPointer {
    Null,
    Value(PointerValue),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub binding: RecordBinding,
    pub copy: u8,
    pub geometry: FormatGeometry,
    pub cleaner_reserve_segments: u32,
    pub initial_range_pages: u64,
    pub initial_segments: u64,
    pub device_id: [u8; 16],
    pub range_first_logical_block: u64,
    pub initial_block_count: u64,
    pub logical_block_size: u32,
    pub max_replay_records: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub binding: RecordBinding,
    pub slot: u8,
    pub previous_generation: u64,
    pub admitted_range_pages: u64,
    pub admitted_segments: u64,
    pub next_segment_generation: u64,
    pub replay_count: u32,
    pub max_replay_records: u32,
    pub cleaner_reserve_segments: u32,
    pub catalog_root: PhysicalPointer,
    pub authority_root: PhysicalPointer,
    pub allocation_root: PhysicalPointer,
    pub replay_tail: PhysicalPointer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentHeader {
    pub binding: RecordBinding,
    pub base_page: u64,
    pub previous_segment_no: u64,
    pub previous_segment_generation: u64,
    pub previous_segment_seal_body_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtentRecord {
    pub binding: RecordBinding,
    pub extent_kind: ExtentKind,
    pub object_kind: u32,
    pub extent_index: u32,
    pub extent_count: u32,
    pub payload_pages: u32,
    pub content_byte_len: u64,
    pub encoded_blob_len: u64,
    pub encoded_offset: u64,
    pub payload_byte_len: u64,
    pub payload_first_relative_page: u32,
    pub record_span_pages: u32,
    pub merkle_root: [u8; 32],
    pub payload_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentSummary {
    pub binding: RecordBinding,
    pub record_count: u32,
    pub next_free_page: u32,
    pub payload_page_count: u32,
    pub total_payload_bytes: u64,
    pub first_target_checkpoint_generation: u64,
    pub last_target_checkpoint_generation: u64,
    pub header_body_sha256: [u8; 32],
    pub descriptor_chain_sha256: [u8; 32],
    pub payload_chain_sha256: [u8; 32],
    pub kind_counts: [u32; 5],
    pub kind_bytes: [u64; 5],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentSeal {
    pub binding: RecordBinding,
    pub header_body_sha256: [u8; 32],
    pub summary_body_sha256: [u8; 32],
    pub final_descriptor_chain_sha256: [u8; 32],
    pub final_payload_chain_sha256: [u8; 32],
    pub record_count: u32,
    pub next_free_page: u32,
    pub payload_page_count: u32,
    pub total_payload_bytes: u64,
    pub target_checkpoint_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BodyDigest {
    binding: RecordBinding,
    kind: RecordKind,
    payload_len: u32,
    body_crc32c: u32,
    body_sha256: [u8; 32],
}

impl From<&BodyDigest> for BodyDigest {
    fn from(value: &BodyDigest) -> Self {
        *value
    }
}

impl BodyDigest {
    pub const fn binding(&self) -> RecordBinding {
        self.binding
    }

    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    pub const fn payload_len(&self) -> u32 {
        self.payload_len
    }

    pub const fn body_crc32c(&self) -> u32 {
        self.body_crc32c
    }

    pub const fn body_sha256(&self) -> [u8; 32] {
        self.body_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRecord<T> {
    value: T,
    digest: BodyDigest,
}

impl<T> VerifiedRecord<T> {
    pub const fn value(&self) -> &T {
        &self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub const fn digest(&self) -> BodyDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStatus<T> {
    Empty,
    Unsealed,
    Sealed(T),
}

fn map_verified_status<T>(status: DecodeStatus<VerifiedRecord<T>>) -> DecodeStatus<T> {
    match status {
        DecodeStatus::Empty => DecodeStatus::Empty,
        DecodeStatus::Unsealed => DecodeStatus::Unsealed,
        DecodeStatus::Sealed(record) => DecodeStatus::Sealed(record.value),
    }
}

pub fn admitted_pages(segment_count: u64) -> Result<u64, FormatError> {
    segment_count
        .checked_mul(SEGMENT_PAGES)
        .and_then(|pages| ANCHOR_PAGES.checked_add(pages))
        .ok_or(FormatError::ArithmeticOverflow)
}

pub fn segment_base_page(segment_no: u64) -> Result<u64, FormatError> {
    segment_no
        .checked_mul(SEGMENT_PAGES)
        .and_then(|pages| ANCHOR_PAGES.checked_add(pages))
        .ok_or(FormatError::ArithmeticOverflow)
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

pub fn payload_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
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

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

fn checked_payload_end(payload_len: u32) -> Result<usize, FormatError> {
    let end = PAYLOAD_OFFSET
        .checked_add(payload_len as usize)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if end > TRAILER_OFFSET {
        return Err(FormatError::InvalidPayloadLength);
    }
    Ok(end)
}

fn validate_binding(binding: RecordBinding) -> Result<(), FormatError> {
    if binding.generation == 0 {
        Err(FormatError::InvalidBinding)
    } else {
        Ok(())
    }
}

fn begin_body(
    kind: RecordKind,
    payload_len: u32,
    binding: RecordBinding,
    out: &mut Page,
) -> Result<(), FormatError> {
    validate_binding(binding)?;
    checked_payload_end(payload_len)?;
    out.fill(0);
    out[0..8].copy_from_slice(BODY_MAGIC);
    put_u16(out, 0x008, FORMAT_VERSION);
    put_u16(out, 0x00a, HEADER_LEN);
    put_u16(out, 0x00c, kind as u16);
    put_u32(out, 0x010, payload_len);
    out[0x018..0x028].copy_from_slice(binding.store_uuid.as_bytes());
    put_u64(out, 0x028, binding.generation);
    put_u64(out, 0x030, binding.segment_no);
    put_u32(out, 0x038, binding.ordinal);
    put_u64(out, 0x040, binding.self_page);
    put_u64(out, 0x048, binding.target_checkpoint_generation);
    Ok(())
}

fn finish_body(
    kind: RecordKind,
    payload_len: u32,
    binding: RecordBinding,
    out: &mut Page,
) -> BodyDigest {
    let crc = crc32c(&out[..TRAILER_OFFSET]);
    put_u32(out, 0xfd0, crc);
    put_u32(out, 0xfd4, !crc);
    put_u64(out, 0xfd8, binding.self_page);
    put_u64(out, 0xfe0, binding.generation);
    put_u64(out, 0xfe8, binding.segment_no);
    put_u32(out, 0xff0, binding.ordinal);
    put_u16(out, 0xff4, kind as u16);
    put_u16(out, 0xff6, FORMAT_VERSION);
    put_u32(out, 0xff8, payload_len);
    put_u16(out, 0xffc, HEADER_LEN);
    put_u16(out, 0xffe, 0);
    BodyDigest {
        binding,
        kind,
        payload_len,
        body_crc32c: crc,
        body_sha256: sha256(out),
    }
}

fn parse_body(
    body: &Page,
    expected_kind: RecordKind,
    expected_payload_len: u32,
) -> Result<BodyDigest, FormatError> {
    if &body[0..8] != BODY_MAGIC {
        return Err(FormatError::InvalidMagic);
    }
    if get_u16(body, 0x008) != FORMAT_VERSION || get_u16(body, 0xff6) != FORMAT_VERSION {
        return Err(FormatError::InvalidVersion);
    }
    if get_u16(body, 0x00a) != HEADER_LEN || get_u16(body, 0xffc) != HEADER_LEN {
        return Err(FormatError::InvalidHeaderLength);
    }
    let kind = RecordKind::from_raw(get_u16(body, 0x00c))?;
    if kind != expected_kind || get_u16(body, 0xff4) != expected_kind as u16 {
        return Err(FormatError::WrongRecordKind);
    }
    if get_u16(body, 0x00e) != 0 || get_u16(body, 0xffe) != 0 {
        return Err(FormatError::InvalidField);
    }
    let payload_len = get_u32(body, 0x010);
    if payload_len != expected_payload_len || get_u32(body, 0xff8) != payload_len {
        return Err(FormatError::InvalidPayloadLength);
    }
    let payload_end = checked_payload_end(payload_len)?;
    if get_u32(body, 0x014) != 0
        || get_u32(body, 0x03c) != 0
        || !is_zero(&body[0x050..0x080])
        || !is_zero(&body[payload_end..TRAILER_OFFSET])
    {
        return Err(FormatError::NonZeroReserved);
    }
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&body[0x018..0x028]);
    let binding = RecordBinding {
        store_uuid: StoreUuid::new(uuid)?,
        generation: get_u64(body, 0x028),
        segment_no: get_u64(body, 0x030),
        ordinal: get_u32(body, 0x038),
        self_page: get_u64(body, 0x040),
        target_checkpoint_generation: get_u64(body, 0x048),
    };
    validate_binding(binding)?;
    let crc = get_u32(body, 0xfd0);
    if crc != crc32c(&body[..TRAILER_OFFSET]) || get_u32(body, 0xfd4) != !crc {
        return Err(FormatError::ChecksumMismatch);
    }
    if get_u64(body, 0xfd8) != binding.self_page
        || get_u64(body, 0xfe0) != binding.generation
        || get_u64(body, 0xfe8) != binding.segment_no
        || get_u32(body, 0xff0) != binding.ordinal
    {
        return Err(FormatError::CopyMismatch);
    }
    Ok(BodyDigest {
        binding,
        kind,
        payload_len,
        body_crc32c: crc,
        body_sha256: sha256(body),
    })
}

pub fn encode_record_seal(
    digest: impl Into<BodyDigest>,
    out: &mut Page,
) -> Result<(), FormatError> {
    let digest = digest.into();
    out.fill(0);
    out[0..8].copy_from_slice(SEAL_MAGIC);
    put_u16(out, 0x008, FORMAT_VERSION);
    put_u16(out, 0x00a, digest.kind as u16);
    put_u16(out, 0x00c, HEADER_LEN);
    out[0x010..0x020].copy_from_slice(digest.binding.store_uuid.as_bytes());
    put_u64(out, 0x020, digest.binding.generation);
    put_u64(out, 0x028, digest.binding.segment_no);
    put_u32(out, 0x030, digest.binding.ordinal);
    put_u64(out, 0x038, digest.binding.self_page);
    put_u64(out, 0x040, digest.binding.target_checkpoint_generation);
    put_u32(out, 0x048, digest.body_crc32c);
    put_u32(out, 0x04c, !digest.body_crc32c);
    out[0x050..0x070].copy_from_slice(&digest.body_sha256);
    put_u32(out, 0x070, digest.payload_len);
    let crc = crc32c(&out[..TRAILER_OFFSET]);
    put_u32(out, 0xfd0, crc);
    put_u32(out, 0xfd4, !crc);
    put_u64(out, 0xfd8, digest.binding.self_page);
    put_u64(out, 0xfe0, digest.binding.generation);
    put_u64(out, 0xfe8, digest.binding.segment_no);
    // Publication marker is deliberately the final write to this page.
    out[0xff0..].copy_from_slice(TERMINAL_MARKER);
    Ok(())
}

fn decode_common(
    body: &Page,
    seal: &Page,
    kind: RecordKind,
    payload_len: u32,
) -> Result<DecodeStatus<BodyDigest>, FormatError> {
    if is_zero(body) && is_zero(seal) {
        return Ok(DecodeStatus::Empty);
    }
    if &seal[0xff0..] != TERMINAL_MARKER {
        return Ok(DecodeStatus::Unsealed);
    }
    let digest = parse_body(body, kind, payload_len)?;
    if &seal[0..8] != SEAL_MAGIC {
        return Err(FormatError::InvalidMagic);
    }
    if get_u16(seal, 0x008) != FORMAT_VERSION {
        return Err(FormatError::InvalidVersion);
    }
    if RecordKind::from_raw(get_u16(seal, 0x00a))? != kind {
        return Err(FormatError::WrongRecordKind);
    }
    if get_u16(seal, 0x00c) != HEADER_LEN {
        return Err(FormatError::InvalidHeaderLength);
    }
    if get_u16(seal, 0x00e) != 0 || get_u32(seal, 0x034) != 0 {
        return Err(FormatError::InvalidField);
    }
    if !is_zero(&seal[0x074..TRAILER_OFFSET]) {
        return Err(FormatError::NonZeroReserved);
    }
    let binding = digest.binding;
    if &seal[0x010..0x020] != binding.store_uuid.as_bytes()
        || get_u64(seal, 0x020) != binding.generation
        || get_u64(seal, 0x028) != binding.segment_no
        || get_u32(seal, 0x030) != binding.ordinal
        || get_u64(seal, 0x038) != binding.self_page
        || get_u64(seal, 0x040) != binding.target_checkpoint_generation
        || get_u32(seal, 0x048) != digest.body_crc32c
        || get_u32(seal, 0x04c) != !digest.body_crc32c
        || seal[0x050..0x070] != digest.body_sha256
        || get_u32(seal, 0x070) != payload_len
    {
        return Err(FormatError::BindingMismatch);
    }
    let seal_crc = get_u32(seal, 0xfd0);
    if seal_crc != crc32c(&seal[..TRAILER_OFFSET]) || get_u32(seal, 0xfd4) != !seal_crc {
        return Err(FormatError::ChecksumMismatch);
    }
    if get_u64(seal, 0xfd8) != binding.self_page
        || get_u64(seal, 0xfe0) != binding.generation
        || get_u64(seal, 0xfe8) != binding.segment_no
    {
        return Err(FormatError::CopyMismatch);
    }
    Ok(DecodeStatus::Sealed(digest))
}

fn payload_pages(exact_byte_len: u64) -> Result<u32, FormatError> {
    if exact_byte_len == 0 {
        return Err(FormatError::InvalidPointer);
    }
    let pages = exact_byte_len
        .checked_add(PAGE_SIZE as u64 - 1)
        .ok_or(FormatError::ArithmeticOverflow)?
        / PAGE_SIZE as u64;
    let pages = u32::try_from(pages).map_err(|_| FormatError::ArithmeticOverflow)?;
    if pages == 0 || pages > MAX_EXTENT_PAYLOAD_PAGES {
        return Err(FormatError::InvalidPointer);
    }
    Ok(pages)
}

pub fn encode_physical_pointer(
    pointer: PhysicalPointer,
    out: &mut [u8; POINTER_SIZE],
) -> Result<(), FormatError> {
    out.fill(0);
    let PhysicalPointer::Value(value) = pointer else {
        return Ok(());
    };
    validate_pointer_value(value)?;
    out[0..0x10].copy_from_slice(value.store_uuid.as_bytes());
    put_u64(out, 0x10, value.segment_no);
    put_u64(out, 0x18, value.segment_generation);
    put_u32(out, 0x20, value.descriptor_relative_page);
    put_u32(out, 0x24, value.payload_relative_page);
    put_u32(out, 0x28, value.payload_pages);
    put_u32(out, 0x2c, value.ordinal);
    put_u64(out, 0x30, value.exact_byte_len);
    put_u16(out, 0x38, value.extent_kind as u16);
    put_u16(out, 0x3a, HASH_ALGORITHM_SHA256);
    out[0x40..0x60].copy_from_slice(&value.payload_sha256);
    Ok(())
}

pub fn decode_physical_pointer(input: &[u8; POINTER_SIZE]) -> Result<PhysicalPointer, FormatError> {
    if is_zero(input) {
        return Ok(PhysicalPointer::Null);
    }
    if get_u16(input, 0x3a) != HASH_ALGORITHM_SHA256 || get_u32(input, 0x3c) != 0 {
        return Err(FormatError::InvalidPointer);
    }
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&input[0..0x10]);
    let mut payload_sha256 = [0; 32];
    payload_sha256.copy_from_slice(&input[0x40..0x60]);
    let value = PointerValue {
        store_uuid: StoreUuid::new(uuid)?,
        segment_no: get_u64(input, 0x10),
        segment_generation: get_u64(input, 0x18),
        descriptor_relative_page: get_u32(input, 0x20),
        payload_relative_page: get_u32(input, 0x24),
        payload_pages: get_u32(input, 0x28),
        ordinal: get_u32(input, 0x2c),
        exact_byte_len: get_u64(input, 0x30),
        extent_kind: ExtentKind::from_raw(get_u16(input, 0x38))?,
        payload_sha256,
    };
    validate_pointer_value(value)?;
    Ok(PhysicalPointer::Value(value))
}

fn validate_pointer_value(value: PointerValue) -> Result<(), FormatError> {
    if value.segment_generation == 0
        || value.ordinal == 0
        || value.descriptor_relative_page < DATA_FIRST_PAGE
        || value.payload_relative_page
            != value
                .descriptor_relative_page
                .checked_add(2)
                .ok_or(FormatError::ArithmeticOverflow)?
        || value.payload_pages != payload_pages(value.exact_byte_len)?
        || value
            .payload_relative_page
            .checked_add(value.payload_pages)
            .is_none_or(|end| end > DATA_END_PAGE)
    {
        return Err(FormatError::InvalidPointer);
    }
    Ok(())
}

pub fn validate_pointer(
    pointer: PhysicalPointer,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    expected_kind: ExtentKind,
) -> Result<(), FormatError> {
    let PhysicalPointer::Value(value) = pointer else {
        return Ok(());
    };
    validate_pointer_value(value)?;
    if value.store_uuid != store_uuid || value.segment_no >= admitted_segments {
        return Err(FormatError::InvalidPointer);
    }
    if value.extent_kind != expected_kind {
        return Err(FormatError::PointerKindMismatch);
    }
    Ok(())
}

fn pointers_overlap(left: PhysicalPointer, right: PhysicalPointer) -> bool {
    let (PhysicalPointer::Value(left), PhysicalPointer::Value(right)) = (left, right) else {
        return false;
    };
    if left.store_uuid != right.store_uuid
        || left.segment_no != right.segment_no
        || left.segment_generation != right.segment_generation
    {
        return false;
    }
    let left_end = left.payload_relative_page.checked_add(left.payload_pages);
    let right_end = right.payload_relative_page.checked_add(right.payload_pages);
    match (left_end, right_end) {
        (Some(left_end), Some(right_end)) => {
            left.descriptor_relative_page < right_end && right.descriptor_relative_page < left_end
        }
        _ => true,
    }
}

fn copy_array<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    let mut result = [0; N];
    result.copy_from_slice(&input[offset..offset + N]);
    result
}

fn write_pointer(
    out: &mut Page,
    offset: usize,
    pointer: PhysicalPointer,
) -> Result<(), FormatError> {
    let mut encoded = [0; POINTER_SIZE];
    encode_physical_pointer(pointer, &mut encoded)?;
    out[offset..offset + POINTER_SIZE].copy_from_slice(&encoded);
    Ok(())
}

fn read_pointer(input: &Page, offset: usize) -> Result<PhysicalPointer, FormatError> {
    let mut encoded = [0; POINTER_SIZE];
    encoded.copy_from_slice(&input[offset..offset + POINTER_SIZE]);
    decode_physical_pointer(&encoded)
}

fn binding_matches_digest(digest: BodyDigest, kind: RecordKind, binding: RecordBinding) -> bool {
    digest.kind == kind && digest.binding == binding
}

fn validate_superblock(value: &Superblock) -> Result<(), FormatError> {
    let expected_self_page = match value.copy {
        0 => 0,
        1 => 2,
        _ => return Err(FormatError::InvalidField),
    };
    if value.binding.generation != 1
        || value.binding.segment_no != ANCHOR_SEGMENT_NO
        || value.binding.ordinal != u32::from(value.copy)
        || value.binding.self_page != expected_self_page
        || value.binding.target_checkpoint_generation != 0
        || !value.geometry.is_storage_v2()
        || value.cleaner_reserve_segments == 0
        || u64::from(value.cleaner_reserve_segments) >= value.initial_segments
        || value.initial_range_pages != admitted_pages(value.initial_segments)?
        || is_zero(&value.device_id)
        || value.initial_block_count == 0
        || !matches!(value.logical_block_size, 512 | 1024 | 2048 | 4096)
        || value.max_replay_records == 0
    {
        return Err(FormatError::InvalidGeometry);
    }
    value
        .range_first_logical_block
        .checked_add(value.initial_block_count)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let range_bytes = value
        .initial_range_pages
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let block_bytes = value
        .initial_block_count
        .checked_mul(u64::from(value.logical_block_size))
        .ok_or(FormatError::ArithmeticOverflow)?;
    if range_bytes != block_bytes {
        return Err(FormatError::InvalidGeometry);
    }
    Ok(())
}

pub fn encode_superblock_body(
    value: &Superblock,
    out: &mut Page,
) -> Result<BodyDigest, FormatError> {
    validate_superblock(value)?;
    begin_body(RecordKind::Superblock, 0x80, value.binding, out)?;
    out[0x080] = value.copy;
    put_u32(out, 0x088, value.geometry.page_size);
    put_u32(out, 0x08c, value.geometry.anchor_pages);
    put_u32(out, 0x090, value.geometry.segment_pages);
    put_u32(out, 0x094, value.geometry.data_first_page);
    put_u32(out, 0x098, value.geometry.data_end_page);
    put_u32(out, 0x09c, value.geometry.summary_body_page);
    put_u32(out, 0x0a0, value.geometry.summary_seal_page);
    put_u32(out, 0x0a4, value.geometry.segment_seal_body_page);
    put_u32(out, 0x0a8, value.geometry.segment_seal_page);
    put_u32(out, 0x0ac, value.geometry.max_extent_payload_pages);
    put_u32(out, 0x0b0, value.cleaner_reserve_segments);
    put_u16(out, 0x0b4, HASH_ALGORITHM_SHA256);
    put_u64(out, 0x0b8, value.initial_range_pages);
    put_u64(out, 0x0c0, ANCHOR_PAGES);
    put_u64(out, 0x0c8, value.initial_segments);
    out[0x0d0..0x0e0].copy_from_slice(&value.device_id);
    put_u64(out, 0x0e0, value.range_first_logical_block);
    put_u64(out, 0x0e8, value.initial_block_count);
    put_u32(out, 0x0f0, value.logical_block_size);
    put_u32(out, 0x0f8, value.max_replay_records);
    Ok(finish_body(
        RecordKind::Superblock,
        0x80,
        value.binding,
        out,
    ))
}

pub fn decode_superblock_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<Superblock>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::Superblock, 0x80)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if !is_zero(&body[0x081..0x088])
        || get_u16(body, 0x0b6) != 0
        || get_u32(body, 0x0f4) != 0
        || get_u32(body, 0x0fc) != 0
        || get_u16(body, 0x0b4) != HASH_ALGORITHM_SHA256
        || get_u64(body, 0x0c0) != ANCHOR_PAGES
    {
        return Err(FormatError::NonZeroReserved);
    }
    let value = Superblock {
        binding: digest.binding,
        copy: body[0x080],
        geometry: FormatGeometry {
            page_size: get_u32(body, 0x088),
            anchor_pages: get_u32(body, 0x08c),
            segment_pages: get_u32(body, 0x090),
            data_first_page: get_u32(body, 0x094),
            data_end_page: get_u32(body, 0x098),
            summary_body_page: get_u32(body, 0x09c),
            summary_seal_page: get_u32(body, 0x0a0),
            segment_seal_body_page: get_u32(body, 0x0a4),
            segment_seal_page: get_u32(body, 0x0a8),
            max_extent_payload_pages: get_u32(body, 0x0ac),
        },
        cleaner_reserve_segments: get_u32(body, 0x0b0),
        initial_range_pages: get_u64(body, 0x0b8),
        initial_segments: get_u64(body, 0x0c8),
        device_id: copy_array(body, 0x0d0),
        range_first_logical_block: get_u64(body, 0x0e0),
        initial_block_count: get_u64(body, 0x0e8),
        logical_block_size: get_u32(body, 0x0f0),
        max_replay_records: get_u32(body, 0x0f8),
    };
    validate_superblock(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_superblock(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<Superblock>, FormatError> {
    decode_superblock_verified(body, seal).map(map_verified_status)
}

fn expected_checkpoint_slot(generation: u64) -> Result<u8, FormatError> {
    let previous = generation
        .checked_sub(1)
        .ok_or(FormatError::BrokenGenerationChain)?;
    Ok((previous & 1) as u8)
}

fn validate_checkpoint(value: &Checkpoint) -> Result<(), FormatError> {
    let expected_slot = expected_checkpoint_slot(value.binding.generation)?;
    if value.slot != expected_slot
        || value.binding.segment_no != ANCHOR_SEGMENT_NO
        || value.binding.ordinal != u32::from(value.slot)
        || value.binding.self_page != 4 + u64::from(value.slot) * 2
        || value.binding.target_checkpoint_generation != value.binding.generation
    {
        return Err(FormatError::WrongSlot);
    }
    let expected_previous = value.binding.generation - 1;
    if value.previous_generation != expected_previous {
        return Err(FormatError::BrokenGenerationChain);
    }
    if value.admitted_range_pages != admitted_pages(value.admitted_segments)? {
        return Err(FormatError::AllocationAmplification);
    }
    if value.next_segment_generation == 0
        || value.max_replay_records == 0
        || value.replay_count > value.max_replay_records
        || value.cleaner_reserve_segments == 0
        || u64::from(value.cleaner_reserve_segments) >= value.admitted_segments
    {
        return Err(FormatError::InvalidField);
    }
    let replay_is_null = value.replay_tail == PhysicalPointer::Null;
    if (value.replay_count == 0) != replay_is_null {
        return Err(FormatError::InvalidPointer);
    }
    for (pointer, kind) in [
        (value.catalog_root, ExtentKind::Catalog),
        (value.authority_root, ExtentKind::Authority),
        (value.allocation_root, ExtentKind::Allocation),
        (value.replay_tail, ExtentKind::CatalogDelta),
    ] {
        validate_pointer(
            pointer,
            value.binding.store_uuid,
            value.admitted_segments,
            kind,
        )?;
        if let PhysicalPointer::Value(pointer) = pointer {
            if pointer.segment_generation >= value.next_segment_generation {
                return Err(FormatError::InvalidPointer);
            }
        }
    }
    let pointers = [
        value.catalog_root,
        value.authority_root,
        value.allocation_root,
        value.replay_tail,
    ];
    for left in 0..pointers.len() {
        for right in left + 1..pointers.len() {
            if pointers_overlap(pointers[left], pointers[right]) {
                return Err(FormatError::DuplicateOrOverlappingRecord);
            }
        }
    }
    Ok(())
}

pub fn encode_checkpoint_body(
    value: &Checkpoint,
    out: &mut Page,
) -> Result<BodyDigest, FormatError> {
    validate_checkpoint(value)?;
    begin_body(RecordKind::Checkpoint, 0x1c0, value.binding, out)?;
    out[0x080] = value.slot;
    put_u64(out, 0x088, value.previous_generation);
    put_u64(out, 0x090, value.admitted_range_pages);
    put_u64(out, 0x098, value.admitted_segments);
    put_u64(out, 0x0a0, value.next_segment_generation);
    put_u32(out, 0x0a8, value.replay_count);
    put_u32(out, 0x0ac, value.max_replay_records);
    put_u32(out, 0x0b0, value.cleaner_reserve_segments);
    write_pointer(out, 0x0c0, value.catalog_root)?;
    write_pointer(out, 0x120, value.authority_root)?;
    write_pointer(out, 0x180, value.allocation_root)?;
    write_pointer(out, 0x1e0, value.replay_tail)?;
    Ok(finish_body(
        RecordKind::Checkpoint,
        0x1c0,
        value.binding,
        out,
    ))
}

pub fn decode_checkpoint_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<Checkpoint>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::Checkpoint, 0x1c0)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if !is_zero(&body[0x081..0x088]) || get_u32(body, 0x0b4) != 0 || !is_zero(&body[0x0b8..0x0c0]) {
        return Err(FormatError::NonZeroReserved);
    }
    let value = Checkpoint {
        binding: digest.binding,
        slot: body[0x080],
        previous_generation: get_u64(body, 0x088),
        admitted_range_pages: get_u64(body, 0x090),
        admitted_segments: get_u64(body, 0x098),
        next_segment_generation: get_u64(body, 0x0a0),
        replay_count: get_u32(body, 0x0a8),
        max_replay_records: get_u32(body, 0x0ac),
        cleaner_reserve_segments: get_u32(body, 0x0b0),
        catalog_root: read_pointer(body, 0x0c0)?,
        authority_root: read_pointer(body, 0x120)?,
        allocation_root: read_pointer(body, 0x180)?,
        replay_tail: read_pointer(body, 0x1e0)?,
    };
    validate_checkpoint(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_checkpoint(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<Checkpoint>, FormatError> {
    decode_checkpoint_verified(body, seal).map(map_verified_status)
}

fn checkpoints_match_superblock(
    superblock: &Superblock,
    checkpoint: &Checkpoint,
    maximum_admitted_pages: u64,
) -> Result<Option<Checkpoint>, FormatError> {
    validate_superblock(superblock)?;
    validate_checkpoint(checkpoint)?;
    if checkpoint.binding.store_uuid != superblock.binding.store_uuid
        || checkpoint.cleaner_reserve_segments != superblock.cleaner_reserve_segments
        || checkpoint.max_replay_records != superblock.max_replay_records
    {
        return Err(FormatError::BindingMismatch);
    }
    if checkpoint.admitted_range_pages < superblock.initial_range_pages
        || checkpoint.admitted_range_pages > maximum_admitted_pages
        || (checkpoint.binding.generation == 1
            && (checkpoint.admitted_range_pages != superblock.initial_range_pages
                || checkpoint.admitted_segments != superblock.initial_segments))
    {
        return Err(FormatError::AllocationAmplification);
    }
    Ok(Some(*checkpoint))
}

pub fn validate_checkpoint_against_superblock(
    superblock: &Superblock,
    checkpoint: &Checkpoint,
    maximum_admitted_pages: u64,
) -> Result<(), FormatError> {
    checkpoints_match_superblock(superblock, checkpoint, maximum_admitted_pages).map(|_| ())
}

pub fn select_checkpoint_for_superblock(
    superblock: VerifiedRecord<Superblock>,
    left: Option<VerifiedRecord<Checkpoint>>,
    right: Option<VerifiedRecord<Checkpoint>>,
    maximum_admitted_pages: u64,
) -> Result<Option<VerifiedRecord<Checkpoint>>, FormatError> {
    validate_superblock(&superblock.value)?;
    for checkpoint in [left, right].into_iter().flatten() {
        validate_checkpoint_against_superblock(
            &superblock.value,
            &checkpoint.value,
            maximum_admitted_pages,
        )?;
    }
    select_checkpoint_structural(left, right)
}

fn validate_checkpoint_transition(
    older: &Checkpoint,
    newer: &Checkpoint,
) -> Result<(), FormatError> {
    if newer.binding.generation
        != older
            .binding
            .generation
            .checked_add(1)
            .ok_or(FormatError::ArithmeticOverflow)?
        || newer.previous_generation != older.binding.generation
    {
        return Err(FormatError::BrokenGenerationChain);
    }
    if newer.binding.store_uuid != older.binding.store_uuid
        || newer.cleaner_reserve_segments != older.cleaner_reserve_segments
        || newer.max_replay_records != older.max_replay_records
    {
        return Err(FormatError::BindingMismatch);
    }
    if newer.admitted_segments < older.admitted_segments
        || newer.admitted_range_pages < older.admitted_range_pages
        || newer.next_segment_generation < older.next_segment_generation
    {
        return Err(FormatError::AllocationAmplification);
    }
    Ok(())
}

fn select_checkpoint_structural(
    left: Option<VerifiedRecord<Checkpoint>>,
    right: Option<VerifiedRecord<Checkpoint>>,
) -> Result<Option<VerifiedRecord<Checkpoint>>, FormatError> {
    if let Some(value) = left.as_ref() {
        validate_checkpoint(&value.value)?;
        if value.value.slot != 0 {
            return Err(FormatError::WrongSlot);
        }
    }
    if let Some(value) = right.as_ref() {
        validate_checkpoint(&value.value)?;
        if value.value.slot != 1 {
            return Err(FormatError::WrongSlot);
        }
    }
    match (left, right) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (Some(left), Some(right))
            if left.value.binding.generation == right.value.binding.generation =>
        {
            if left.digest == right.digest && left.value == right.value {
                Ok(Some(left))
            } else {
                Err(FormatError::ConflictingGeneration)
            }
        }
        (Some(left), Some(right)) => {
            let (older, newer) = if left.value.binding.generation < right.value.binding.generation {
                (left, right)
            } else {
                (right, left)
            };
            validate_checkpoint_transition(&older.value, &newer.value)?;
            Ok(Some(newer))
        }
    }
}

fn same_superblock_semantics(left: &Superblock, right: &Superblock) -> bool {
    left.binding.store_uuid == right.binding.store_uuid
        && left.binding.generation == right.binding.generation
        && left.geometry == right.geometry
        && left.cleaner_reserve_segments == right.cleaner_reserve_segments
        && left.initial_range_pages == right.initial_range_pages
        && left.initial_segments == right.initial_segments
        && left.device_id == right.device_id
        && left.range_first_logical_block == right.range_first_logical_block
        && left.initial_block_count == right.initial_block_count
        && left.logical_block_size == right.logical_block_size
        && left.max_replay_records == right.max_replay_records
}

pub fn select_superblock(
    left: Option<VerifiedRecord<Superblock>>,
    right: Option<VerifiedRecord<Superblock>>,
) -> Result<Option<VerifiedRecord<Superblock>>, FormatError> {
    if let Some(value) = left.as_ref() {
        validate_superblock(&value.value)?;
        if value.value.copy != 0 {
            return Err(FormatError::InvalidBinding);
        }
    }
    if let Some(value) = right.as_ref() {
        validate_superblock(&value.value)?;
        if value.value.copy != 1 {
            return Err(FormatError::InvalidBinding);
        }
    }
    match (left, right) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (Some(left), Some(right)) => {
            if same_superblock_semantics(&left.value, &right.value) {
                Ok(Some(left))
            } else {
                Err(FormatError::ConflictingGeneration)
            }
        }
    }
}

fn validate_segment_header(value: &SegmentHeader) -> Result<(), FormatError> {
    let expected_base = segment_base_page(value.binding.segment_no)?;
    let no_previous = value.previous_segment_no == ANCHOR_SEGMENT_NO
        && value.previous_segment_generation == 0
        && is_zero(&value.previous_segment_seal_body_sha256);
    let has_previous = value.previous_segment_no != ANCHOR_SEGMENT_NO
        && value.previous_segment_generation > 0
        && value.previous_segment_generation < value.binding.generation
        && !is_zero(&value.previous_segment_seal_body_sha256);
    if value.binding.segment_no == ANCHOR_SEGMENT_NO
        || value.binding.ordinal != 0
        || value.binding.self_page != expected_base
        || value.binding.target_checkpoint_generation == 0
        || value.base_page != expected_base
        || (!no_previous && !has_previous)
        || (has_previous && value.previous_segment_no == value.binding.segment_no)
    {
        return Err(FormatError::InvalidBinding);
    }
    Ok(())
}

pub fn encode_segment_header_body(
    value: &SegmentHeader,
    out: &mut Page,
) -> Result<BodyDigest, FormatError> {
    validate_segment_header(value)?;
    begin_body(RecordKind::SegmentHeader, 0x58, value.binding, out)?;
    put_u64(out, 0x080, value.base_page);
    put_u32(out, 0x088, DATA_FIRST_PAGE);
    put_u32(out, 0x08c, DATA_END_PAGE);
    put_u32(out, 0x090, SUMMARY_BODY_PAGE);
    put_u32(out, 0x094, SUMMARY_SEAL_PAGE);
    put_u32(out, 0x098, SEGMENT_SEAL_BODY_PAGE);
    put_u32(out, 0x09c, SEGMENT_SEAL_PAGE);
    put_u32(out, 0x0a0, MAX_EXTENT_PAYLOAD_PAGES);
    put_u16(out, 0x0a4, 1);
    put_u64(out, 0x0a8, value.previous_segment_no);
    put_u64(out, 0x0b0, value.previous_segment_generation);
    out[0x0b8..0x0d8].copy_from_slice(&value.previous_segment_seal_body_sha256);
    Ok(finish_body(
        RecordKind::SegmentHeader,
        0x58,
        value.binding,
        out,
    ))
}

pub fn decode_segment_header_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<SegmentHeader>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::SegmentHeader, 0x58)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if get_u32(body, 0x088) != DATA_FIRST_PAGE
        || get_u32(body, 0x08c) != DATA_END_PAGE
        || get_u32(body, 0x090) != SUMMARY_BODY_PAGE
        || get_u32(body, 0x094) != SUMMARY_SEAL_PAGE
        || get_u32(body, 0x098) != SEGMENT_SEAL_BODY_PAGE
        || get_u32(body, 0x09c) != SEGMENT_SEAL_PAGE
        || get_u32(body, 0x0a0) != MAX_EXTENT_PAYLOAD_PAGES
        || get_u16(body, 0x0a4) != 1
        || get_u16(body, 0x0a6) != 0
    {
        return Err(FormatError::InvalidGeometry);
    }
    let value = SegmentHeader {
        binding: digest.binding,
        base_page: get_u64(body, 0x080),
        previous_segment_no: get_u64(body, 0x0a8),
        previous_segment_generation: get_u64(body, 0x0b0),
        previous_segment_seal_body_sha256: copy_array(body, 0x0b8),
    };
    validate_segment_header(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_segment_header(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<SegmentHeader>, FormatError> {
    decode_segment_header_verified(body, seal).map(map_verified_status)
}

fn extent_descriptor_relative_page(value: &ExtentRecord) -> Result<u32, FormatError> {
    let base = segment_base_page(value.binding.segment_no)?;
    let relative = value
        .binding
        .self_page
        .checked_sub(base)
        .ok_or(FormatError::InvalidBinding)?;
    u32::try_from(relative).map_err(|_| FormatError::InvalidBinding)
}

fn validate_extent(value: &ExtentRecord) -> Result<(), FormatError> {
    let descriptor_relative_page = extent_descriptor_relative_page(value)?;
    let expected_payload_pages = payload_pages(value.payload_byte_len)?;
    let expected_span = expected_payload_pages
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let payload_end = value
        .payload_first_relative_page
        .checked_add(value.payload_pages)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let encoded_end = value
        .encoded_offset
        .checked_add(value.payload_byte_len)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let expected_payload_first = descriptor_relative_page
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if value.binding.segment_no == ANCHOR_SEGMENT_NO
        || value.binding.ordinal == 0
        || value.binding.target_checkpoint_generation == 0
        || value.object_kind == 0
        || value.extent_count == 0
        || value.extent_index >= value.extent_count
        || value.encoded_blob_len == 0
        || encoded_end > value.encoded_blob_len
        || value.payload_pages != expected_payload_pages
        || descriptor_relative_page < DATA_FIRST_PAGE
        || value.payload_first_relative_page != expected_payload_first
        || value.record_span_pages != expected_span
        || payload_end > DATA_END_PAGE
    {
        return Err(FormatError::InvalidField);
    }
    Ok(())
}

pub fn encode_extent_body(value: &ExtentRecord, out: &mut Page) -> Result<BodyDigest, FormatError> {
    validate_extent(value)?;
    begin_body(RecordKind::Extent, 0x80, value.binding, out)?;
    put_u16(out, 0x080, value.extent_kind as u16);
    put_u16(out, 0x082, HASH_ALGORITHM_SHA256);
    put_u32(out, 0x088, value.object_kind);
    put_u32(out, 0x08c, value.extent_index);
    put_u32(out, 0x090, value.extent_count);
    put_u32(out, 0x094, value.payload_pages);
    put_u64(out, 0x098, value.content_byte_len);
    put_u64(out, 0x0a0, value.encoded_blob_len);
    put_u64(out, 0x0a8, value.encoded_offset);
    put_u64(out, 0x0b0, value.payload_byte_len);
    put_u32(out, 0x0b8, value.payload_first_relative_page);
    put_u32(out, 0x0bc, value.record_span_pages);
    out[0x0c0..0x0e0].copy_from_slice(&value.merkle_root);
    out[0x0e0..0x100].copy_from_slice(&value.payload_sha256);
    Ok(finish_body(RecordKind::Extent, 0x80, value.binding, out))
}

pub fn decode_extent_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<ExtentRecord>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::Extent, 0x80)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if get_u16(body, 0x082) != HASH_ALGORITHM_SHA256 || get_u32(body, 0x084) != 0 {
        return Err(FormatError::InvalidField);
    }
    let value = ExtentRecord {
        binding: digest.binding,
        extent_kind: ExtentKind::from_raw(get_u16(body, 0x080))?,
        object_kind: get_u32(body, 0x088),
        extent_index: get_u32(body, 0x08c),
        extent_count: get_u32(body, 0x090),
        payload_pages: get_u32(body, 0x094),
        content_byte_len: get_u64(body, 0x098),
        encoded_blob_len: get_u64(body, 0x0a0),
        encoded_offset: get_u64(body, 0x0a8),
        payload_byte_len: get_u64(body, 0x0b0),
        payload_first_relative_page: get_u32(body, 0x0b8),
        record_span_pages: get_u32(body, 0x0bc),
        merkle_root: copy_array(body, 0x0c0),
        payload_sha256: copy_array(body, 0x0e0),
    };
    validate_extent(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_extent(body: &Page, seal: &Page) -> Result<DecodeStatus<ExtentRecord>, FormatError> {
    decode_extent_verified(body, seal).map(map_verified_status)
}

fn checked_sum_u32(values: &[u32]) -> Result<u32, FormatError> {
    values.iter().try_fold(0_u32, |sum, value| {
        sum.checked_add(*value)
            .ok_or(FormatError::ArithmeticOverflow)
    })
}

fn checked_sum_u64(values: &[u64]) -> Result<u64, FormatError> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(FormatError::ArithmeticOverflow)
    })
}

fn validate_segment_summary(value: &SegmentSummary) -> Result<(), FormatError> {
    let base = segment_base_page(value.binding.segment_no)?;
    let expected_self_page = base
        .checked_add(u64::from(SUMMARY_BODY_PAGE))
        .ok_or(FormatError::ArithmeticOverflow)?;
    let expected_ordinal = value
        .record_count
        .checked_add(1)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if value.binding.segment_no == ANCHOR_SEGMENT_NO
        || value.binding.ordinal != expected_ordinal
        || value.binding.self_page != expected_self_page
        || value.binding.target_checkpoint_generation != value.last_target_checkpoint_generation
        || value.first_target_checkpoint_generation == 0
        || value.first_target_checkpoint_generation > value.last_target_checkpoint_generation
        || value.next_free_page < DATA_FIRST_PAGE
        || value.next_free_page > DATA_END_PAGE
        || checked_sum_u32(&value.kind_counts)? != value.record_count
        || checked_sum_u64(&value.kind_bytes)? != value.total_payload_bytes
    {
        return Err(FormatError::InvalidField);
    }
    Ok(())
}

pub fn encode_segment_summary_body(
    value: &SegmentSummary,
    out: &mut Page,
) -> Result<BodyDigest, FormatError> {
    validate_segment_summary(value)?;
    begin_body(RecordKind::SegmentSummary, 0xc8, value.binding, out)?;
    put_u32(out, 0x080, value.record_count);
    put_u32(out, 0x084, value.next_free_page);
    put_u32(out, 0x088, value.payload_page_count);
    put_u64(out, 0x090, value.total_payload_bytes);
    put_u64(out, 0x098, value.first_target_checkpoint_generation);
    put_u64(out, 0x0a0, value.last_target_checkpoint_generation);
    out[0x0a8..0x0c8].copy_from_slice(&value.header_body_sha256);
    out[0x0c8..0x0e8].copy_from_slice(&value.descriptor_chain_sha256);
    out[0x0e8..0x108].copy_from_slice(&value.payload_chain_sha256);
    for (index, count) in value.kind_counts.iter().enumerate() {
        put_u32(out, 0x108 + index * 4, *count);
    }
    for (index, bytes) in value.kind_bytes.iter().enumerate() {
        put_u64(out, 0x120 + index * 8, *bytes);
    }
    Ok(finish_body(
        RecordKind::SegmentSummary,
        0xc8,
        value.binding,
        out,
    ))
}

pub fn decode_segment_summary_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<SegmentSummary>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::SegmentSummary, 0xc8)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if get_u32(body, 0x08c) != 0 || get_u32(body, 0x11c) != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    let mut kind_counts = [0; 5];
    let mut kind_bytes = [0; 5];
    for index in 0..5 {
        kind_counts[index] = get_u32(body, 0x108 + index * 4);
        kind_bytes[index] = get_u64(body, 0x120 + index * 8);
    }
    let value = SegmentSummary {
        binding: digest.binding,
        record_count: get_u32(body, 0x080),
        next_free_page: get_u32(body, 0x084),
        payload_page_count: get_u32(body, 0x088),
        total_payload_bytes: get_u64(body, 0x090),
        first_target_checkpoint_generation: get_u64(body, 0x098),
        last_target_checkpoint_generation: get_u64(body, 0x0a0),
        header_body_sha256: copy_array(body, 0x0a8),
        descriptor_chain_sha256: copy_array(body, 0x0c8),
        payload_chain_sha256: copy_array(body, 0x0e8),
        kind_counts,
        kind_bytes,
    };
    validate_segment_summary(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_segment_summary(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<SegmentSummary>, FormatError> {
    decode_segment_summary_verified(body, seal).map(map_verified_status)
}

fn validate_segment_seal(value: &SegmentSeal) -> Result<(), FormatError> {
    let base = segment_base_page(value.binding.segment_no)?;
    let expected_self_page = base
        .checked_add(u64::from(SEGMENT_SEAL_BODY_PAGE))
        .ok_or(FormatError::ArithmeticOverflow)?;
    let expected_ordinal = value
        .record_count
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    if value.binding.segment_no == ANCHOR_SEGMENT_NO
        || value.binding.ordinal != expected_ordinal
        || value.binding.self_page != expected_self_page
        || value.binding.target_checkpoint_generation != value.target_checkpoint_generation
        || value.target_checkpoint_generation == 0
        || value.next_free_page < DATA_FIRST_PAGE
        || value.next_free_page > DATA_END_PAGE
    {
        return Err(FormatError::InvalidField);
    }
    Ok(())
}

pub fn encode_segment_seal_body(
    value: &SegmentSeal,
    out: &mut Page,
) -> Result<BodyDigest, FormatError> {
    validate_segment_seal(value)?;
    begin_body(RecordKind::SegmentSeal, 0xa0, value.binding, out)?;
    out[0x080..0x0a0].copy_from_slice(&value.header_body_sha256);
    out[0x0a0..0x0c0].copy_from_slice(&value.summary_body_sha256);
    out[0x0c0..0x0e0].copy_from_slice(&value.final_descriptor_chain_sha256);
    out[0x0e0..0x100].copy_from_slice(&value.final_payload_chain_sha256);
    put_u32(out, 0x100, value.record_count);
    put_u32(out, 0x104, value.next_free_page);
    put_u32(out, 0x108, value.payload_page_count);
    put_u64(out, 0x110, value.total_payload_bytes);
    put_u64(out, 0x118, value.target_checkpoint_generation);
    Ok(finish_body(
        RecordKind::SegmentSeal,
        0xa0,
        value.binding,
        out,
    ))
}

pub fn decode_segment_seal_verified(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<VerifiedRecord<SegmentSeal>>, FormatError> {
    let digest = match decode_common(body, seal, RecordKind::SegmentSeal, 0xa0)? {
        DecodeStatus::Empty => return Ok(DecodeStatus::Empty),
        DecodeStatus::Unsealed => return Ok(DecodeStatus::Unsealed),
        DecodeStatus::Sealed(digest) => digest,
    };
    if get_u32(body, 0x10c) != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    let value = SegmentSeal {
        binding: digest.binding,
        header_body_sha256: copy_array(body, 0x080),
        summary_body_sha256: copy_array(body, 0x0a0),
        final_descriptor_chain_sha256: copy_array(body, 0x0c0),
        final_payload_chain_sha256: copy_array(body, 0x0e0),
        record_count: get_u32(body, 0x100),
        next_free_page: get_u32(body, 0x104),
        payload_page_count: get_u32(body, 0x108),
        total_payload_bytes: get_u64(body, 0x110),
        target_checkpoint_generation: get_u64(body, 0x118),
    };
    validate_segment_seal(&value)?;
    Ok(DecodeStatus::Sealed(VerifiedRecord { value, digest }))
}

pub fn decode_segment_seal(
    body: &Page,
    seal: &Page,
) -> Result<DecodeStatus<SegmentSeal>, FormatError> {
    decode_segment_seal_verified(body, seal).map(map_verified_status)
}

fn chain_initial(
    domain: &[u8],
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
) -> [u8; 32] {
    let mut state = Sha256::new();
    state.update(domain);
    state.update(store_uuid.as_bytes());
    state.update(segment_no.to_le_bytes());
    state.update(segment_generation.to_le_bytes());
    let digest = state.finalize();
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

pub fn descriptor_chain_initial(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
) -> [u8; 32] {
    chain_initial(
        DESCRIPTOR_CHAIN_DOMAIN,
        store_uuid,
        segment_no,
        segment_generation,
    )
}

pub fn payload_chain_initial(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
) -> [u8; 32] {
    chain_initial(
        DATA_CHAIN_DOMAIN,
        store_uuid,
        segment_no,
        segment_generation,
    )
}

pub fn descriptor_chain_next(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    previous: [u8; 32],
    ordinal: u32,
    descriptor_body_sha256: [u8; 32],
    payload_sha256: [u8; 32],
) -> [u8; 32] {
    let mut state = Sha256::new();
    state.update(DESCRIPTOR_CHAIN_DOMAIN);
    state.update(store_uuid.as_bytes());
    state.update(segment_no.to_le_bytes());
    state.update(segment_generation.to_le_bytes());
    state.update(previous);
    state.update(ordinal.to_le_bytes());
    state.update(descriptor_body_sha256);
    state.update(payload_sha256);
    let digest = state.finalize();
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

pub fn payload_chain_next(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    previous: [u8; 32],
    ordinal: u32,
    payload_byte_len: u64,
    payload_sha256: [u8; 32],
) -> [u8; 32] {
    let mut state = Sha256::new();
    state.update(DATA_CHAIN_DOMAIN);
    state.update(store_uuid.as_bytes());
    state.update(segment_no.to_le_bytes());
    state.update(segment_generation.to_le_bytes());
    state.update(previous);
    state.update(ordinal.to_le_bytes());
    state.update(payload_byte_len.to_le_bytes());
    state.update(payload_sha256);
    let digest = state.finalize();
    let mut result = [0; 32];
    result.copy_from_slice(&digest);
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentVerifier {
    header: SegmentHeader,
    header_body_sha256: [u8; 32],
    next_ordinal: u32,
    next_relative_page: u32,
    payload_page_count: u32,
    total_payload_bytes: u64,
    first_target_checkpoint_generation: u64,
    last_target_checkpoint_generation: u64,
    descriptor_chain_sha256: [u8; 32],
    payload_chain_sha256: [u8; 32],
    kind_counts: [u32; 5],
    kind_bytes: [u64; 5],
}

impl SegmentVerifier {
    pub fn new(header: VerifiedRecord<SegmentHeader>) -> Result<Self, FormatError> {
        let digest = header.digest;
        let header = header.value;
        validate_segment_header(&header)?;
        if !binding_matches_digest(digest, RecordKind::SegmentHeader, header.binding) {
            return Err(FormatError::BindingMismatch);
        }
        Ok(Self {
            header,
            header_body_sha256: digest.body_sha256,
            next_ordinal: 1,
            next_relative_page: DATA_FIRST_PAGE,
            payload_page_count: 0,
            total_payload_bytes: 0,
            first_target_checkpoint_generation: 0,
            last_target_checkpoint_generation: 0,
            descriptor_chain_sha256: descriptor_chain_initial(
                header.binding.store_uuid,
                header.binding.segment_no,
                header.binding.generation,
            ),
            payload_chain_sha256: payload_chain_initial(
                header.binding.store_uuid,
                header.binding.segment_no,
                header.binding.generation,
            ),
            kind_counts: [0; 5],
            kind_bytes: [0; 5],
        })
    }

    pub const fn next_ordinal(&self) -> u32 {
        self.next_ordinal
    }

    pub const fn next_relative_page(&self) -> u32 {
        self.next_relative_page
    }

    pub fn append_extent(
        &mut self,
        extent: VerifiedRecord<ExtentRecord>,
        exact_payload: &[u8],
    ) -> Result<(), FormatError> {
        let digest = extent.digest;
        let extent = extent.value;
        validate_extent(&extent)?;
        let observed_payload_len =
            u64::try_from(exact_payload.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
        if observed_payload_len != extent.payload_byte_len
            || payload_sha256(exact_payload) != extent.payload_sha256
        {
            return Err(FormatError::DigestMismatch);
        }
        if !binding_matches_digest(digest, RecordKind::Extent, extent.binding)
            || extent.binding.store_uuid != self.header.binding.store_uuid
            || extent.binding.segment_no != self.header.binding.segment_no
            || extent.binding.generation != self.header.binding.generation
            || extent.binding.ordinal != self.next_ordinal
            || extent_descriptor_relative_page(&extent)? != self.next_relative_page
            || (self.next_ordinal == 1
                && extent.binding.target_checkpoint_generation
                    != self.header.binding.target_checkpoint_generation)
            || (self.last_target_checkpoint_generation != 0
                && extent.binding.target_checkpoint_generation
                    < self.last_target_checkpoint_generation)
        {
            return Err(FormatError::DuplicateOrOverlappingRecord);
        }
        let next_relative_page = self
            .next_relative_page
            .checked_add(extent.record_span_pages)
            .ok_or(FormatError::ArithmeticOverflow)?;
        if next_relative_page > DATA_END_PAGE {
            return Err(FormatError::InvalidGeometry);
        }
        let next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let payload_page_count = self
            .payload_page_count
            .checked_add(extent.payload_pages)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let total_payload_bytes = self
            .total_payload_bytes
            .checked_add(extent.payload_byte_len)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let index = extent.extent_kind.index();
        let kind_count = self.kind_counts[index]
            .checked_add(1)
            .ok_or(FormatError::ArithmeticOverflow)?;
        let kind_bytes = self.kind_bytes[index]
            .checked_add(extent.payload_byte_len)
            .ok_or(FormatError::ArithmeticOverflow)?;

        self.descriptor_chain_sha256 = descriptor_chain_next(
            self.header.binding.store_uuid,
            self.header.binding.segment_no,
            self.header.binding.generation,
            self.descriptor_chain_sha256,
            extent.binding.ordinal,
            digest.body_sha256,
            extent.payload_sha256,
        );
        self.payload_chain_sha256 = payload_chain_next(
            self.header.binding.store_uuid,
            self.header.binding.segment_no,
            self.header.binding.generation,
            self.payload_chain_sha256,
            extent.binding.ordinal,
            extent.payload_byte_len,
            extent.payload_sha256,
        );
        self.next_relative_page = next_relative_page;
        self.next_ordinal = next_ordinal;
        self.payload_page_count = payload_page_count;
        self.total_payload_bytes = total_payload_bytes;
        if self.first_target_checkpoint_generation == 0 {
            self.first_target_checkpoint_generation = extent.binding.target_checkpoint_generation;
        }
        self.last_target_checkpoint_generation = extent.binding.target_checkpoint_generation;
        self.kind_counts[index] = kind_count;
        self.kind_bytes[index] = kind_bytes;
        Ok(())
    }

    pub fn verify_summary(
        &self,
        summary: VerifiedRecord<SegmentSummary>,
    ) -> Result<(), FormatError> {
        let digest = summary.digest;
        let summary = summary.value;
        validate_segment_summary(&summary)?;
        let record_count = self.next_ordinal - 1;
        if record_count == 0
            || !binding_matches_digest(digest, RecordKind::SegmentSummary, summary.binding)
            || summary.binding.store_uuid != self.header.binding.store_uuid
            || summary.binding.segment_no != self.header.binding.segment_no
            || summary.binding.generation != self.header.binding.generation
            || summary.record_count != record_count
            || summary.next_free_page != self.next_relative_page
            || summary.payload_page_count != self.payload_page_count
            || summary.total_payload_bytes != self.total_payload_bytes
            || summary.first_target_checkpoint_generation != self.first_target_checkpoint_generation
            || summary.last_target_checkpoint_generation != self.last_target_checkpoint_generation
            || summary.header_body_sha256 != self.header_body_sha256
            || summary.descriptor_chain_sha256 != self.descriptor_chain_sha256
            || summary.payload_chain_sha256 != self.payload_chain_sha256
            || summary.kind_counts != self.kind_counts
            || summary.kind_bytes != self.kind_bytes
        {
            return Err(FormatError::IncompleteSegment);
        }
        Ok(())
    }

    pub fn verify_seal(
        &self,
        summary: VerifiedRecord<SegmentSummary>,
        seal: VerifiedRecord<SegmentSeal>,
    ) -> Result<(), FormatError> {
        self.verify_summary(summary)?;
        let summary_digest = summary.digest;
        let summary = summary.value;
        let seal_digest = seal.digest;
        let seal = seal.value;
        validate_segment_seal(&seal)?;
        if !binding_matches_digest(seal_digest, RecordKind::SegmentSeal, seal.binding)
            || seal.binding.store_uuid != self.header.binding.store_uuid
            || seal.binding.segment_no != self.header.binding.segment_no
            || seal.binding.generation != self.header.binding.generation
            || seal.header_body_sha256 != self.header_body_sha256
            || seal.summary_body_sha256 != summary_digest.body_sha256
            || seal.final_descriptor_chain_sha256 != self.descriptor_chain_sha256
            || seal.final_payload_chain_sha256 != self.payload_chain_sha256
            || seal.record_count != summary.record_count
            || seal.next_free_page != summary.next_free_page
            || seal.payload_page_count != summary.payload_page_count
            || seal.total_payload_bytes != summary.total_payload_bytes
            || seal.target_checkpoint_generation != summary.last_target_checkpoint_generation
        {
            return Err(FormatError::IncompleteSegment);
        }
        Ok(())
    }
}
