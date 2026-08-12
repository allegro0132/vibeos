//! Canonical, fail-closed typed child-reference manifest (`refs-v1`).
//!
//! Parsing bytes is not reference admission.  GC must enter through
//! [`ReferenceCodecAdmission::decode`], which binds one non-zero ObjectKind to
//! the exact `vibe.refs-v1` tag.  Object kinds without such an admission remain
//! opaque even if their bytes happen to be a valid refs-v1 payload.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub const TYPED_REFS_VERSION: u16 = 1;
pub const TYPED_REFS_HEADER_LEN: usize = 0x60;
pub const TYPED_REFERENCE_ENTRY_LEN: usize = 0x28;
pub const REFERENCE_CODEC_TAG_LEN: usize = 0x10;
pub const MAX_TYPED_REFS_PAYLOAD_LEN: usize = 256 * 4096;
pub const MAX_TYPED_REFERENCES: usize =
    (MAX_TYPED_REFS_PAYLOAD_LEN - TYPED_REFS_HEADER_LEN) / TYPED_REFERENCE_ENTRY_LEN;

/// Stable policy tag stored in the payload and pinned by ObjectKind admission.
pub const REFS_V1_ADMISSION_TAG: [u8; REFERENCE_CODEC_TAG_LEN] = *b"vibe.refs-v1\0\0\0\0";

const TYPED_REFS_MAGIC: &[u8; 8] = b"VIBEREF1";
const KNOWN_HEADER_FLAGS: u32 = 0;
const KNOWN_ENTRY_FLAGS: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceCodecTag {
    RefsV1,
}

impl ReferenceCodecTag {
    pub const fn as_bytes(self) -> &'static [u8; REFERENCE_CODEC_TAG_LEN] {
        match self {
            Self::RefsV1 => &REFS_V1_ADMISSION_TAG,
        }
    }

    pub fn from_bytes(bytes: &[u8; REFERENCE_CODEC_TAG_LEN]) -> Result<Self, TypedRefsError> {
        if bytes == &REFS_V1_ADMISSION_TAG {
            Ok(Self::RefsV1)
        } else {
            Err(TypedRefsError::UnknownCodec)
        }
    }
}

/// A trusted policy decision that one ObjectKind is a refs-v1 manifest.
///
/// Construct these from an image/build policy, never by inspecting Blob bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceCodecAdmission {
    object_kind: u32,
    codec: ReferenceCodecTag,
}

impl ReferenceCodecAdmission {
    pub fn refs_v1(object_kind: u32) -> Result<Self, TypedRefsError> {
        if object_kind == 0 {
            return Err(TypedRefsError::InvalidField);
        }
        Ok(Self {
            object_kind,
            codec: ReferenceCodecTag::RefsV1,
        })
    }

    pub const fn object_kind(self) -> u32 {
        self.object_kind
    }

    pub const fn codec(self) -> ReferenceCodecTag {
        self.codec
    }

    /// Fail-closed admission entry point used by the marker.  A valid-looking
    /// payload of any other ObjectKind does not become a graph edge.
    pub fn decode(
        self,
        actual_object_kind: u32,
        input: &[u8],
    ) -> Result<TypedManifestRefsV1, TypedRefsError> {
        if actual_object_kind != self.object_kind || self.codec != ReferenceCodecTag::RefsV1 {
            return Err(TypedRefsError::NotAdmitted);
        }
        let value = decode_typed_manifest_refs_v1(input)?;
        if value.manifest_object_kind != actual_object_kind {
            return Err(TypedRefsError::NotAdmitted);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedObjectReference {
    pub object_id: u128,
    pub commit_generation: u64,
    pub object_kind: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedManifestRefsV1 {
    pub manifest_object_kind: u32,
    pub manifest_commit_generation: u64,
    references: Vec<TypedObjectReference>,
}

impl TypedManifestRefsV1 {
    pub fn new(
        manifest_object_kind: u32,
        manifest_commit_generation: u64,
        references: Vec<TypedObjectReference>,
    ) -> Result<Self, TypedRefsError> {
        let value = Self {
            manifest_object_kind,
            manifest_commit_generation,
            references,
        };
        validate_manifest(&value)?;
        Ok(value)
    }

    pub fn references(&self) -> &[TypedObjectReference] {
        &self.references
    }

    pub fn into_references(self) -> Vec<TypedObjectReference> {
        self.references
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedRefsError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    NonZeroReserved,
    NotAdmitted,
    OutOfBounds,
    UnknownCodec,
    UnsortedOrDuplicate,
}

impl fmt::Display for TypedRefsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ArithmeticOverflow => "refs-v1 arithmetic overflowed",
            Self::InvalidField => "refs-v1 contains an invalid field",
            Self::InvalidLength => "refs-v1 has a non-canonical length",
            Self::InvalidMagic => "refs-v1 magic is invalid",
            Self::NonZeroReserved => "refs-v1 reserved bytes or unknown flags are non-zero",
            Self::NotAdmitted => "ObjectKind is not admitted for this reference codec",
            Self::OutOfBounds => "refs-v1 exceeds its fixed metadata bound",
            Self::UnknownCodec => "reference codec admission tag is unknown",
            Self::UnsortedOrDuplicate => "refs-v1 children are not strictly ordered by ObjectId",
        })
    }
}

impl core::error::Error for TypedRefsError {}

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

fn encoded_len(reference_count: usize) -> Result<usize, TypedRefsError> {
    TYPED_REFS_HEADER_LEN
        .checked_add(
            reference_count
                .checked_mul(TYPED_REFERENCE_ENTRY_LEN)
                .ok_or(TypedRefsError::ArithmeticOverflow)?,
        )
        .ok_or(TypedRefsError::ArithmeticOverflow)
}

fn validate_manifest(value: &TypedManifestRefsV1) -> Result<(), TypedRefsError> {
    if value.manifest_object_kind == 0 || value.manifest_commit_generation == 0 {
        return Err(TypedRefsError::InvalidField);
    }
    if value.references.len() > MAX_TYPED_REFERENCES
        || encoded_len(value.references.len())? > MAX_TYPED_REFS_PAYLOAD_LEN
    {
        return Err(TypedRefsError::OutOfBounds);
    }
    let mut previous = None;
    for reference in &value.references {
        if reference.object_id == 0
            || reference.object_kind == 0
            || reference.commit_generation == 0
            || reference.commit_generation > value.manifest_commit_generation
        {
            return Err(TypedRefsError::InvalidField);
        }
        if previous.is_some_and(|object_id| object_id >= reference.object_id) {
            return Err(TypedRefsError::UnsortedOrDuplicate);
        }
        previous = Some(reference.object_id);
    }
    Ok(())
}

pub fn encode_typed_manifest_refs_v1(
    value: &TypedManifestRefsV1,
) -> Result<Vec<u8>, TypedRefsError> {
    validate_manifest(value)?;
    let encoded_len = encoded_len(value.references.len())?;
    let mut out = vec![0_u8; encoded_len];
    out[0x00..0x08].copy_from_slice(TYPED_REFS_MAGIC);
    put_u16(&mut out, 0x08, TYPED_REFS_VERSION);
    put_u16(&mut out, 0x0a, TYPED_REFS_HEADER_LEN as u16);
    put_u32(&mut out, 0x0c, KNOWN_HEADER_FLAGS);
    out[0x10..0x20].copy_from_slice(&REFS_V1_ADMISSION_TAG);
    put_u32(&mut out, 0x20, value.manifest_object_kind);
    put_u64(&mut out, 0x28, value.manifest_commit_generation);
    put_u32(&mut out, 0x30, value.references.len() as u32);
    put_u32(&mut out, 0x34, TYPED_REFERENCE_ENTRY_LEN as u32);
    put_u64(&mut out, 0x38, TYPED_REFS_HEADER_LEN as u64);
    put_u64(&mut out, 0x40, encoded_len as u64);
    for (index, reference) in value.references.iter().enumerate() {
        let offset = TYPED_REFS_HEADER_LEN + index * TYPED_REFERENCE_ENTRY_LEN;
        put_u128(&mut out, offset, reference.object_id);
        put_u64(&mut out, offset + 0x10, reference.commit_generation);
        put_u32(&mut out, offset + 0x18, reference.object_kind);
        put_u32(&mut out, offset + 0x1c, KNOWN_ENTRY_FLAGS);
        // +0x20..+0x28 remains reserved zero.
    }
    Ok(out)
}

pub fn decode_typed_manifest_refs_v1(input: &[u8]) -> Result<TypedManifestRefsV1, TypedRefsError> {
    if input.len() < TYPED_REFS_HEADER_LEN || input.len() > MAX_TYPED_REFS_PAYLOAD_LEN {
        return Err(TypedRefsError::InvalidLength);
    }
    if &input[0x00..0x08] != TYPED_REFS_MAGIC {
        return Err(TypedRefsError::InvalidMagic);
    }
    if get_u16(input, 0x08) != TYPED_REFS_VERSION
        || get_u16(input, 0x0a) as usize != TYPED_REFS_HEADER_LEN
        || get_u32(input, 0x0c) != KNOWN_HEADER_FLAGS
        || get_u32(input, 0x34) as usize != TYPED_REFERENCE_ENTRY_LEN
        || get_u64(input, 0x38) != TYPED_REFS_HEADER_LEN as u64
    {
        return Err(TypedRefsError::InvalidField);
    }
    let mut tag = [0_u8; REFERENCE_CODEC_TAG_LEN];
    tag.copy_from_slice(&input[0x10..0x20]);
    ReferenceCodecTag::from_bytes(&tag)?;
    if get_u32(input, 0x24) != 0 || !is_zero(&input[0x48..0x60]) {
        return Err(TypedRefsError::NonZeroReserved);
    }
    let reference_count =
        usize::try_from(get_u32(input, 0x30)).map_err(|_| TypedRefsError::InvalidLength)?;
    let expected_len = encoded_len(reference_count)?;
    if reference_count > MAX_TYPED_REFERENCES
        || expected_len > MAX_TYPED_REFS_PAYLOAD_LEN
        || get_u64(input, 0x40) != expected_len as u64
        || input.len() != expected_len
    {
        return Err(TypedRefsError::InvalidLength);
    }
    let mut references = Vec::new();
    references
        .try_reserve_exact(reference_count)
        .map_err(|_| TypedRefsError::OutOfBounds)?;
    for index in 0..reference_count {
        let offset = TYPED_REFS_HEADER_LEN + index * TYPED_REFERENCE_ENTRY_LEN;
        if get_u32(input, offset + 0x1c) != KNOWN_ENTRY_FLAGS
            || !is_zero(&input[offset + 0x20..offset + 0x28])
        {
            return Err(TypedRefsError::NonZeroReserved);
        }
        references.push(TypedObjectReference {
            object_id: get_u128(input, offset),
            commit_generation: get_u64(input, offset + 0x10),
            object_kind: get_u32(input, offset + 0x18),
        });
    }
    TypedManifestRefsV1::new(get_u32(input, 0x20), get_u64(input, 0x28), references)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TypedManifestRefsV1 {
        TypedManifestRefsV1::new(
            0x44,
            11,
            vec![
                TypedObjectReference {
                    object_id: 2,
                    commit_generation: 3,
                    object_kind: 7,
                },
                TypedObjectReference {
                    object_id: 9,
                    commit_generation: 10,
                    object_kind: 8,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn golden_round_trip_and_admission_binding() {
        let value = sample();
        let encoded = encode_typed_manifest_refs_v1(&value).unwrap();
        assert_eq!(&encoded[0x00..0x08], b"VIBEREF1");
        assert_eq!(&encoded[0x10..0x20], &REFS_V1_ADMISSION_TAG);
        assert_eq!(encoded.len(), 0xb0);
        assert_eq!(&encoded[0x60..0x70], &2_u128.to_le_bytes());
        assert_eq!(decode_typed_manifest_refs_v1(&encoded).unwrap(), value);

        let admission = ReferenceCodecAdmission::refs_v1(0x44).unwrap();
        assert_eq!(admission.decode(0x44, &encoded).unwrap(), value);
        assert_eq!(
            admission.decode(0x45, &encoded),
            Err(TypedRefsError::NotAdmitted)
        );
    }

    #[test]
    fn unknown_tag_flags_reserved_and_suffix_fail_closed() {
        let encoded = encode_typed_manifest_refs_v1(&sample()).unwrap();
        let mut unknown_tag = encoded.clone();
        unknown_tag[0x10] ^= 1;
        assert_eq!(
            decode_typed_manifest_refs_v1(&unknown_tag),
            Err(TypedRefsError::UnknownCodec)
        );
        for offset in [0x0c, 0x24, 0x48, 0x7c, 0x80] {
            let mut corrupt = encoded.clone();
            corrupt[offset] = 1;
            assert!(
                decode_typed_manifest_refs_v1(&corrupt).is_err(),
                "offset {offset:#x}"
            );
        }
        let mut suffix = encoded.clone();
        suffix.push(0);
        assert_eq!(
            decode_typed_manifest_refs_v1(&suffix),
            Err(TypedRefsError::InvalidLength)
        );
    }

    #[test]
    fn strict_sorted_unique_and_generation_validation() {
        for second_id in [1_u128, 2] {
            let value = TypedManifestRefsV1::new(
                1,
                5,
                vec![
                    TypedObjectReference {
                        object_id: 2,
                        commit_generation: 1,
                        object_kind: 1,
                    },
                    TypedObjectReference {
                        object_id: second_id,
                        commit_generation: 1,
                        object_kind: 1,
                    },
                ],
            );
            assert_eq!(value, Err(TypedRefsError::UnsortedOrDuplicate));
        }
        assert_eq!(
            TypedManifestRefsV1::new(
                1,
                5,
                vec![TypedObjectReference {
                    object_id: 1,
                    commit_generation: 6,
                    object_kind: 1,
                }],
            ),
            Err(TypedRefsError::InvalidField)
        );
    }

    #[test]
    fn maximum_table_is_bounded_without_unbounded_decode_allocation() {
        let mut references = Vec::new();
        references.reserve_exact(MAX_TYPED_REFERENCES);
        for index in 0..MAX_TYPED_REFERENCES {
            references.push(TypedObjectReference {
                object_id: index as u128 + 1,
                commit_generation: 1,
                object_kind: 1,
            });
        }
        let value = TypedManifestRefsV1::new(1, 1, references.clone()).unwrap();
        assert_eq!(
            encode_typed_manifest_refs_v1(&value).unwrap().len(),
            TYPED_REFS_HEADER_LEN + MAX_TYPED_REFERENCES * TYPED_REFERENCE_ENTRY_LEN
        );
        references.push(TypedObjectReference {
            object_id: MAX_TYPED_REFERENCES as u128 + 1,
            commit_generation: 1,
            object_kind: 1,
        });
        assert_eq!(
            TypedManifestRefsV1::new(1, 1, references),
            Err(TypedRefsError::OutOfBounds)
        );
    }
}
