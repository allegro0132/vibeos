//! Durable capability log format and fail-closed recovery.
//!
//! This module deliberately contains no block-device code. It defines the
//! stable, append-only representation which M4.1--M4.3 can place on durable
//! media, plus the recovery validation which prevents a crash image from
//! amplifying authority.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

pub const RECORD_SIZE: usize = 512;
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: u16 = 80;
pub const PAYLOAD_OFFSET: usize = 0x50;
pub const PAYLOAD_CAPACITY: usize = 384;
pub const CRC_OFFSET: usize = 0x1d0;
pub const SEAL_OFFSET: usize = 0x1f0;
pub const CHUNK_DATA_SIZE: usize = 360;
pub const MAX_OBJECT_CHUNKS: u32 = 1024;
pub const MAX_OBJECT_SIZE: usize = CHUNK_DATA_SIZE * MAX_OBJECT_CHUNKS as usize;

const MAGIC: &[u8; 8] = b"VIBECAP\0";
const SEAL: &[u8; 16] = b"VIBECAP-COMMIT!!";
const KNOWN_RIGHTS: u32 = 0x3f;

macro_rules! stable_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u128);

        impl $name {
            pub const fn new(value: u128) -> Option<Self> {
                if value == 0 {
                    None
                } else {
                    Some(Self(value))
                }
            }

            pub const fn get(self) -> u128 {
                self.0
            }
        }
    };
}

stable_id!(StoreId);
stable_id!(ObjectId);
stable_id!(DerivationId);
stable_id!(SpaceId);
stable_id!(TransactionId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceKind(u32);

impl ResourceKind {
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Stable content-type tag for a capability-addressed stored object. This is
/// an on-media number, never a Rust `TypeId`, address, path, or display string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKind(u32);

impl ObjectKind {
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub object_id: ObjectId,
    pub object_kind: ObjectKind,
    pub byte_len: u64,
    pub chunk_count: u32,
    pub content_crc32c: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectChunk {
    pub object_id: ObjectId,
    pub chunk_index: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectCommit {
    pub object_id: ObjectId,
    pub prepare_sequence: u64,
    pub prepare_crc32c: u32,
    pub chunk_count: u32,
    pub first_chunk_sequence: u64,
    /// CRC32C over the little-endian CRC32C values of every chunk record in
    /// chunk-index order. The empty digest is zero.
    pub chunks_crc32c: u32,
    /// Repeats the prepare's whole-object checksum so the commit binds both
    /// metadata and content.
    pub content_crc32c: u32,
}

/// Stable on-disk rights bits. These intentionally mirror `cap::Rights`, but
/// are a separate type until M4.3 installs recovered grants into a live CSpace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableRights(u32);

impl DurableRights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEND: Self = Self(1 << 2);
    pub const RECV: Self = Self(1 << 3);
    pub const GRANT: Self = Self(1 << 4);
    pub const REVOKE: Self = Self(1 << 5);
    pub const ALL: Self = Self(KNOWN_RIGHTS);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !KNOWN_RIGHTS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantFlags(u32);

impl GrantFlags {
    pub const DERIVED: Self = Self(0);
    pub const ROOT: Self = Self(1);

    const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ROOT.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_root(self) -> bool {
        self.0 == Self::ROOT.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotIdentity {
    pub space: SpaceId,
    pub slot: u32,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    pub derivation_id: DerivationId,
    pub parent_id: Option<DerivationId>,
    pub object_id: ObjectId,
    pub target: SlotIdentity,
    pub rights: DurableRights,
    pub resource_kind: ResourceKind,
    pub flags: GrantFlags,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordBody {
    Format,
    IdHighWater {
        exclusive_end: u128,
    },
    GrantPrepare(GrantRecord),
    GrantCommit {
        prepare_sequence: u64,
        prepare_crc32c: u32,
        derivation_id: DerivationId,
    },
    RevokeTombstone {
        derivation_id: DerivationId,
    },
    ObjectPrepare(ObjectMetadata),
    ObjectChunk(ObjectChunk),
    ObjectCommit(ObjectCommit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    pub store_id: StoreId,
    pub transaction_id: Option<TransactionId>,
    pub sequence: u64,
    pub previous_sequence: u64,
    pub previous_crc32c: u32,
    pub body: RecordBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedRecord {
    pub record: LogRecord,
    pub crc32c: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeStatus {
    Empty,
    /// An unsealed append. Under the documented crash model this physical slot
    /// is ignored forever and a later valid record may chain around it.
    Torn,
    Valid(DecodedRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    ZeroSequence,
    SequenceOverflow,
    BadFirstLink,
    MissingTransaction,
    UnexpectedTransaction,
    ZeroHighWater,
    ZeroPrepareSequence,
    ObjectTooLarge,
    BadChunkCount,
    BadChunkLength,
    BadFirstChunkSequence,
    BadCheckpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadMagic,
    UnsupportedVersion,
    UnknownKind,
    BadHeaderLength,
    BadPayloadLength,
    NonZeroHeaderFlags,
    NonZeroReserved,
    NonCanonicalPadding,
    BadCrc,
    BadCrcComplement,
    BadSequenceCopy,
    BadTransactionCopy,
    ZeroStoreId,
    ZeroSequence,
    BadFirstLink,
    MissingTransaction,
    UnexpectedTransaction,
    ZeroStableId,
    ZeroResourceKind,
    UnknownRights,
    UnknownGrantFlags,
    ZeroHighWater,
    ZeroPrepareSequence,
    ZeroObjectKind,
    ObjectTooLarge,
    BadChunkCount,
    BadChunkLength,
    BadFirstChunkSequence,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordKind {
    Format = 1,
    IdHighWater = 2,
    GrantPrepare = 3,
    GrantCommit = 4,
    RevokeTombstone = 5,
    ObjectPrepare = 6,
    ObjectChunk = 7,
    ObjectCommit = 8,
}

impl RecordKind {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Format),
            2 => Some(Self::IdHighWater),
            3 => Some(Self::GrantPrepare),
            4 => Some(Self::GrantCommit),
            5 => Some(Self::RevokeTombstone),
            6 => Some(Self::ObjectPrepare),
            7 => Some(Self::ObjectChunk),
            8 => Some(Self::ObjectCommit),
            _ => None,
        }
    }

    const fn payload_len(self) -> u16 {
        match self {
            Self::Format => 0,
            Self::IdHighWater => 16,
            Self::GrantPrepare => 88,
            Self::GrantCommit => 32,
            Self::RevokeTombstone => 16,
            Self::ObjectPrepare => 40,
            Self::ObjectChunk => PAYLOAD_CAPACITY as u16,
            Self::ObjectCommit => 48,
        }
    }
}

impl RecordBody {
    const fn kind(&self) -> RecordKind {
        match self {
            Self::Format => RecordKind::Format,
            Self::IdHighWater { .. } => RecordKind::IdHighWater,
            Self::GrantPrepare(_) => RecordKind::GrantPrepare,
            Self::GrantCommit { .. } => RecordKind::GrantCommit,
            Self::RevokeTombstone { .. } => RecordKind::RevokeTombstone,
            Self::ObjectPrepare(_) => RecordKind::ObjectPrepare,
            Self::ObjectChunk(_) => RecordKind::ObjectChunk,
            Self::ObjectCommit(_) => RecordKind::ObjectCommit,
        }
    }
}

impl LogRecord {
    pub fn encode(&self) -> Result<[u8; RECORD_SIZE], EncodeError> {
        validate_envelope(self)?;
        let mut out = [0u8; RECORD_SIZE];
        out[0..8].copy_from_slice(MAGIC);
        put_u16(&mut out, 0x08, FORMAT_VERSION);
        put_u16(&mut out, 0x0a, self.body.kind() as u16);
        put_u16(&mut out, 0x0c, HEADER_LEN);
        put_u16(&mut out, 0x0e, self.body.kind().payload_len());
        put_u64(&mut out, 0x10, self.sequence);
        put_u64(&mut out, 0x18, self.previous_sequence);
        put_u32(&mut out, 0x20, self.previous_crc32c);
        put_u32(&mut out, 0x24, 0);
        put_u128(&mut out, 0x28, self.store_id.get());
        put_u128(
            &mut out,
            0x38,
            self.transaction_id.map(TransactionId::get).unwrap_or(0),
        );

        match &self.body {
            RecordBody::Format => {}
            RecordBody::IdHighWater { exclusive_end } => {
                put_u128(&mut out, PAYLOAD_OFFSET, *exclusive_end);
            }
            RecordBody::GrantPrepare(grant) => {
                let mut at = PAYLOAD_OFFSET;
                put_u128(&mut out, at, grant.derivation_id.get());
                at += 16;
                put_u128(
                    &mut out,
                    at,
                    grant.parent_id.map(DerivationId::get).unwrap_or(0),
                );
                at += 16;
                put_u128(&mut out, at, grant.object_id.get());
                at += 16;
                put_u128(&mut out, at, grant.target.space.get());
                at += 16;
                put_u32(&mut out, at, grant.target.slot);
                at += 4;
                put_u32(&mut out, at, grant.rights.bits());
                at += 4;
                put_u64(&mut out, at, grant.target.generation);
                at += 8;
                put_u32(&mut out, at, grant.resource_kind.get());
                at += 4;
                put_u32(&mut out, at, grant.flags.bits());
            }
            RecordBody::GrantCommit {
                prepare_sequence,
                prepare_crc32c,
                derivation_id,
            } => {
                put_u64(&mut out, PAYLOAD_OFFSET, *prepare_sequence);
                put_u32(&mut out, PAYLOAD_OFFSET + 8, *prepare_crc32c);
                put_u32(&mut out, PAYLOAD_OFFSET + 12, 0);
                put_u128(&mut out, PAYLOAD_OFFSET + 16, derivation_id.get());
            }
            RecordBody::RevokeTombstone { derivation_id } => {
                put_u128(&mut out, PAYLOAD_OFFSET, derivation_id.get());
            }
            RecordBody::ObjectPrepare(metadata) => {
                put_u128(&mut out, PAYLOAD_OFFSET, metadata.object_id.get());
                put_u32(&mut out, PAYLOAD_OFFSET + 16, metadata.object_kind.get());
                put_u64(&mut out, PAYLOAD_OFFSET + 24, metadata.byte_len);
                put_u32(&mut out, PAYLOAD_OFFSET + 32, metadata.chunk_count);
                put_u32(&mut out, PAYLOAD_OFFSET + 36, metadata.content_crc32c);
            }
            RecordBody::ObjectChunk(chunk) => {
                put_u128(&mut out, PAYLOAD_OFFSET, chunk.object_id.get());
                put_u32(&mut out, PAYLOAD_OFFSET + 16, chunk.chunk_index);
                put_u16(&mut out, PAYLOAD_OFFSET + 20, chunk.data.len() as u16);
                out[PAYLOAD_OFFSET + 24..PAYLOAD_OFFSET + 24 + chunk.data.len()]
                    .copy_from_slice(&chunk.data);
            }
            RecordBody::ObjectCommit(commit) => {
                put_u128(&mut out, PAYLOAD_OFFSET, commit.object_id.get());
                put_u64(&mut out, PAYLOAD_OFFSET + 16, commit.prepare_sequence);
                put_u32(&mut out, PAYLOAD_OFFSET + 24, commit.prepare_crc32c);
                put_u32(&mut out, PAYLOAD_OFFSET + 28, commit.chunk_count);
                put_u64(&mut out, PAYLOAD_OFFSET + 32, commit.first_chunk_sequence);
                put_u32(&mut out, PAYLOAD_OFFSET + 40, commit.chunks_crc32c);
                put_u32(&mut out, PAYLOAD_OFFSET + 44, commit.content_crc32c);
            }
        }

        let crc = crc32c(&out[..CRC_OFFSET]);
        put_u32(&mut out, CRC_OFFSET, crc);
        put_u32(&mut out, CRC_OFFSET + 4, !crc);
        put_u64(&mut out, CRC_OFFSET + 8, self.sequence);
        put_u128(
            &mut out,
            CRC_OFFSET + 16,
            self.transaction_id.map(TransactionId::get).unwrap_or(0),
        );
        out[SEAL_OFFSET..RECORD_SIZE].copy_from_slice(SEAL);
        Ok(out)
    }

    pub fn decode(bytes: &[u8; RECORD_SIZE]) -> Result<DecodeStatus, DecodeError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(DecodeStatus::Empty);
        }
        if &bytes[SEAL_OFFSET..RECORD_SIZE] != SEAL {
            return Ok(DecodeStatus::Torn);
        }
        if &bytes[0..8] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if get_u16(bytes, 0x08) != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion);
        }
        let kind = RecordKind::from_raw(get_u16(bytes, 0x0a)).ok_or(DecodeError::UnknownKind)?;
        if get_u16(bytes, 0x0c) != HEADER_LEN {
            return Err(DecodeError::BadHeaderLength);
        }
        let payload_len = get_u16(bytes, 0x0e);
        if payload_len != kind.payload_len() {
            return Err(DecodeError::BadPayloadLength);
        }
        if get_u32(bytes, 0x24) != 0 {
            return Err(DecodeError::NonZeroHeaderFlags);
        }
        if bytes[0x48..0x50].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonZeroReserved);
        }
        let padding = PAYLOAD_OFFSET + payload_len as usize..CRC_OFFSET;
        if bytes[padding].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonCanonicalPadding);
        }

        let crc = get_u32(bytes, CRC_OFFSET);
        if crc32c(&bytes[..CRC_OFFSET]) != crc {
            return Err(DecodeError::BadCrc);
        }
        if get_u32(bytes, CRC_OFFSET + 4) != !crc {
            return Err(DecodeError::BadCrcComplement);
        }

        let sequence = get_u64(bytes, 0x10);
        if sequence == 0 {
            return Err(DecodeError::ZeroSequence);
        }
        if get_u64(bytes, CRC_OFFSET + 8) != sequence {
            return Err(DecodeError::BadSequenceCopy);
        }
        let transaction_raw = get_u128(bytes, 0x38);
        if get_u128(bytes, CRC_OFFSET + 16) != transaction_raw {
            return Err(DecodeError::BadTransactionCopy);
        }
        let store_id = StoreId::new(get_u128(bytes, 0x28)).ok_or(DecodeError::ZeroStoreId)?;
        let transaction_id = TransactionId::new(transaction_raw);

        let body = decode_body(bytes, kind)?;
        let record = LogRecord {
            store_id,
            transaction_id,
            sequence,
            previous_sequence: get_u64(bytes, 0x18),
            previous_crc32c: get_u32(bytes, 0x20),
            body,
        };
        validate_decoded_envelope(&record)?;
        Ok(DecodeStatus::Valid(DecodedRecord {
            record,
            crc32c: crc,
        }))
    }
}

fn validate_envelope(record: &LogRecord) -> Result<(), EncodeError> {
    if record.sequence == 0 {
        return Err(EncodeError::ZeroSequence);
    }
    if record.sequence == 1 && (record.previous_sequence != 0 || record.previous_crc32c != 0) {
        return Err(EncodeError::BadFirstLink);
    }
    let needs_tx = matches!(
        record.body,
        RecordBody::GrantPrepare(_)
            | RecordBody::GrantCommit { .. }
            | RecordBody::RevokeTombstone { .. }
            | RecordBody::ObjectPrepare(_)
            | RecordBody::ObjectChunk(_)
            | RecordBody::ObjectCommit(_)
    );
    if needs_tx && record.transaction_id.is_none() {
        return Err(EncodeError::MissingTransaction);
    }
    if !needs_tx && record.transaction_id.is_some() {
        return Err(EncodeError::UnexpectedTransaction);
    }
    if matches!(record.body, RecordBody::IdHighWater { exclusive_end: 0 }) {
        return Err(EncodeError::ZeroHighWater);
    }
    if matches!(
        record.body,
        RecordBody::GrantCommit {
            prepare_sequence: 0,
            ..
        } | RecordBody::ObjectCommit(ObjectCommit {
            prepare_sequence: 0,
            ..
        })
    ) {
        return Err(EncodeError::ZeroPrepareSequence);
    }
    match &record.body {
        RecordBody::ObjectPrepare(metadata) => {
            let expected =
                checked_chunk_count(metadata.byte_len).map_err(|_| EncodeError::ObjectTooLarge)?;
            if metadata.chunk_count != expected {
                return Err(EncodeError::BadChunkCount);
            }
        }
        RecordBody::ObjectChunk(chunk) => {
            if chunk.data.is_empty() || chunk.data.len() > CHUNK_DATA_SIZE {
                return Err(EncodeError::BadChunkLength);
            }
        }
        RecordBody::ObjectCommit(commit) => {
            if commit.chunk_count > MAX_OBJECT_CHUNKS {
                return Err(EncodeError::BadChunkCount);
            }
            if (commit.chunk_count == 0) != (commit.first_chunk_sequence == 0) {
                return Err(EncodeError::BadFirstChunkSequence);
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_decoded_envelope(record: &LogRecord) -> Result<(), DecodeError> {
    if record.sequence == 1 && (record.previous_sequence != 0 || record.previous_crc32c != 0) {
        return Err(DecodeError::BadFirstLink);
    }
    let needs_tx = matches!(
        record.body,
        RecordBody::GrantPrepare(_)
            | RecordBody::GrantCommit { .. }
            | RecordBody::RevokeTombstone { .. }
            | RecordBody::ObjectPrepare(_)
            | RecordBody::ObjectChunk(_)
            | RecordBody::ObjectCommit(_)
    );
    if needs_tx && record.transaction_id.is_none() {
        return Err(DecodeError::MissingTransaction);
    }
    if !needs_tx && record.transaction_id.is_some() {
        return Err(DecodeError::UnexpectedTransaction);
    }
    Ok(())
}

fn decode_body(bytes: &[u8; RECORD_SIZE], kind: RecordKind) -> Result<RecordBody, DecodeError> {
    Ok(match kind {
        RecordKind::Format => RecordBody::Format,
        RecordKind::IdHighWater => {
            let exclusive_end = get_u128(bytes, PAYLOAD_OFFSET);
            if exclusive_end == 0 {
                return Err(DecodeError::ZeroHighWater);
            }
            RecordBody::IdHighWater { exclusive_end }
        }
        RecordKind::GrantPrepare => {
            let mut at = PAYLOAD_OFFSET;
            let derivation_id = id::<DerivationId>(get_u128(bytes, at))?;
            at += 16;
            let parent_id = DerivationId::new(get_u128(bytes, at));
            at += 16;
            let object_id = id::<ObjectId>(get_u128(bytes, at))?;
            at += 16;
            let space = id::<SpaceId>(get_u128(bytes, at))?;
            at += 16;
            let slot = get_u32(bytes, at);
            at += 4;
            let rights =
                DurableRights::from_bits(get_u32(bytes, at)).ok_or(DecodeError::UnknownRights)?;
            at += 4;
            let generation = get_u64(bytes, at);
            at += 8;
            let resource_kind =
                ResourceKind::new(get_u32(bytes, at)).ok_or(DecodeError::ZeroResourceKind)?;
            at += 4;
            let flags =
                GrantFlags::from_bits(get_u32(bytes, at)).ok_or(DecodeError::UnknownGrantFlags)?;
            RecordBody::GrantPrepare(GrantRecord {
                derivation_id,
                parent_id,
                object_id,
                target: SlotIdentity {
                    space,
                    slot,
                    generation,
                },
                rights,
                resource_kind,
                flags,
            })
        }
        RecordKind::GrantCommit => {
            if get_u32(bytes, PAYLOAD_OFFSET + 12) != 0 {
                return Err(DecodeError::NonZeroReserved);
            }
            let prepare_sequence = get_u64(bytes, PAYLOAD_OFFSET);
            if prepare_sequence == 0 {
                return Err(DecodeError::ZeroPrepareSequence);
            }
            RecordBody::GrantCommit {
                prepare_sequence,
                prepare_crc32c: get_u32(bytes, PAYLOAD_OFFSET + 8),
                derivation_id: id::<DerivationId>(get_u128(bytes, PAYLOAD_OFFSET + 16))?,
            }
        }
        RecordKind::RevokeTombstone => RecordBody::RevokeTombstone {
            derivation_id: id::<DerivationId>(get_u128(bytes, PAYLOAD_OFFSET))?,
        },
        RecordKind::ObjectPrepare => {
            if get_u32(bytes, PAYLOAD_OFFSET + 20) != 0 {
                return Err(DecodeError::NonZeroReserved);
            }
            let byte_len = get_u64(bytes, PAYLOAD_OFFSET + 24);
            let chunk_count = get_u32(bytes, PAYLOAD_OFFSET + 32);
            if chunk_count != checked_chunk_count(byte_len)? {
                return Err(DecodeError::BadChunkCount);
            }
            RecordBody::ObjectPrepare(ObjectMetadata {
                object_id: id::<ObjectId>(get_u128(bytes, PAYLOAD_OFFSET))?,
                object_kind: ObjectKind::new(get_u32(bytes, PAYLOAD_OFFSET + 16))
                    .ok_or(DecodeError::ZeroObjectKind)?,
                byte_len,
                chunk_count,
                content_crc32c: get_u32(bytes, PAYLOAD_OFFSET + 36),
            })
        }
        RecordKind::ObjectChunk => {
            if get_u16(bytes, PAYLOAD_OFFSET + 22) != 0 {
                return Err(DecodeError::NonZeroReserved);
            }
            let data_len = get_u16(bytes, PAYLOAD_OFFSET + 20) as usize;
            if data_len == 0 || data_len > CHUNK_DATA_SIZE {
                return Err(DecodeError::BadChunkLength);
            }
            let data_start = PAYLOAD_OFFSET + 24;
            if bytes[data_start + data_len..data_start + CHUNK_DATA_SIZE]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(DecodeError::NonCanonicalPadding);
            }
            RecordBody::ObjectChunk(ObjectChunk {
                object_id: id::<ObjectId>(get_u128(bytes, PAYLOAD_OFFSET))?,
                chunk_index: get_u32(bytes, PAYLOAD_OFFSET + 16),
                data: bytes[data_start..data_start + data_len].to_vec(),
            })
        }
        RecordKind::ObjectCommit => {
            let chunk_count = get_u32(bytes, PAYLOAD_OFFSET + 28);
            if chunk_count > MAX_OBJECT_CHUNKS {
                return Err(DecodeError::BadChunkCount);
            }
            let prepare_sequence = get_u64(bytes, PAYLOAD_OFFSET + 16);
            if prepare_sequence == 0 {
                return Err(DecodeError::ZeroPrepareSequence);
            }
            let first_chunk_sequence = get_u64(bytes, PAYLOAD_OFFSET + 32);
            if (chunk_count == 0) != (first_chunk_sequence == 0) {
                return Err(DecodeError::BadFirstChunkSequence);
            }
            RecordBody::ObjectCommit(ObjectCommit {
                object_id: id::<ObjectId>(get_u128(bytes, PAYLOAD_OFFSET))?,
                prepare_sequence,
                prepare_crc32c: get_u32(bytes, PAYLOAD_OFFSET + 24),
                chunk_count,
                first_chunk_sequence,
                chunks_crc32c: get_u32(bytes, PAYLOAD_OFFSET + 40),
                content_crc32c: get_u32(bytes, PAYLOAD_OFFSET + 44),
            })
        }
    })
}

fn checked_chunk_count(byte_len: u64) -> Result<u32, DecodeError> {
    if byte_len > MAX_OBJECT_SIZE as u64 {
        return Err(DecodeError::ObjectTooLarge);
    }
    if byte_len == 0 {
        return Ok(0);
    }
    let chunks = byte_len
        .checked_add(CHUNK_DATA_SIZE as u64 - 1)
        .ok_or(DecodeError::ObjectTooLarge)?
        / CHUNK_DATA_SIZE as u64;
    u32::try_from(chunks).map_err(|_| DecodeError::ObjectTooLarge)
}

trait FromNonZeroU128: Sized {
    fn from_nonzero(value: u128) -> Option<Self>;
}

impl FromNonZeroU128 for DerivationId {
    fn from_nonzero(value: u128) -> Option<Self> {
        Self::new(value)
    }
}
impl FromNonZeroU128 for ObjectId {
    fn from_nonzero(value: u128) -> Option<Self> {
        Self::new(value)
    }
}
impl FromNonZeroU128 for SpaceId {
    fn from_nonzero(value: u128) -> Option<Self> {
        Self::new(value)
    }
}

fn id<T: FromNonZeroU128>(value: u128) -> Result<T, DecodeError> {
    T::from_nonzero(value).ok_or(DecodeError::ZeroStableId)
}

/// Convenience encoder for a correctly-linked stream. It does not perform I/O
/// and therefore makes no durability claim; a storage transaction must still
/// write and flush each returned sector before publishing authority.
#[derive(Clone, Debug)]
pub struct RecordChain {
    store_id: StoreId,
    next_sequence: u64,
    previous_sequence: u64,
    previous_crc32c: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainCheckpoint {
    pub next_sequence: u64,
    pub previous_sequence: u64,
    pub previous_crc32c: u32,
}

impl RecordChain {
    pub const fn new(store_id: StoreId) -> Self {
        Self {
            store_id,
            next_sequence: 1,
            previous_sequence: 0,
            previous_crc32c: 0,
        }
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub const fn checkpoint(&self) -> ChainCheckpoint {
        ChainCheckpoint {
            next_sequence: self.next_sequence,
            previous_sequence: self.previous_sequence,
            previous_crc32c: self.previous_crc32c,
        }
    }

    pub fn from_checkpoint(
        store_id: StoreId,
        checkpoint: ChainCheckpoint,
    ) -> Result<Self, EncodeError> {
        let canonical = if checkpoint.next_sequence == 1 {
            checkpoint.previous_sequence == 0 && checkpoint.previous_crc32c == 0
        } else {
            checkpoint.next_sequence != 0
                && checkpoint
                    .previous_sequence
                    .checked_add(1)
                    .is_some_and(|next| next == checkpoint.next_sequence)
        };
        if !canonical {
            return Err(EncodeError::BadCheckpoint);
        }
        Ok(Self {
            store_id,
            next_sequence: checkpoint.next_sequence,
            previous_sequence: checkpoint.previous_sequence,
            previous_crc32c: checkpoint.previous_crc32c,
        })
    }

    pub(crate) fn ensure_capacity(&self, record_count: u64) -> Result<(), EncodeError> {
        self.next_sequence
            .checked_add(record_count)
            .ok_or(EncodeError::SequenceOverflow)
            .map(|_| ())
    }

    pub fn append(
        &mut self,
        transaction_id: Option<TransactionId>,
        body: RecordBody,
    ) -> Result<[u8; RECORD_SIZE], EncodeError> {
        self.ensure_capacity(1)?;
        let record = LogRecord {
            store_id: self.store_id,
            transaction_id,
            sequence: self.next_sequence,
            previous_sequence: self.previous_sequence,
            previous_crc32c: self.previous_crc32c,
            body,
        };
        let bytes = record.encode()?;
        let crc = get_u32(&bytes, CRC_OFFSET);
        self.previous_sequence = self.next_sequence;
        self.previous_crc32c = crc;
        self.next_sequence += 1;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootPolicy {
    /// Root grants are trust anchors and must match this record exactly.
    pub grant: GrantRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy<'a> {
    pub store_id: StoreId,
    pub roots: &'a [RootPolicy],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredGrant {
    pub grant: GrantRecord,
    pub transaction_id: TransactionId,
    pub prepare_sequence: u64,
    pub commit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredStore {
    pub store_id: StoreId,
    pub id_high_water: u128,
    pub grants: Vec<RecoveredGrant>,
    pub tombstones: Vec<DerivationId>,
    pub last_sequence: u64,
    pub last_crc32c: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    SealedRecord { sector: usize, source: DecodeError },
    MissingFormat,
    FormatNotFirst,
    DuplicateFormat,
    WrongStore { sector: usize },
    BrokenSequence { sector: usize },
    SequenceOverflow,
    NonMonotonicHighWater,
    IdNotReserved { sequence: u64 },
    IdClassCollision { sequence: u64 },
    DuplicateTransaction { sequence: u64 },
    DuplicateDerivation { sequence: u64 },
    DuplicateObject { sequence: u64 },
    CommitMismatch { sequence: u64 },
    ObjectChunkWithoutPrepare { sequence: u64 },
    UnexpectedObjectChunk { sequence: u64 },
    ObjectChunkLength { sequence: u64 },
    ObjectCommitWithoutPrepare { sequence: u64 },
    ObjectCommitMismatch { sequence: u64 },
    ObjectContentCrcMismatch { sequence: u64 },
    RootShape { sequence: u64 },
    RootNotTrusted { sequence: u64 },
    MissingParent { sequence: u64 },
    ParentCannotGrant { sequence: u64 },
    RightsAmplification { sequence: u64 },
    ObjectMismatch { sequence: u64 },
    SlotGeneration { sequence: u64 },
    SlotStillLive { sequence: u64 },
}

struct PreparedGrant {
    grant: GrantRecord,
    sequence: u64,
    crc32c: u32,
}

struct PreparedObject {
    metadata: ObjectMetadata,
    sequence: u64,
    crc32c: u32,
    next_chunk: u32,
    first_chunk_sequence: u64,
    chunk_digest: Crc32cDigest,
    content_digest: Crc32cDigest,
    byte_len: usize,
}

enum TxState {
    GrantPrepared(PreparedGrant),
    ObjectPrepared(PreparedObject),
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdClass {
    Object,
    Derivation,
    Space,
    Transaction,
}

/// Recover live authority from physical sectors.
///
/// Empty and unsealed sectors are skipped. Any *sealed* non-canonical sector,
/// chain break, invalid graph, or policy mismatch rejects the entire store.
pub fn recover(
    sectors: &[[u8; RECORD_SIZE]],
    policy: RecoveryPolicy<'_>,
) -> Result<RecoveredStore, RecoveryError> {
    // Decode-only preflight rejects every sealed malformed sector without
    // retaining ObjectChunk Vecs for the full journal.
    for (sector, bytes) in sectors.iter().enumerate() {
        match LogRecord::decode(bytes) {
            Ok(DecodeStatus::Empty | DecodeStatus::Torn | DecodeStatus::Valid(_)) => {}
            Err(source) => return Err(RecoveryError::SealedRecord { sector, source }),
        }
    }

    let mut previous_sequence = 0u64;
    let mut previous_crc = 0u32;
    let mut valid_index = 0usize;
    for (sector, bytes) in sectors.iter().enumerate() {
        let decoded = match LogRecord::decode(bytes) {
            Ok(DecodeStatus::Empty | DecodeStatus::Torn) => continue,
            Ok(DecodeStatus::Valid(decoded)) => decoded,
            Err(_) => unreachable!("decode-only preflight accepted this sector"),
        };
        let record = &decoded.record;
        if valid_index == 0 && (record.sequence != 1 || !matches!(record.body, RecordBody::Format))
        {
            return Err(RecoveryError::FormatNotFirst);
        }
        if record.store_id != policy.store_id {
            return Err(RecoveryError::WrongStore { sector });
        }
        let expected = previous_sequence
            .checked_add(1)
            .ok_or(RecoveryError::SequenceOverflow)?;
        if record.sequence != expected
            || record.previous_sequence != previous_sequence
            || record.previous_crc32c != previous_crc
        {
            return Err(RecoveryError::BrokenSequence { sector });
        }
        if valid_index != 0 && matches!(record.body, RecordBody::Format) {
            return Err(RecoveryError::DuplicateFormat);
        }
        previous_sequence = record.sequence;
        previous_crc = decoded.crc32c;
        valid_index += 1;
    }
    if valid_index == 0 {
        return Err(RecoveryError::MissingFormat);
    }

    let mut high_water = 0u128;
    let mut id_classes: BTreeMap<u128, IdClass> = BTreeMap::new();
    let mut transactions: BTreeMap<TransactionId, TxState> = BTreeMap::new();
    let mut seen_derivations = BTreeSet::new();
    let mut seen_objects = BTreeSet::new();
    let mut committed: Vec<RecoveredGrant> = Vec::new();
    let mut tombstone_sequence: BTreeMap<DerivationId, u64> = BTreeMap::new();

    // Decode and validate one record at a time. At most one <=360-byte chunk
    // Vec is transiently owned here; no per-record decoded catalog survives.
    for bytes in sectors {
        let decoded = match LogRecord::decode(bytes) {
            Ok(DecodeStatus::Empty | DecodeStatus::Torn) => continue,
            Ok(DecodeStatus::Valid(decoded)) => decoded,
            Err(_) => unreachable!("decode-only preflight accepted this sector"),
        };
        let sequence = decoded.record.sequence;
        match &decoded.record.body {
            RecordBody::Format => {}
            RecordBody::IdHighWater { exclusive_end } => {
                if *exclusive_end <= high_water {
                    return Err(RecoveryError::NonMonotonicHighWater);
                }
                high_water = *exclusive_end;
            }
            RecordBody::GrantPrepare(grant) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !ids_reserved_for_grant(grant, tx, high_water) {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    grant.derivation_id.get(),
                    IdClass::Derivation,
                    sequence,
                )?;
                if let Some(parent) = grant.parent_id {
                    claim_id_class(&mut id_classes, parent.get(), IdClass::Derivation, sequence)?;
                }
                claim_id_class(
                    &mut id_classes,
                    grant.object_id.get(),
                    IdClass::Object,
                    sequence,
                )?;
                claim_id_class(
                    &mut id_classes,
                    grant.target.space.get(),
                    IdClass::Space,
                    sequence,
                )?;
                if transactions.contains_key(&tx) {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if tombstone_sequence.contains_key(&grant.derivation_id)
                    || !seen_derivations.insert(grant.derivation_id)
                {
                    return Err(RecoveryError::DuplicateDerivation { sequence });
                }
                transactions.insert(
                    tx,
                    TxState::GrantPrepared(PreparedGrant {
                        grant: grant.clone(),
                        sequence,
                        crc32c: decoded.crc32c,
                    }),
                );
            }
            RecordBody::GrantCommit {
                prepare_sequence,
                prepare_crc32c,
                derivation_id,
            } => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), high_water)
                    || !id_reserved(derivation_id.get(), high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    derivation_id.get(),
                    IdClass::Derivation,
                    sequence,
                )?;
                match transactions.remove(&tx) {
                    Some(TxState::GrantPrepared(prepared)) => {
                        if prepared.sequence != *prepare_sequence
                            || prepared.crc32c != *prepare_crc32c
                            || prepared.grant.derivation_id != *derivation_id
                        {
                            return Err(RecoveryError::CommitMismatch { sequence });
                        }
                        committed.push(RecoveredGrant {
                            grant: prepared.grant,
                            transaction_id: tx,
                            prepare_sequence: prepared.sequence,
                            commit_sequence: sequence,
                        });
                        transactions.insert(tx, TxState::Finished);
                    }
                    Some(TxState::Finished) => {
                        return Err(RecoveryError::DuplicateTransaction { sequence });
                    }
                    Some(TxState::ObjectPrepared(_)) => {
                        return Err(RecoveryError::DuplicateTransaction { sequence });
                    }
                    None => {
                        // A complete orphan commit is harmless but consumes its
                        // transaction and derivation IDs so later records cannot
                        // attach to it or reuse stable identity.
                        if !seen_derivations.insert(*derivation_id) {
                            return Err(RecoveryError::DuplicateDerivation { sequence });
                        }
                        transactions.insert(tx, TxState::Finished);
                    }
                }
            }
            RecordBody::RevokeTombstone { derivation_id } => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), high_water)
                    || !id_reserved(derivation_id.get(), high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    derivation_id.get(),
                    IdClass::Derivation,
                    sequence,
                )?;
                if transactions.insert(tx, TxState::Finished).is_some() {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                tombstone_sequence
                    .entry(*derivation_id)
                    .and_modify(|old| *old = (*old).min(sequence))
                    .or_insert(sequence);
            }
            RecordBody::ObjectPrepare(metadata) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), high_water)
                    || !id_reserved(metadata.object_id.get(), high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    metadata.object_id.get(),
                    IdClass::Object,
                    sequence,
                )?;
                if transactions.contains_key(&tx) {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if !seen_objects.insert(metadata.object_id) {
                    return Err(RecoveryError::DuplicateObject { sequence });
                }
                transactions.insert(
                    tx,
                    TxState::ObjectPrepared(PreparedObject {
                        metadata: metadata.clone(),
                        sequence,
                        crc32c: decoded.crc32c,
                        next_chunk: 0,
                        first_chunk_sequence: 0,
                        chunk_digest: Crc32cDigest::new(),
                        content_digest: Crc32cDigest::new(),
                        byte_len: 0,
                    }),
                );
            }
            RecordBody::ObjectChunk(chunk) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), high_water)
                    || !id_reserved(chunk.object_id.get(), high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    chunk.object_id.get(),
                    IdClass::Object,
                    sequence,
                )?;
                let Some(state) = transactions.get_mut(&tx) else {
                    return Err(RecoveryError::ObjectChunkWithoutPrepare { sequence });
                };
                let TxState::ObjectPrepared(prepared) = state else {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                };
                if prepared.metadata.object_id != chunk.object_id
                    || chunk.chunk_index != prepared.next_chunk
                    || prepared.next_chunk >= prepared.metadata.chunk_count
                {
                    return Err(RecoveryError::UnexpectedObjectChunk { sequence });
                }
                let expected_len = expected_chunk_len(
                    prepared.metadata.byte_len as usize,
                    prepared.next_chunk,
                    prepared.metadata.chunk_count,
                );
                if chunk.data.len() != expected_len {
                    return Err(RecoveryError::ObjectChunkLength { sequence });
                }
                if prepared.next_chunk == 0 {
                    prepared.first_chunk_sequence = sequence;
                }
                prepared.chunk_digest.update(&decoded.crc32c.to_le_bytes());
                prepared.content_digest.update(&chunk.data);
                prepared.byte_len += chunk.data.len();
                prepared.next_chunk += 1;
            }
            RecordBody::ObjectCommit(commit) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), high_water)
                    || !id_reserved(commit.object_id.get(), high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(&mut id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    &mut id_classes,
                    commit.object_id.get(),
                    IdClass::Object,
                    sequence,
                )?;
                // Commit is an ownership transfer: removing the state prevents
                // any accumulated payload from being cloned at publication.
                let Some(state) = transactions.remove(&tx) else {
                    return Err(RecoveryError::ObjectCommitWithoutPrepare { sequence });
                };
                let TxState::ObjectPrepared(prepared) = state else {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                };
                if prepared.metadata.object_id != commit.object_id
                    || prepared.next_chunk != prepared.metadata.chunk_count
                    || commit.prepare_sequence != prepared.sequence
                    || commit.prepare_crc32c != prepared.crc32c
                    || commit.chunk_count != prepared.metadata.chunk_count
                    || commit.first_chunk_sequence != prepared.first_chunk_sequence
                    || commit.chunks_crc32c != prepared.chunk_digest.finish()
                    || commit.content_crc32c != prepared.metadata.content_crc32c
                {
                    return Err(RecoveryError::ObjectCommitMismatch { sequence });
                }
                if prepared.byte_len != prepared.metadata.byte_len as usize
                    || prepared.content_digest.finish() != prepared.metadata.content_crc32c
                {
                    return Err(RecoveryError::ObjectContentCrcMismatch { sequence });
                }
                transactions.insert(tx, TxState::Finished);
            }
        }
    }

    let mut graph: BTreeMap<DerivationId, RecoveredGrant> = BTreeMap::new();
    let mut object_kinds: BTreeMap<ObjectId, ResourceKind> = BTreeMap::new();
    for recovered in &committed {
        let grant = &recovered.grant;
        if let Some(kind) = object_kinds.insert(grant.object_id, grant.resource_kind) {
            if kind != grant.resource_kind {
                return Err(RecoveryError::ObjectMismatch {
                    sequence: recovered.commit_sequence,
                });
            }
        }
        if grant.flags.is_root() {
            if grant.parent_id.is_some() {
                return Err(RecoveryError::RootShape {
                    sequence: recovered.commit_sequence,
                });
            }
            if !policy.roots.iter().any(|root| root.grant == *grant) {
                return Err(RecoveryError::RootNotTrusted {
                    sequence: recovered.commit_sequence,
                });
            }
        } else {
            let Some(parent_id) = grant.parent_id else {
                return Err(RecoveryError::RootShape {
                    sequence: recovered.commit_sequence,
                });
            };
            let Some(parent) = graph.get(&parent_id) else {
                return Err(RecoveryError::MissingParent {
                    sequence: recovered.commit_sequence,
                });
            };
            if !parent.grant.rights.contains(DurableRights::GRANT) {
                return Err(RecoveryError::ParentCannotGrant {
                    sequence: recovered.commit_sequence,
                });
            }
            if !parent.grant.rights.contains(grant.rights) {
                return Err(RecoveryError::RightsAmplification {
                    sequence: recovered.commit_sequence,
                });
            }
            if parent.grant.object_id != grant.object_id
                || parent.grant.resource_kind != grant.resource_kind
            {
                return Err(RecoveryError::ObjectMismatch {
                    sequence: recovered.commit_sequence,
                });
            }
        }
        graph.insert(grant.derivation_id, recovered.clone());
    }

    let mut slots: BTreeMap<(SpaceId, u32), (u64, DerivationId)> = BTreeMap::new();
    for recovered in &committed {
        let key = (recovered.grant.target.space, recovered.grant.target.slot);
        if let Some((old_generation, old_derivation)) = slots.get(&key).copied() {
            if old_generation == u64::MAX || recovered.grant.target.generation <= old_generation {
                return Err(RecoveryError::SlotGeneration {
                    sequence: recovered.commit_sequence,
                });
            }
            if !is_tombstoned_before(
                old_derivation,
                recovered.commit_sequence,
                &graph,
                &tombstone_sequence,
            ) {
                return Err(RecoveryError::SlotStillLive {
                    sequence: recovered.commit_sequence,
                });
            }
        }
        slots.insert(
            key,
            (
                recovered.grant.target.generation,
                recovered.grant.derivation_id,
            ),
        );
    }

    let grants = committed
        .into_iter()
        .filter(|grant| !is_tombstoned(grant.grant.derivation_id, &graph, &tombstone_sequence))
        .collect();
    let tombstones = tombstone_sequence.keys().copied().collect();
    Ok(RecoveredStore {
        store_id: policy.store_id,
        id_high_water: high_water,
        grants,
        tombstones,
        last_sequence: previous_sequence,
        last_crc32c: previous_crc,
    })
}

fn ids_reserved_for_grant(grant: &GrantRecord, tx: TransactionId, high_water: u128) -> bool {
    id_reserved(tx.get(), high_water)
        && id_reserved(grant.derivation_id.get(), high_water)
        && grant
            .parent_id
            .map(|parent| id_reserved(parent.get(), high_water))
            .unwrap_or(true)
        && id_reserved(grant.object_id.get(), high_water)
        && id_reserved(grant.target.space.get(), high_water)
}

const fn id_reserved(id: u128, high_water: u128) -> bool {
    id != 0 && id < high_water
}

fn claim_id_class(
    classes: &mut BTreeMap<u128, IdClass>,
    id: u128,
    class: IdClass,
    sequence: u64,
) -> Result<(), RecoveryError> {
    if classes.get(&id).is_some_and(|existing| *existing != class) {
        return Err(RecoveryError::IdClassCollision { sequence });
    }
    classes.insert(id, class);
    Ok(())
}

fn is_tombstoned_before(
    mut derivation: DerivationId,
    before: u64,
    graph: &BTreeMap<DerivationId, RecoveredGrant>,
    tombstones: &BTreeMap<DerivationId, u64>,
) -> bool {
    loop {
        if tombstones
            .get(&derivation)
            .is_some_and(|sequence| *sequence < before)
        {
            return true;
        }
        match graph.get(&derivation).and_then(|node| node.grant.parent_id) {
            Some(parent) => derivation = parent,
            None => return false,
        }
    }
}

fn is_tombstoned(
    mut derivation: DerivationId,
    graph: &BTreeMap<DerivationId, RecoveredGrant>,
    tombstones: &BTreeMap<DerivationId, u64>,
) -> bool {
    loop {
        if tombstones.contains_key(&derivation) {
            return true;
        }
        match graph.get(&derivation).and_then(|node| node.grant.parent_id) {
            Some(parent) => derivation = parent,
            None => return false,
        }
    }
}

fn expected_chunk_len(byte_len: usize, index: u32, count: u32) -> usize {
    if index + 1 < count {
        CHUNK_DATA_SIZE
    } else {
        byte_len - CHUNK_DATA_SIZE * index as usize
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Crc32cDigest {
    state: u32,
}

impl Crc32cDigest {
    pub(crate) const fn new() -> Self {
        Self { state: !0 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state ^= *byte as u32;
            for _ in 0..8 {
                let mask = 0u32.wrapping_sub(self.state & 1);
                self.state = (self.state >> 1) ^ (0x82f6_3b78 & mask);
            }
        }
    }

    pub(crate) const fn finish(self) -> u32 {
        !self.state
    }
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut digest = Crc32cDigest::new();
    digest.update(bytes);
    digest.finish()
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn put_u128(out: &mut [u8], at: usize, value: u128) {
    out[at..at + 16].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("fixed record field"))
}
fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed record field"))
}
fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed record field"))
}
fn get_u128(bytes: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(bytes[at..at + 16].try_into().expect("fixed record field"))
}
