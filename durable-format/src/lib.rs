//! Durable capability log format and fail-closed recovery.
//!
//! This module deliberately contains no block-device code. It defines the
//! stable, append-only representation which M4.1--M4.3 can place on durable
//! media, plus the recovery validation which prevents a crash image from
//! amplifying authority.

#![no_std]

extern crate alloc;

mod object;
mod policy;

pub use object::{encode_object_transaction, preview_object_transaction, EncodedObjectTransaction};
pub use policy::{
    partition_tombstones_by_space, select_root_policy_union, RootPolicyPartition,
    TombstonePartition, TombstonePartitionError,
};

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
/// Storage V2 admits larger logical objects than the M4 journal's physical
/// 512-sector log. The chunk count is the logical-stream envelope; the M4
/// backend still enforces its physical sector capacity independently.
pub const MAX_OBJECT_CHUNKS: u32 = 4096;
pub const MAX_OBJECT_SIZE: usize = CHUNK_DATA_SIZE * MAX_OBJECT_CHUNKS as usize;
/// Ceiling for external (content-by-reference) objects. Their bytes live in
/// the Storage V2 content-addressed store; the stream carries only the
/// declared identity, so this matches the CAS blob format's 64 MiB envelope
/// rather than the inline chunk budget above.
pub const MAX_EXTERNAL_OBJECT_SIZE: u64 = 64 * 1024 * 1024;

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
    ObjectExternal {
        object_id: ObjectId,
        object_kind: ObjectKind,
        byte_len: u64,
        merkle_root: [u8; 32],
    },
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
    ZeroExternalRoot,
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
    ZeroExternalRoot,
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
    /// One-record commit of an object whose content lives in the V2
    /// content-addressed store. The record declares the exact identity
    /// (kind, byte length, CAS Merkle root); the storage layer must bind and
    /// verify a blob with that identity before the object confers anything.
    ObjectExternal = 9,
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
            9 => Some(Self::ObjectExternal),
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
            Self::ObjectExternal => 64,
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
            Self::ObjectExternal { .. } => RecordKind::ObjectExternal,
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
            RecordBody::ObjectExternal {
                object_id,
                object_kind,
                byte_len,
                merkle_root,
            } => {
                put_u128(&mut out, PAYLOAD_OFFSET, object_id.get());
                put_u32(&mut out, PAYLOAD_OFFSET + 16, object_kind.get());
                put_u64(&mut out, PAYLOAD_OFFSET + 24, *byte_len);
                out[PAYLOAD_OFFSET + 32..PAYLOAD_OFFSET + 64].copy_from_slice(merkle_root);
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
            | RecordBody::ObjectExternal { .. }
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
        RecordBody::ObjectExternal {
            byte_len,
            merkle_root,
            ..
        } => {
            if *byte_len == 0 || *byte_len > MAX_EXTERNAL_OBJECT_SIZE {
                return Err(EncodeError::ObjectTooLarge);
            }
            if *merkle_root == [0u8; 32] {
                return Err(EncodeError::ZeroExternalRoot);
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
            | RecordBody::ObjectExternal { .. }
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
        RecordKind::ObjectExternal => {
            if get_u32(bytes, PAYLOAD_OFFSET + 20) != 0 {
                return Err(DecodeError::NonZeroReserved);
            }
            let byte_len = get_u64(bytes, PAYLOAD_OFFSET + 24);
            if byte_len == 0 || byte_len > MAX_EXTERNAL_OBJECT_SIZE {
                return Err(DecodeError::ObjectTooLarge);
            }
            let mut merkle_root = [0u8; 32];
            merkle_root.copy_from_slice(&bytes[PAYLOAD_OFFSET + 32..PAYLOAD_OFFSET + 64]);
            if merkle_root == [0u8; 32] {
                return Err(DecodeError::ZeroExternalRoot);
            }
            RecordBody::ObjectExternal {
                object_id: id::<ObjectId>(get_u128(bytes, PAYLOAD_OFFSET))?,
                object_kind: ObjectKind::new(get_u32(bytes, PAYLOAD_OFFSET + 16))
                    .ok_or(DecodeError::ZeroObjectKind)?,
                byte_len,
                merkle_root,
            }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedAuthorityTransaction {
    /// Canonical records in the order they must be written. The caller must
    /// flush the last record before publishing the corresponding live change.
    pub records: Vec<[u8; RECORD_SIZE]>,
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

    /// Verify that appending `record_count` records cannot overflow the stable
    /// sequence space without advancing this chain.
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

/// Preview a high-water reservation without advancing `chain` in place.
pub fn preview_id_high_water(
    chain: &RecordChain,
    exclusive_end: u128,
) -> Result<(EncodedAuthorityTransaction, RecordChain), EncodeError> {
    let mut next = chain.clone();
    let record = next.append(None, RecordBody::IdHighWater { exclusive_end })?;
    Ok((
        EncodedAuthorityTransaction {
            records: alloc::vec![record],
        },
        next,
    ))
}

/// Preview one prepare/commit grant transaction without advancing `chain`.
pub fn preview_grant_transaction(
    chain: &RecordChain,
    transaction_id: TransactionId,
    grant: GrantRecord,
) -> Result<(EncodedAuthorityTransaction, RecordChain), EncodeError> {
    let mut next = chain.clone();
    next.ensure_capacity(2)?;
    let prepare = next.append(
        Some(transaction_id),
        RecordBody::GrantPrepare(grant.clone()),
    )?;
    let DecodeStatus::Valid(decoded) =
        LogRecord::decode(&prepare).expect("a freshly encoded prepare must decode")
    else {
        unreachable!()
    };
    let commit = next.append(
        Some(transaction_id),
        RecordBody::GrantCommit {
            prepare_sequence: decoded.record.sequence,
            prepare_crc32c: decoded.crc32c,
            derivation_id: grant.derivation_id,
        },
    )?;
    Ok((
        EncodedAuthorityTransaction {
            records: alloc::vec![prepare, commit],
        },
        next,
    ))
}

/// Preview a tombstone-first revoke record without advancing `chain`.
pub fn preview_revoke_transaction(
    chain: &RecordChain,
    transaction_id: TransactionId,
    derivation_id: DerivationId,
) -> Result<(EncodedAuthorityTransaction, RecordChain), EncodeError> {
    let mut next = chain.clone();
    let record = next.append(
        Some(transaction_id),
        RecordBody::RevokeTombstone { derivation_id },
    )?;
    Ok((
        EncodedAuthorityTransaction {
            records: alloc::vec![record],
        },
        next,
    ))
}

/// Preview one single-record external object commit without advancing `chain`.
/// The caller must separately make a blob with exactly this (kind, length,
/// Merkle root) durable in the same transaction that publishes these records.
pub fn preview_external_object_transaction(
    chain: &RecordChain,
    transaction_id: TransactionId,
    object_id: ObjectId,
    object_kind: ObjectKind,
    byte_len: u64,
    merkle_root: [u8; 32],
) -> Result<(EncodedAuthorityTransaction, RecordChain), EncodeError> {
    let mut next = chain.clone();
    let record = next.append(
        Some(transaction_id),
        RecordBody::ObjectExternal {
            object_id,
            object_kind,
            byte_len,
            merkle_root,
        },
    )?;
    Ok((
        EncodedAuthorityTransaction {
            records: alloc::vec![record],
        },
        next,
    ))
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
pub struct RecoveredObject {
    pub object_id: ObjectId,
    pub object_kind: ObjectKind,
    /// Inline content. Empty for external objects, whose bytes live in the
    /// content-addressed store under `external_root`.
    pub bytes: Vec<u8>,
    /// Exact logical length: `bytes.len()` for inline objects, the declared
    /// length for external objects.
    pub byte_len: u64,
    /// CAS Merkle root declared by an external commit record; `None` for
    /// inline objects.
    pub external_root: Option<[u8; 32]>,
    pub transaction_id: TransactionId,
    pub prepare_sequence: u64,
    pub commit_sequence: u64,
}

impl RecoveredObject {
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn is_external(&self) -> bool {
        self.external_root.is_some()
    }
}

/// Complete historical state of one durable CSpace slot. `max_generation`
/// remains meaningful when the latest derivation was tombstoned, so a reboot
/// cannot accidentally reuse that generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveredSlot {
    pub space: SpaceId,
    pub slot: u32,
    pub max_generation: u64,
    pub live_derivation: Option<DerivationId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredStore {
    pub store_id: StoreId,
    pub id_high_water: u128,
    pub grants: Vec<RecoveredGrant>,
    pub objects: Vec<RecoveredObject>,
    pub slots: Vec<RecoveredSlot>,
    pub tombstones: Vec<DerivationId>,
    pub last_sequence: u64,
    pub last_crc32c: u32,
}

impl RecoveredStore {
    pub fn chain_checkpoint(&self) -> Result<ChainCheckpoint, RecoveryError> {
        Ok(ChainCheckpoint {
            next_sequence: self
                .last_sequence
                .checked_add(1)
                .ok_or(RecoveryError::SequenceOverflow)?,
            previous_sequence: self.last_sequence,
            previous_crc32c: self.last_crc32c,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootRightsConstraint {
    /// Every selected root must carry these rights.
    pub required: DurableRights,
    /// A selected root may carry no rights outside this mask. Set this equal
    /// to `required` for an exact-rights match.
    pub allowed: DurableRights,
}

impl RootRightsConstraint {
    pub const fn exact(rights: DurableRights) -> Self {
        Self {
            required: rights,
            allowed: rights,
        }
    }

    pub const fn at_most(required: DurableRights, allowed: DurableRights) -> Self {
        Self { required, allowed }
    }
}

/// External trust constraint for selecting one dynamic durable root. On-media
/// ROOT is only a candidate marker; exactly one final live root must satisfy
/// every field below or selection fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootConstraint {
    pub space: SpaceId,
    pub first_slot: u32,
    pub last_slot_inclusive: u32,
    pub rights: RootRightsConstraint,
    pub resource_kind: ResourceKind,
    pub object_kind: ObjectKind,
}

/// A decoded and semantically checked journal which has not yet been allowed
/// to confer authority. It deliberately exposes candidates and committed
/// objects only as inert typed records, never as an ObjectId lookup service.
#[derive(Clone, Debug)]
pub struct RecoveryPreflight {
    store_id: StoreId,
    id_high_water: u128,
    committed: Vec<RecoveredGrant>,
    objects: Vec<RecoveredObject>,
    tombstone_sequence: BTreeMap<DerivationId, u64>,
    /// The transaction that carried each tombstone, retained so a compacted
    /// stream can re-emit the tombstone under its original stable identity.
    tombstone_transactions: BTreeMap<DerivationId, TransactionId>,
    graph: BTreeMap<DerivationId, RecoveredGrant>,
    slots: Vec<RecoveredSlot>,
    last_sequence: u64,
    last_crc32c: u32,
}

impl RecoveryPreflight {
    pub const fn store_id(&self) -> StoreId {
        self.store_id
    }

    pub const fn id_high_water(&self) -> u128 {
        self.id_high_water
    }

    pub fn committed_objects(&self) -> &[RecoveredObject] {
        &self.objects
    }

    pub fn committed_grants(&self) -> &[RecoveredGrant] {
        &self.committed
    }

    pub fn slots(&self) -> &[RecoveredSlot] {
        &self.slots
    }

    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub const fn last_crc32c(&self) -> u32 {
        self.last_crc32c
    }

    pub fn chain_checkpoint(&self) -> Result<ChainCheckpoint, RecoveryError> {
        Ok(ChainCheckpoint {
            next_sequence: self
                .last_sequence
                .checked_add(1)
                .ok_or(RecoveryError::SequenceOverflow)?,
            previous_sequence: self.last_sequence,
            previous_crc32c: self.last_crc32c,
        })
    }

    /// Select exactly one live root for every external constraint. Multiple
    /// matching roots are ambiguous even if their commit order differs.
    pub fn select_roots(
        &self,
        constraints: &[RootConstraint],
    ) -> Result<Vec<RootPolicy>, RecoveryError> {
        let mut selected = Vec::with_capacity(constraints.len());
        let mut selected_ids = BTreeSet::new();
        for constraint in constraints {
            if constraint.first_slot > constraint.last_slot_inclusive
                || !constraint
                    .rights
                    .allowed
                    .contains(constraint.rights.required)
            {
                return Err(RecoveryError::InvalidRootConstraint);
            }
            let mut match_ = None;
            for candidate in &self.committed {
                let grant = &candidate.grant;
                if !grant.flags.is_root()
                    || grant.parent_id.is_some()
                    || is_tombstoned(grant.derivation_id, &self.graph, &self.tombstone_sequence)
                    || grant.target.space != constraint.space
                    || grant.target.slot < constraint.first_slot
                    || grant.target.slot > constraint.last_slot_inclusive
                    || grant.resource_kind != constraint.resource_kind
                    || !grant.rights.contains(constraint.rights.required)
                    || !constraint.rights.allowed.contains(grant.rights)
                {
                    continue;
                }
                let object_matches = self.objects.iter().any(|object| {
                    object.object_id == grant.object_id
                        && object.object_kind == constraint.object_kind
                        && object.commit_sequence < candidate.commit_sequence
                });
                if !object_matches {
                    continue;
                }
                if match_.replace(candidate).is_some() {
                    return Err(RecoveryError::AmbiguousRootConstraint);
                }
            }
            let Some(candidate) = match_ else {
                return Err(RecoveryError::MissingRootConstraint);
            };
            if !selected_ids.insert(candidate.grant.derivation_id) {
                return Err(RecoveryError::AmbiguousRootConstraint);
            }
            selected.push(RootPolicy {
                grant: candidate.grant.clone(),
            });
        }
        Ok(selected)
    }

    /// Rebuild a minimal record stream whose recovery is equivalent to this
    /// one for every consumer-visible property: the id high-water mark, the
    /// live derivation graph, per-slot generation history (so no retired slot
    /// generation can ever be reissued), and every object still reachable
    /// through a retained grant. Grants whose whole closure is tombstoned are
    /// dropped together with objects referenced only by dropped grants — the
    /// steady-state garbage a replace-style workload accumulates.
    ///
    /// Objects that never received any grant are runtime-transient: nothing
    /// durable can name them after a reboot, but capabilities minted this
    /// boot still resolve them. `drop_ungranted_objects` therefore must be
    /// `false` for any compaction while such capabilities may exist, and may
    /// be `true` only at a boot boundary.
    ///
    /// The compacted stream is fully re-validated here, and its recovered
    /// state is compared against this preflight property by property; any
    /// divergence fails closed with [`RecoveryError::CompactionMismatch`]
    /// and the caller keeps the original stream. Sequence numbers and record
    /// CRCs necessarily differ; no equivalence claim covers them.
    ///
    /// One check this rewrite deliberately relaxes: dropped derivation and
    /// transaction ids are no longer remembered by the stream itself, so a
    /// later writer could re-prepare one without the stream rejecting it.
    /// The id allocator's high-water mark — which is preserved — remains the
    /// authority that prevents such reuse.
    pub fn compact(
        &self,
        drop_ungranted_objects: bool,
    ) -> Result<Vec<[u8; RECORD_SIZE]>, RecoveryError> {
        self.compact_inner(drop_ungranted_objects, &BTreeSet::new())
    }

    /// Compact at a boot boundary while retaining only caller-proved exact
    /// ungranted attachments in addition to objects reachable from retained
    /// grants.
    ///
    /// Each attachment is a complete comparison witness from this preflight,
    /// not an object-ID lookup request. The slice must be strictly ordered by
    /// ObjectId; every value must equal the unique recovered object, be inline,
    /// and have no historical grant reference (including tombstoned grants).
    /// This keeps detached policy evidence without preserving unrelated
    /// orphan objects.
    pub fn compact_with_exact_ungranted(
        &self,
        exact_ungranted: &[RecoveredObject],
    ) -> Result<Vec<[u8; RECORD_SIZE]>, RecoveryError> {
        for attachment in exact_ungranted {
            if attachment.is_external()
                || attachment.byte_len() != attachment.bytes.len() as u64
                || self
                    .committed
                    .iter()
                    .any(|grant| grant.grant.object_id == attachment.object_id)
            {
                return Err(RecoveryError::CompactionMismatch);
            }
        }
        self.compact_with_exact_policy_objects(exact_ungranted)
    }

    /// Boot-boundary compaction retaining an exact set of externally selected
    /// policy objects. Every full record must occur uniquely in this same
    /// preflight and the slice must be strictly ordered. Object identities are
    /// comparison evidence only; the caller remains responsible for proving
    /// the policy association (for example root-relative operator evidence or
    /// the explicitly allowlisted SSH singleton).
    pub fn compact_with_exact_policy_objects(
        &self,
        exact_objects: &[RecoveredObject],
    ) -> Result<Vec<[u8; RECORD_SIZE]>, RecoveryError> {
        let mut retained = BTreeSet::new();
        let mut previous = None;
        for object in exact_objects {
            if previous.is_some_and(|id| id >= object.object_id)
                || self
                    .objects
                    .iter()
                    .filter(|candidate| candidate.object_id == object.object_id)
                    .count()
                    != 1
                || !self.objects.iter().any(|candidate| candidate == object)
                || !retained.insert(object.object_id)
            {
                return Err(RecoveryError::CompactionMismatch);
            }
            previous = Some(object.object_id);
        }
        self.compact_inner(true, &retained)
    }

    fn compact_inner(
        &self,
        drop_ungranted_objects: bool,
        exact_ungranted: &BTreeSet<ObjectId>,
    ) -> Result<Vec<[u8; RECORD_SIZE]>, RecoveryError> {
        // 1. Retained derivations: every live grant, plus each slot's
        // highest-generation holder (alive or dead), plus ancestor closure.
        let mut retained: BTreeSet<DerivationId> = BTreeSet::new();
        for recovered in &self.committed {
            if !is_tombstoned(
                recovered.grant.derivation_id,
                &self.graph,
                &self.tombstone_sequence,
            ) {
                retained.insert(recovered.grant.derivation_id);
            }
        }
        for slot in &self.slots {
            let holder = self
                .committed
                .iter()
                .find(|recovered| {
                    recovered.grant.target.space == slot.space
                        && recovered.grant.target.slot == slot.slot
                        && recovered.grant.target.generation == slot.max_generation
                })
                .ok_or(RecoveryError::CompactionMismatch)?;
            retained.insert(holder.grant.derivation_id);
        }
        let mut closure: Vec<DerivationId> = retained.iter().copied().collect();
        while let Some(derivation) = closure.pop() {
            let Some(node) = self.graph.get(&derivation) else {
                return Err(RecoveryError::CompactionMismatch);
            };
            if let Some(parent) = node.grant.parent_id {
                if retained.insert(parent) {
                    closure.push(parent);
                }
            }
        }

        // 2. Retained objects: referenced by a retained grant, or never
        // granted at all (unless a boot boundary permits dropping those).
        let mut granted_objects: BTreeSet<ObjectId> = BTreeSet::new();
        let mut retained_objects: BTreeSet<ObjectId> = BTreeSet::new();
        for recovered in &self.committed {
            granted_objects.insert(recovered.grant.object_id);
            if retained.contains(&recovered.grant.derivation_id) {
                retained_objects.insert(recovered.grant.object_id);
            }
        }
        if !drop_ungranted_objects {
            for object in &self.objects {
                if !granted_objects.contains(&object.object_id) {
                    retained_objects.insert(object.object_id);
                }
            }
        } else {
            retained_objects.extend(exact_ungranted.iter().copied());
        }

        // 3. Merge retained events in original sequence order so every
        // cross-record proof obligation (objects before the root grants that
        // select them, tombstones before slot reuse) carries over.
        enum Event<'a> {
            Object(&'a RecoveredObject),
            Grant(&'a RecoveredGrant),
            Tombstone(DerivationId, TransactionId),
        }
        let mut events: Vec<(u64, Event<'_>)> = Vec::new();
        events
            .try_reserve_exact(
                self.objects
                    .len()
                    .checked_add(self.committed.len())
                    .and_then(|count| count.checked_add(self.tombstone_sequence.len()))
                    .ok_or(RecoveryError::AllocationFailed)?,
            )
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for object in &self.objects {
            if retained_objects.contains(&object.object_id) {
                events.push((object.commit_sequence, Event::Object(object)));
            }
        }
        for recovered in &self.committed {
            if retained.contains(&recovered.grant.derivation_id) {
                events.push((recovered.commit_sequence, Event::Grant(recovered)));
            }
        }
        for (derivation, sequence) in &self.tombstone_sequence {
            if retained.contains(derivation) {
                let transaction = self
                    .tombstone_transactions
                    .get(derivation)
                    .ok_or(RecoveryError::CompactionMismatch)?;
                events.push((*sequence, Event::Tombstone(*derivation, *transaction)));
            }
        }
        events.sort_by_key(|(sequence, _)| *sequence);

        // 4. Re-encode under a fresh chain.
        let mut chain = RecordChain::new(self.store_id);
        let mut records: Vec<[u8; RECORD_SIZE]> = Vec::new();
        records
            .push(chain.append(None, RecordBody::Format).map_err(|_| {
                RecoveryError::CompactionMismatch
            })?);
        if self.id_high_water != 0 {
            records.push(
                chain
                    .append(
                        None,
                        RecordBody::IdHighWater {
                            exclusive_end: self.id_high_water,
                        },
                    )
                    .map_err(|_| RecoveryError::CompactionMismatch)?,
            );
        }
        for (_, event) in &events {
            match event {
                Event::Object(object) => {
                    let encoded = match object.external_root {
                        Some(merkle_root) => {
                            let (transaction, next) = preview_external_object_transaction(
                                &chain,
                                object.transaction_id,
                                object.object_id,
                                object.object_kind,
                                object.byte_len,
                                merkle_root,
                            )
                            .map_err(|_| RecoveryError::CompactionMismatch)?;
                            chain = next;
                            transaction.records
                        }
                        None => {
                            encode_object_transaction(
                                &mut chain,
                                object.transaction_id,
                                object.object_id,
                                object.object_kind,
                                &object.bytes,
                            )
                            .map_err(|_| RecoveryError::CompactionMismatch)?
                            .records
                        }
                    };
                    records
                        .try_reserve(encoded.len())
                        .map_err(|_| RecoveryError::AllocationFailed)?;
                    records.extend(encoded);
                }
                Event::Grant(recovered) => {
                    let (transaction, next) = preview_grant_transaction(
                        &chain,
                        recovered.transaction_id,
                        recovered.grant.clone(),
                    )
                    .map_err(|_| RecoveryError::CompactionMismatch)?;
                    chain = next;
                    records
                        .try_reserve(transaction.records.len())
                        .map_err(|_| RecoveryError::AllocationFailed)?;
                    records.extend(transaction.records);
                }
                Event::Tombstone(derivation, transaction_id) => {
                    let (transaction, next) =
                        preview_revoke_transaction(&chain, *transaction_id, *derivation)
                            .map_err(|_| RecoveryError::CompactionMismatch)?;
                    chain = next;
                    records
                        .try_reserve(transaction.records.len())
                        .map_err(|_| RecoveryError::AllocationFailed)?;
                    records.extend(transaction.records);
                }
            }
        }

        // 5. Fail closed unless the compacted stream provably recovers the
        // equivalent state.
        let verify = preflight_recovery(&records, self.store_id)?;
        if verify.id_high_water != self.id_high_water {
            return Err(RecoveryError::CompactionMismatch);
        }
        let live = |preflight: &RecoveryPreflight| -> BTreeMap<DerivationId, GrantRecord> {
            preflight
                .committed
                .iter()
                .filter(|recovered| {
                    !is_tombstoned(
                        recovered.grant.derivation_id,
                        &preflight.graph,
                        &preflight.tombstone_sequence,
                    )
                })
                .map(|recovered| (recovered.grant.derivation_id, recovered.grant.clone()))
                .collect()
        };
        if live(&verify) != live(self) {
            return Err(RecoveryError::CompactionMismatch);
        }
        if verify.slots != self.slots {
            return Err(RecoveryError::CompactionMismatch);
        }
        let objects_by_id = |preflight: &RecoveryPreflight| -> BTreeMap<
            ObjectId,
            (ObjectKind, u64, Option<[u8; 32]>, u32),
        > {
            preflight
                .objects
                .iter()
                .map(|object| {
                    (
                        object.object_id,
                        (
                            object.object_kind,
                            object.byte_len,
                            object.external_root,
                            crc32c(&object.bytes),
                        ),
                    )
                })
                .collect()
        };
        let recovered_objects = objects_by_id(&verify);
        let original_objects = objects_by_id(self);
        if recovered_objects.len() != retained_objects.len()
            || recovered_objects.iter().any(|(object_id, identity)| {
                !retained_objects.contains(object_id)
                    || original_objects.get(object_id) != Some(identity)
            })
        {
            return Err(RecoveryError::CompactionMismatch);
        }
        Ok(records)
    }

    /// Apply exact external root policy and publish the unified object,
    /// authority, slot-history, and chain-checkpoint view.
    pub fn finish(self, roots: &[RootPolicy]) -> Result<RecoveredStore, RecoveryError> {
        for recovered in &self.committed {
            let grant = &recovered.grant;
            if grant.flags.is_root()
                && !is_tombstoned(grant.derivation_id, &self.graph, &self.tombstone_sequence)
                && !roots.iter().any(|root| root.grant == *grant)
            {
                return Err(RecoveryError::RootNotTrusted {
                    sequence: recovered.commit_sequence,
                });
            }
        }

        let grants = self
            .committed
            .into_iter()
            .filter(|grant| {
                !is_tombstoned(
                    grant.grant.derivation_id,
                    &self.graph,
                    &self.tombstone_sequence,
                )
            })
            .collect();
        let tombstones = self.tombstone_sequence.keys().copied().collect();
        Ok(RecoveredStore {
            store_id: self.store_id,
            id_high_water: self.id_high_water,
            grants,
            objects: self.objects,
            slots: self.slots,
            tombstones,
            last_sequence: self.last_sequence,
            last_crc32c: self.last_crc32c,
        })
    }

    /// Consume the same semantic pass as an object-only compatibility view.
    /// No root candidate acquires live authority through this operation.
    pub fn into_objects(self) -> Vec<RecoveredObject> {
        self.objects
    }
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
    ObjectIdentityMismatch { sequence: u64 },
    UnexpectedObjectChunkIndex { sequence: u64 },
    MissingObjectChunks { sequence: u64 },
    RootShape { sequence: u64 },
    RootNotTrusted { sequence: u64 },
    MissingParent { sequence: u64 },
    ParentCannotGrant { sequence: u64 },
    RightsAmplification { sequence: u64 },
    ObjectMismatch { sequence: u64 },
    SlotGeneration { sequence: u64 },
    SlotStillLive { sequence: u64 },
    InvalidRootConstraint,
    MissingRootConstraint,
    AmbiguousRootConstraint,
    AllocationFailed,
    /// A compacted rewrite failed its own equivalence proof; the original
    /// stream stays authoritative.
    CompactionMismatch,
    /// A resumable replay builder observed an earlier failure; its retained
    /// state is not a validated prefix of any stream.
    ReplayPoisoned,
}

#[derive(Clone)]
struct PreparedGrant {
    grant: GrantRecord,
    sequence: u64,
    crc32c: u32,
}

#[derive(Clone)]
struct PreparedObject {
    metadata: ObjectMetadata,
    sequence: u64,
    crc32c: u32,
    next_chunk: u32,
    first_chunk_sequence: u64,
    chunk_digest: Crc32cDigest,
    content_digest: Crc32cDigest,
    byte_len: usize,
    bytes: Vec<u8>,
}

#[derive(Clone)]
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

/// Decode and semantically validate one unified object/authority journal.
///
/// Empty and unsealed sectors are skipped. Any *sealed* non-canonical sector,
/// chain break, invalid object transaction, or invalid derivation graph rejects
/// the entire store. The result is inert until exact external root policy is
/// supplied to [`RecoveryPreflight::finish`].
/// Resumable single-owner replay of the unified journal. The stream's
/// appender may retain this builder and validate only newly appended records
/// instead of re-decoding the entire journal on every append. Both passes
/// (chain probe, then semantic replay) run in the same order as
/// [`preflight_recovery`], so `new` + one `append` of the whole stream +
/// `finish` is behaviorally identical to a fresh recovery. Any error poisons
/// the builder: a failed append leaves partially applied state, so every
/// later call fails closed.
#[derive(Clone)]
pub struct PreflightReplay {
    store_id: StoreId,
    poisoned: bool,
    total_sectors: usize,
    valid_records: u64,
    previous_sequence: u64,
    previous_crc: u32,
    high_water: u128,
    id_classes: BTreeMap<u128, IdClass>,
    transactions: BTreeMap<TransactionId, TxState>,
    seen_derivations: BTreeSet<DerivationId>,
    seen_objects: BTreeSet<ObjectId>,
    committed: Vec<RecoveredGrant>,
    committed_objects: Vec<RecoveredObject>,
    tombstone_sequence: BTreeMap<DerivationId, u64>,
    tombstone_transactions: BTreeMap<DerivationId, TransactionId>,
}

impl PreflightReplay {
    pub fn new(store_id: StoreId) -> Self {
        Self {
            store_id,
            poisoned: false,
            total_sectors: 0,
            valid_records: 0,
            previous_sequence: 0,
            previous_crc: 0,
            high_water: 0,
            id_classes: BTreeMap::new(),
            transactions: BTreeMap::new(),
            seen_derivations: BTreeSet::new(),
            seen_objects: BTreeSet::new(),
            committed: Vec::new(),
            committed_objects: Vec::new(),
            tombstone_sequence: BTreeMap::new(),
            tombstone_transactions: BTreeMap::new(),
        }
    }

    pub const fn record_count(&self) -> u64 {
        self.valid_records
    }

    /// Chain checkpoint after every record appended so far. This is the value
    /// an appender compares against a concurrently observed stream tail
    /// before trusting this builder as that stream's validated prefix.
    pub fn chain_checkpoint(&self) -> Result<ChainCheckpoint, RecoveryError> {
        if self.poisoned || self.valid_records == 0 {
            return Err(RecoveryError::ReplayPoisoned);
        }
        Ok(ChainCheckpoint {
            next_sequence: self
                .previous_sequence
                .checked_add(1)
                .ok_or(RecoveryError::SequenceOverflow)?,
            previous_sequence: self.previous_sequence,
            previous_crc32c: self.previous_crc,
        })
    }

    pub fn append(&mut self, sectors: &[[u8; RECORD_SIZE]]) -> Result<(), RecoveryError> {
        if self.poisoned {
            return Err(RecoveryError::ReplayPoisoned);
        }
        let result = self.append_inner(sectors);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_inner(&mut self, sectors: &[[u8; RECORD_SIZE]]) -> Result<(), RecoveryError> {
        // Decode-only chain probe over exactly the appended records, seeded
        // from the retained chain state, mirroring the whole-stream probe.
        #[derive(Clone, Copy)]
        struct ChainProbe {
            sequence: u64,
            previous_sequence: u64,
            previous_crc32c: u32,
            crc32c: u32,
            store_id: StoreId,
            is_format: bool,
        }
        let mut probes: Vec<Option<ChainProbe>> = Vec::new();
        probes
            .try_reserve_exact(sectors.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (sector, bytes) in sectors.iter().enumerate() {
            match LogRecord::decode(bytes) {
                Ok(DecodeStatus::Empty | DecodeStatus::Torn) => probes.push(None),
                Ok(DecodeStatus::Valid(decoded)) => probes.push(Some(ChainProbe {
                    sequence: decoded.record.sequence,
                    previous_sequence: decoded.record.previous_sequence,
                    previous_crc32c: decoded.record.previous_crc32c,
                    crc32c: decoded.crc32c,
                    store_id: decoded.record.store_id,
                    is_format: matches!(decoded.record.body, RecordBody::Format),
                })),
                Err(source) => {
                    return Err(RecoveryError::SealedRecord {
                        sector: self.total_sectors + sector,
                        source,
                    })
                }
            }
        }
        let mut previous_sequence = self.previous_sequence;
        let mut previous_crc = self.previous_crc;
        let mut valid_index = self.valid_records;
        for (sector, entry) in probes.iter().enumerate() {
            let Some(probe) = entry else { continue };
            if valid_index == 0 && (probe.sequence != 1 || !probe.is_format) {
                return Err(RecoveryError::FormatNotFirst);
            }
            if probe.store_id != self.store_id {
                return Err(RecoveryError::WrongStore {
                    sector: self.total_sectors + sector,
                });
            }
            let expected = previous_sequence
                .checked_add(1)
                .ok_or(RecoveryError::SequenceOverflow)?;
            if probe.sequence != expected
                || probe.previous_sequence != previous_sequence
                || probe.previous_crc32c != previous_crc
            {
                return Err(RecoveryError::BrokenSequence {
                    sector: self.total_sectors + sector,
                });
            }
            if valid_index != 0 && probe.is_format {
                return Err(RecoveryError::DuplicateFormat);
            }
            previous_sequence = probe.sequence;
            previous_crc = probe.crc32c;
            valid_index += 1;
        }
        drop(probes);

        // Semantic replay of the appended records against retained state.
        let high_water = &mut self.high_water;
        let id_classes = &mut self.id_classes;
        let transactions = &mut self.transactions;
        let seen_derivations = &mut self.seen_derivations;
        let seen_objects = &mut self.seen_objects;
        let committed = &mut self.committed;
        let committed_objects = &mut self.committed_objects;
        let tombstone_sequence = &mut self.tombstone_sequence;
        let tombstone_transactions = &mut self.tombstone_transactions;
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
                if *exclusive_end <= *high_water {
                    return Err(RecoveryError::NonMonotonicHighWater);
                }
                *high_water = *exclusive_end;
            }
            RecordBody::GrantPrepare(grant) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !ids_reserved_for_grant(grant, tx, *high_water) {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
                    grant.derivation_id.get(),
                    IdClass::Derivation,
                    sequence,
                )?;
                if let Some(parent) = grant.parent_id {
                    claim_id_class(id_classes, parent.get(), IdClass::Derivation, sequence)?;
                }
                claim_id_class(
                    id_classes,
                    grant.object_id.get(),
                    IdClass::Object,
                    sequence,
                )?;
                claim_id_class(
                    id_classes,
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
                if !id_reserved(tx.get(), *high_water)
                    || !id_reserved(derivation_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
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
                if !id_reserved(tx.get(), *high_water)
                    || !id_reserved(derivation_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
                    derivation_id.get(),
                    IdClass::Derivation,
                    sequence,
                )?;
                if transactions.insert(tx, TxState::Finished).is_some() {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if !tombstone_sequence.contains_key(derivation_id) {
                    tombstone_transactions.insert(*derivation_id, tx);
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
                if !id_reserved(tx.get(), *high_water)
                    || !id_reserved(metadata.object_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
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
                        bytes: Vec::new(),
                    }),
                );
            }
            RecordBody::ObjectChunk(chunk) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), *high_water)
                    || !id_reserved(chunk.object_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
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
                if prepared.metadata.object_id != chunk.object_id {
                    return Err(RecoveryError::ObjectIdentityMismatch { sequence });
                }
                if chunk.chunk_index != prepared.next_chunk
                    || prepared.next_chunk >= prepared.metadata.chunk_count
                {
                    return Err(RecoveryError::UnexpectedObjectChunkIndex { sequence });
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
                prepared.bytes.extend_from_slice(&chunk.data);
                prepared.next_chunk += 1;
            }
            RecordBody::ObjectCommit(commit) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), *high_water)
                    || !id_reserved(commit.object_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(
                    id_classes,
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
                if prepared.metadata.object_id != commit.object_id {
                    return Err(RecoveryError::ObjectIdentityMismatch { sequence });
                }
                if prepared.next_chunk != prepared.metadata.chunk_count {
                    return Err(RecoveryError::MissingObjectChunks { sequence });
                }
                if commit.prepare_sequence != prepared.sequence
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
                let byte_len = prepared.bytes.len() as u64;
                committed_objects.push(RecoveredObject {
                    object_id: prepared.metadata.object_id,
                    object_kind: prepared.metadata.object_kind,
                    bytes: prepared.bytes,
                    byte_len,
                    external_root: None,
                    transaction_id: tx,
                    prepare_sequence: prepared.sequence,
                    commit_sequence: sequence,
                });
                transactions.insert(tx, TxState::Finished);
            }
            RecordBody::ObjectExternal {
                object_id,
                object_kind,
                byte_len,
                merkle_root,
            } => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                if !id_reserved(tx.get(), *high_water) || !id_reserved(object_id.get(), *high_water)
                {
                    return Err(RecoveryError::IdNotReserved { sequence });
                }
                claim_id_class(id_classes, tx.get(), IdClass::Transaction, sequence)?;
                claim_id_class(id_classes, object_id.get(), IdClass::Object, sequence)?;
                if transactions.insert(tx, TxState::Finished).is_some() {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if !seen_objects.insert(*object_id) {
                    return Err(RecoveryError::DuplicateObject { sequence });
                }
                committed_objects.push(RecoveredObject {
                    object_id: *object_id,
                    object_kind: *object_kind,
                    bytes: Vec::new(),
                    byte_len: *byte_len,
                    external_root: Some(*merkle_root),
                    transaction_id: tx,
                    prepare_sequence: sequence,
                    commit_sequence: sequence,
                });
            }
        }
        }
        self.previous_sequence = previous_sequence;
        self.previous_crc = previous_crc;
        self.valid_records = valid_index;
        self.total_sectors += sectors.len();
        Ok(())
    }

    /// Validate the cross-record graph and slot invariants over everything
    /// appended so far, exactly like the tail of a whole-stream recovery.
    /// Consumes the builder so a single-shot recovery never holds two copies
    /// of the committed object bytes; a caller that keeps the builder for
    /// the next strict extension finishes a clone instead.
    pub fn finish(self) -> Result<RecoveryPreflight, RecoveryError> {
        if self.poisoned {
            return Err(RecoveryError::ReplayPoisoned);
        }
        if self.valid_records == 0 {
            return Err(RecoveryError::MissingFormat);
        }
    let mut graph: BTreeMap<DerivationId, RecoveredGrant> = BTreeMap::new();
    let mut object_kinds: BTreeMap<ObjectId, ResourceKind> = BTreeMap::new();
    for recovered in &self.committed {
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
    for recovered in &self.committed {
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
                &self.tombstone_sequence,
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

    let slots = slots
        .into_iter()
        .map(
            |((space, slot), (max_generation, derivation))| RecoveredSlot {
                space,
                slot,
                max_generation,
                live_derivation: (!is_tombstoned(derivation, &graph, &self.tombstone_sequence))
                    .then_some(derivation),
            },
        )
        .collect();
        Ok(RecoveryPreflight {
            store_id: self.store_id,
            id_high_water: self.high_water,
            committed: self.committed,
            objects: self.committed_objects,
            tombstone_sequence: self.tombstone_sequence,
            tombstone_transactions: self.tombstone_transactions,
            graph,
            slots,
            last_sequence: self.previous_sequence,
            last_crc32c: self.previous_crc,
        })
    }
}

pub fn preflight_recovery(
    sectors: &[[u8; RECORD_SIZE]],
    store_id: StoreId,
) -> Result<RecoveryPreflight, RecoveryError> {
    let mut replay = PreflightReplay::new(store_id);
    replay.append(sectors)?;
    replay.finish()
}
/// Compatibility wrapper for callers with an already-known exact root policy.
/// It shares the same unified semantic pass as dynamic-root recovery.
pub fn recover(
    sectors: &[[u8; RECORD_SIZE]],
    policy: RecoveryPolicy<'_>,
) -> Result<RecoveredStore, RecoveryError> {
    preflight_recovery(sectors, policy.store_id)?.finish(policy.roots)
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
/// Incremental CRC32C state used by canonical multi-record transactions.
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
