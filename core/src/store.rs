//! Capability-addressed object transactions over the unified durable journal.
//!
//! Object and authority recovery deliberately share `durable`'s single
//! semantic pass. This compatibility view publishes only committed immutable
//! object bytes; it never creates an ambient `ObjectId -> object` namespace.

extern crate alloc;

use alloc::vec::Vec;

use crate::durable::{crc32c, preflight_recovery, Crc32cDigest, ObjectId, StoreId, TransactionId};
pub use crate::durable::{
    ChainCheckpoint, DecodeError, DecodeStatus, DecodedRecord, EncodeError,
    LogRecord as StoreRecord, ObjectChunk, ObjectCommit, ObjectKind, ObjectMetadata, RecordBody,
    RecordChain, RecoveredObject, RecoveryError, CHUNK_DATA_SIZE, CRC_OFFSET, FORMAT_VERSION,
    HEADER_LEN, MAX_OBJECT_CHUNKS, MAX_OBJECT_SIZE, PAYLOAD_CAPACITY, PAYLOAD_OFFSET, RECORD_SIZE,
    SEAL_OFFSET,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedObjectTransaction {
    /// Prepare, all chunks in ascending order, then commit. The caller must
    /// flush the final commit before publishing a capability.
    pub records: Vec<[u8; RECORD_SIZE]>,
}

/// Encode one complete object transaction into the canonical journal. A
/// high-water record covering both IDs must already have been flushed;
/// recovery independently enforces that ordering from the shared stream.
pub fn encode_object_transaction(
    chain: &mut RecordChain,
    transaction_id: TransactionId,
    object_id: ObjectId,
    object_kind: ObjectKind,
    bytes: &[u8],
) -> Result<EncodedObjectTransaction, EncodeError> {
    if bytes.len() > MAX_OBJECT_SIZE {
        return Err(EncodeError::ObjectTooLarge);
    }
    let chunk_count = if bytes.is_empty() {
        0
    } else {
        bytes.len().div_ceil(CHUNK_DATA_SIZE) as u32
    };
    let record_count = 2u64 + u64::from(chunk_count);
    chain.ensure_capacity(record_count)?;

    let content_crc32c = crc32c(bytes);
    let prepare = chain.append(
        Some(transaction_id),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id,
            object_kind,
            byte_len: bytes.len() as u64,
            chunk_count,
            content_crc32c,
        }),
    )?;
    let DecodeStatus::Valid(decoded_prepare) =
        StoreRecord::decode(&prepare).expect("freshly encoded prepare must decode")
    else {
        unreachable!()
    };

    let mut records = Vec::with_capacity(record_count as usize);
    records.push(prepare);
    let mut digest = Crc32cDigest::new();
    let mut first_chunk_sequence = 0;
    for (index, data) in bytes.chunks(CHUNK_DATA_SIZE).enumerate() {
        let chunk = chain.append(
            Some(transaction_id),
            RecordBody::ObjectChunk(ObjectChunk {
                object_id,
                chunk_index: index as u32,
                data: data.to_vec(),
            }),
        )?;
        let DecodeStatus::Valid(decoded_chunk) =
            StoreRecord::decode(&chunk).expect("freshly encoded chunk must decode")
        else {
            unreachable!()
        };
        if index == 0 {
            first_chunk_sequence = decoded_chunk.record.sequence;
        }
        digest.update(&decoded_chunk.crc32c.to_le_bytes());
        records.push(chunk);
    }
    records.push(chain.append(
        Some(transaction_id),
        RecordBody::ObjectCommit(ObjectCommit {
            object_id,
            prepare_sequence: decoded_prepare.record.sequence,
            prepare_crc32c: decoded_prepare.crc32c,
            chunk_count,
            first_chunk_sequence,
            chunks_crc32c: digest.finish(),
            content_crc32c,
        }),
    )?);
    Ok(EncodedObjectTransaction { records })
}

/// Build against a cloned chain. The returned next chain is installed only
/// after the caller has durably written the records.
pub fn preview_object_transaction(
    chain: &RecordChain,
    transaction_id: TransactionId,
    object_id: ObjectId,
    object_kind: ObjectKind,
    bytes: &[u8],
) -> Result<(EncodedObjectTransaction, RecordChain), EncodeError> {
    let mut next_chain = chain.clone();
    let transaction = encode_object_transaction(
        &mut next_chain,
        transaction_id,
        object_id,
        object_kind,
        bytes,
    )?;
    Ok((transaction, next_chain))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub store_id: StoreId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredStore {
    pub store_id: StoreId,
    pub id_high_water: u128,
    /// Deliberately a flat recovery result, not an ambient ObjectId lookup API.
    pub objects: Vec<RecoveredObject>,
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

/// Recover the object-only compatibility view through the exact same semantic
/// pass used by durable authority preflight. Root candidates remain inert.
pub fn recover(
    sectors: &[[u8; RECORD_SIZE]],
    policy: RecoveryPolicy,
) -> Result<RecoveredStore, RecoveryError> {
    let preflight = preflight_recovery(sectors, policy.store_id)?;
    let recovered = RecoveredStore {
        store_id: preflight.store_id(),
        id_high_water: preflight.id_high_water(),
        last_sequence: preflight.last_sequence(),
        last_crc32c: preflight.last_crc32c(),
        objects: preflight.into_objects(),
    };
    Ok(recovered)
}
