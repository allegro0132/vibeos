//! Canonical encoding for capability-addressed object transactions.

use alloc::vec::Vec;

use crate::{
    crc32c, Crc32cDigest, DecodeStatus, EncodeError, LogRecord, ObjectChunk, ObjectCommit,
    ObjectId, ObjectKind, ObjectMetadata, RecordBody, RecordChain, TransactionId, CHUNK_DATA_SIZE,
    MAX_OBJECT_SIZE, RECORD_SIZE,
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
        LogRecord::decode(&prepare).expect("freshly encoded prepare must decode")
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
            LogRecord::decode(&chunk).expect("freshly encoded chunk must decode")
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
