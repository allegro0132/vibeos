//! Object-store compatibility view over the canonical durable journal.

use alloc::vec::Vec;

use vibeos_durable_format::preflight_recovery;
pub use vibeos_durable_format::{
    encode_object_transaction, preview_external_object_transaction, preview_object_transaction,
    ChainCheckpoint, DecodeError,
    DecodeStatus, DecodedRecord, EncodeError, EncodedObjectTransaction, LogRecord as StoreRecord,
    ObjectChunk, ObjectCommit, ObjectId, ObjectKind, ObjectMetadata, RecordBody, RecordChain,
    RecoveredObject, RecoveryError, StoreId, TransactionId, CHUNK_DATA_SIZE, CRC_OFFSET,
    FORMAT_VERSION, HEADER_LEN, MAX_EXTERNAL_OBJECT_SIZE, MAX_OBJECT_CHUNKS, MAX_OBJECT_SIZE,
    PAYLOAD_CAPACITY,
    PAYLOAD_OFFSET, RECORD_SIZE, SEAL_OFFSET,
};

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
    Ok(RecoveredStore {
        store_id: preflight.store_id(),
        id_high_water: preflight.id_high_water(),
        last_sequence: preflight.last_sequence(),
        last_crc32c: preflight.last_crc32c(),
        objects: preflight.into_objects(),
    })
}
