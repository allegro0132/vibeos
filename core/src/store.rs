//! Capability-addressed object transactions over the unified durable journal.
//!
//! Kinds 1--8 share one canonical decoder, sequence/CRC chain, high-water mark,
//! numeric ID namespace, and transaction namespace with durable authority.
//! This module deliberately exposes no path namespace and no ambient
//! `ObjectId -> object` lookup. Recovery produces inert object records; the live
//! kernel publishes and resolves them only through capabilities.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::durable::{
    crc32c, Crc32cDigest, DerivationId, GrantRecord, ObjectId, StoreId, TransactionId,
};
pub use crate::durable::{
    ChainCheckpoint, DecodeError, DecodeStatus, DecodedRecord, EncodeError,
    LogRecord as StoreRecord, ObjectChunk, ObjectCommit, ObjectKind, ObjectMetadata, RecordBody,
    RecordChain, CHUNK_DATA_SIZE, CRC_OFFSET, FORMAT_VERSION, HEADER_LEN, MAX_OBJECT_CHUNKS,
    MAX_OBJECT_SIZE, PAYLOAD_CAPACITY, PAYLOAD_OFFSET, RECORD_SIZE, SEAL_OFFSET,
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
/// after the caller has durably written the records; I/O failure leaves the
/// original chain untouched and permits retrying the exact logical bytes in a
/// later physical sector range.
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
pub struct RecoveredObject {
    pub object_id: ObjectId,
    pub object_kind: ObjectKind,
    pub bytes: Vec<u8>,
    pub transaction_id: TransactionId,
    pub prepare_sequence: u64,
    pub commit_sequence: u64,
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
    DuplicateObject { sequence: u64 },
    DuplicateDerivation { sequence: u64 },
    AuthorityCommitMismatch { sequence: u64 },
    ChunkWithoutPrepare { sequence: u64 },
    ObjectMismatch { sequence: u64 },
    UnexpectedChunkIndex { sequence: u64 },
    ChunkLength { sequence: u64 },
    CommitWithoutPrepare { sequence: u64 },
    MissingChunks { sequence: u64 },
    CommitMismatch { sequence: u64 },
    ContentCrcMismatch { sequence: u64 },
}

struct PreparedObject {
    metadata: ObjectMetadata,
    sequence: u64,
    crc32c: u32,
    next_chunk: u32,
    first_chunk_sequence: u64,
    chunk_digest: Crc32cDigest,
    bytes: Vec<u8>,
}

struct PreparedGrant {
    derivation_id: DerivationId,
    sequence: u64,
    crc32c: u32,
}

enum TransactionState {
    ObjectPrepared(PreparedObject),
    GrantPrepared(PreparedGrant),
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdClass {
    Object,
    Derivation,
    Space,
    Transaction,
}

/// Recover fully committed objects while validating every interleaved durable
/// authority record against the same envelope, high-water mark, ID classes,
/// and transaction namespace. Incomplete object prepares consume identity but
/// publish nothing. M4.3 remains responsible for root-policy and authority
/// graph restoration; this view performs the record-level checks needed to
/// prevent an authority record from being skipped as opaque bytes.
pub fn recover(
    sectors: &[[u8; RECORD_SIZE]],
    policy: RecoveryPolicy,
) -> Result<RecoveredStore, RecoveryError> {
    // Decode-only preflight preserves the fail-closed rule that any sealed bad
    // sector rejects the whole journal, without retaining per-chunk Vecs.
    for (sector, bytes) in sectors.iter().enumerate() {
        match StoreRecord::decode(bytes) {
            Ok(DecodeStatus::Empty | DecodeStatus::Torn | DecodeStatus::Valid(_)) => {}
            Err(source) => return Err(RecoveryError::SealedRecord { sector, source }),
        }
    }

    let mut previous_sequence = 0u64;
    let mut previous_crc32c = 0u32;
    let mut valid_index = 0usize;
    for (sector, bytes) in sectors.iter().enumerate() {
        let decoded = match StoreRecord::decode(bytes) {
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
            || record.previous_crc32c != previous_crc32c
        {
            return Err(RecoveryError::BrokenSequence { sector });
        }
        if valid_index != 0 && matches!(record.body, RecordBody::Format) {
            return Err(RecoveryError::DuplicateFormat);
        }
        previous_sequence = record.sequence;
        previous_crc32c = decoded.crc32c;
        valid_index += 1;
    }
    if valid_index == 0 {
        return Err(RecoveryError::MissingFormat);
    }

    let mut high_water = 0u128;
    let mut id_classes = BTreeMap::new();
    let mut transactions = BTreeMap::new();
    let mut seen_objects = BTreeSet::new();
    let mut seen_derivations = BTreeSet::new();
    let mut tombstoned_derivations = BTreeSet::new();
    let mut objects = Vec::new();

    // Decode a third time and drop each record at the end of its iteration.
    // ObjectChunk's owned Vec is therefore one <=360-byte temporary, never a
    // journal-sized retained collection. The only growing content allocation
    // is the assembled object state below.
    for bytes in sectors {
        let decoded = match StoreRecord::decode(bytes) {
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
                validate_grant_ids(grant, tx, high_water, sequence, &mut id_classes)?;
                if transactions.contains_key(&tx) {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if tombstoned_derivations.contains(&grant.derivation_id)
                    || !seen_derivations.insert(grant.derivation_id)
                {
                    return Err(RecoveryError::DuplicateDerivation { sequence });
                }
                transactions.insert(
                    tx,
                    TransactionState::GrantPrepared(PreparedGrant {
                        derivation_id: grant.derivation_id,
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
                validate_tx_and_derivation(
                    tx,
                    *derivation_id,
                    high_water,
                    sequence,
                    &mut id_classes,
                )?;
                match transactions.remove(&tx) {
                    Some(TransactionState::GrantPrepared(prepared)) => {
                        if prepared.sequence != *prepare_sequence
                            || prepared.crc32c != *prepare_crc32c
                            || prepared.derivation_id != *derivation_id
                        {
                            return Err(RecoveryError::AuthorityCommitMismatch { sequence });
                        }
                        transactions.insert(tx, TransactionState::Finished);
                    }
                    Some(_) => return Err(RecoveryError::DuplicateTransaction { sequence }),
                    None => {
                        if !seen_derivations.insert(*derivation_id) {
                            return Err(RecoveryError::DuplicateDerivation { sequence });
                        }
                        transactions.insert(tx, TransactionState::Finished);
                    }
                }
            }
            RecordBody::RevokeTombstone { derivation_id } => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                validate_tx_and_derivation(
                    tx,
                    *derivation_id,
                    high_water,
                    sequence,
                    &mut id_classes,
                )?;
                if transactions
                    .insert(tx, TransactionState::Finished)
                    .is_some()
                {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                tombstoned_derivations.insert(*derivation_id);
            }
            RecordBody::ObjectPrepare(metadata) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                validate_tx_and_object(
                    tx,
                    metadata.object_id,
                    high_water,
                    sequence,
                    &mut id_classes,
                )?;
                if transactions.contains_key(&tx) {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                }
                if !seen_objects.insert(metadata.object_id) {
                    return Err(RecoveryError::DuplicateObject { sequence });
                }
                transactions.insert(
                    tx,
                    TransactionState::ObjectPrepared(PreparedObject {
                        metadata: metadata.clone(),
                        sequence,
                        crc32c: decoded.crc32c,
                        next_chunk: 0,
                        first_chunk_sequence: 0,
                        chunk_digest: Crc32cDigest::new(),
                        // Never reserve the attacker-controlled declared size.
                        // Allocation grows only with validated physical chunks.
                        bytes: Vec::new(),
                    }),
                );
            }
            RecordBody::ObjectChunk(chunk) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                validate_tx_and_object(tx, chunk.object_id, high_water, sequence, &mut id_classes)?;
                let Some(state) = transactions.get_mut(&tx) else {
                    return Err(RecoveryError::ChunkWithoutPrepare { sequence });
                };
                let TransactionState::ObjectPrepared(prepared) = state else {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                };
                if prepared.metadata.object_id != chunk.object_id {
                    return Err(RecoveryError::ObjectMismatch { sequence });
                }
                if chunk.chunk_index != prepared.next_chunk
                    || prepared.next_chunk >= prepared.metadata.chunk_count
                {
                    return Err(RecoveryError::UnexpectedChunkIndex { sequence });
                }
                let expected_len = expected_chunk_len(
                    prepared.metadata.byte_len as usize,
                    prepared.next_chunk,
                    prepared.metadata.chunk_count,
                );
                if chunk.data.len() != expected_len {
                    return Err(RecoveryError::ChunkLength { sequence });
                }
                if prepared.next_chunk == 0 {
                    prepared.first_chunk_sequence = sequence;
                }
                prepared.bytes.extend_from_slice(&chunk.data);
                prepared.chunk_digest.update(&decoded.crc32c.to_le_bytes());
                prepared.next_chunk += 1;
            }
            RecordBody::ObjectCommit(commit) => {
                let tx = decoded
                    .record
                    .transaction_id
                    .expect("decoder requires transaction");
                validate_tx_and_object(
                    tx,
                    commit.object_id,
                    high_water,
                    sequence,
                    &mut id_classes,
                )?;
                // Move, rather than clone, the accumulated content out of the
                // transaction map. Peak object-byte storage therefore remains
                // one decoded journal copy plus one assembled buffer; commit
                // adds no third full-size allocation.
                let Some(state) = transactions.remove(&tx) else {
                    return Err(RecoveryError::CommitWithoutPrepare { sequence });
                };
                let TransactionState::ObjectPrepared(prepared) = state else {
                    return Err(RecoveryError::DuplicateTransaction { sequence });
                };
                if prepared.metadata.object_id != commit.object_id {
                    return Err(RecoveryError::ObjectMismatch { sequence });
                }
                if prepared.next_chunk != prepared.metadata.chunk_count {
                    return Err(RecoveryError::MissingChunks { sequence });
                }
                if commit.prepare_sequence != prepared.sequence
                    || commit.prepare_crc32c != prepared.crc32c
                    || commit.chunk_count != prepared.metadata.chunk_count
                    || commit.first_chunk_sequence != prepared.first_chunk_sequence
                    || commit.chunks_crc32c != prepared.chunk_digest.finish()
                    || commit.content_crc32c != prepared.metadata.content_crc32c
                {
                    return Err(RecoveryError::CommitMismatch { sequence });
                }
                if prepared.bytes.len() != prepared.metadata.byte_len as usize
                    || crc32c(&prepared.bytes) != prepared.metadata.content_crc32c
                {
                    return Err(RecoveryError::ContentCrcMismatch { sequence });
                }
                objects.push(RecoveredObject {
                    object_id: prepared.metadata.object_id,
                    object_kind: prepared.metadata.object_kind,
                    bytes: prepared.bytes,
                    transaction_id: tx,
                    prepare_sequence: prepared.sequence,
                    commit_sequence: sequence,
                });
                transactions.insert(tx, TransactionState::Finished);
            }
        }
    }

    Ok(RecoveredStore {
        store_id: policy.store_id,
        id_high_water: high_water,
        objects,
        last_sequence: previous_sequence,
        last_crc32c: previous_crc32c,
    })
}

fn validate_grant_ids(
    grant: &GrantRecord,
    tx: TransactionId,
    high_water: u128,
    sequence: u64,
    classes: &mut BTreeMap<u128, IdClass>,
) -> Result<(), RecoveryError> {
    if !id_reserved(tx.get(), high_water)
        || !id_reserved(grant.derivation_id.get(), high_water)
        || grant
            .parent_id
            .is_some_and(|parent| !id_reserved(parent.get(), high_water))
        || !id_reserved(grant.object_id.get(), high_water)
        || !id_reserved(grant.target.space.get(), high_water)
    {
        return Err(RecoveryError::IdNotReserved { sequence });
    }
    claim_id_class(classes, tx.get(), IdClass::Transaction, sequence)?;
    claim_id_class(
        classes,
        grant.derivation_id.get(),
        IdClass::Derivation,
        sequence,
    )?;
    if let Some(parent) = grant.parent_id {
        claim_id_class(classes, parent.get(), IdClass::Derivation, sequence)?;
    }
    claim_id_class(classes, grant.object_id.get(), IdClass::Object, sequence)?;
    claim_id_class(classes, grant.target.space.get(), IdClass::Space, sequence)
}

fn validate_tx_and_derivation(
    tx: TransactionId,
    derivation: DerivationId,
    high_water: u128,
    sequence: u64,
    classes: &mut BTreeMap<u128, IdClass>,
) -> Result<(), RecoveryError> {
    if !id_reserved(tx.get(), high_water) || !id_reserved(derivation.get(), high_water) {
        return Err(RecoveryError::IdNotReserved { sequence });
    }
    claim_id_class(classes, tx.get(), IdClass::Transaction, sequence)?;
    claim_id_class(classes, derivation.get(), IdClass::Derivation, sequence)
}

fn validate_tx_and_object(
    tx: TransactionId,
    object: ObjectId,
    high_water: u128,
    sequence: u64,
    classes: &mut BTreeMap<u128, IdClass>,
) -> Result<(), RecoveryError> {
    if !id_reserved(tx.get(), high_water) || !id_reserved(object.get(), high_water) {
        return Err(RecoveryError::IdNotReserved { sequence });
    }
    claim_id_class(classes, tx.get(), IdClass::Transaction, sequence)?;
    claim_id_class(classes, object.get(), IdClass::Object, sequence)
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

fn expected_chunk_len(byte_len: usize, index: u32, count: u32) -> usize {
    if index + 1 < count {
        CHUNK_DATA_SIZE
    } else {
        byte_len - CHUNK_DATA_SIZE * index as usize
    }
}
