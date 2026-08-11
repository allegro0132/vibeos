//! M4.2 capability-addressed object codec and crash-recovery tests.

use vibeos_durable_format::{
    crc32c, recover as recover_authority, DerivationId, DurableRights, GrantFlags, GrantRecord,
    ObjectId, RecoveryError as AuthorityRecoveryError, RecoveryPolicy as AuthorityRecoveryPolicy,
    ResourceKind, RootPolicy, SlotIdentity, SpaceId, StoreId, TransactionId,
};
use vibeos_core::store::{
    encode_object_transaction, preview_object_transaction, recover, ChainCheckpoint, DecodeError,
    DecodeStatus, EncodeError, ObjectChunk, ObjectCommit, ObjectKind, ObjectMetadata, RecordBody,
    RecordChain, RecoveredStore, RecoveryError, RecoveryPolicy, StoreRecord, CHUNK_DATA_SIZE,
    CRC_OFFSET, MAX_OBJECT_SIZE, PAYLOAD_OFFSET, RECORD_SIZE,
};

const HIGH_WATER: u128 = 10_000;

fn store() -> StoreId {
    StoreId::new(9_000).unwrap()
}

fn object(value: u128) -> ObjectId {
    ObjectId::new(value).unwrap()
}

fn tx(value: u128) -> TransactionId {
    TransactionId::new(value).unwrap()
}

fn kind(value: u32) -> ObjectKind {
    ObjectKind::new(value).unwrap()
}

fn deriv(value: u128) -> DerivationId {
    DerivationId::new(value).unwrap()
}

fn space(value: u128) -> SpaceId {
    SpaceId::new(value).unwrap()
}

fn grant(derivation: u128, object_id: u128, space_id: u128, slot: u32) -> GrantRecord {
    GrantRecord {
        derivation_id: deriv(derivation),
        parent_id: None,
        object_id: object(object_id),
        target: SlotIdentity {
            space: space(space_id),
            slot,
            generation: 0,
        },
        rights: DurableRights::ALL,
        resource_kind: ResourceKind::new(77).unwrap(),
        flags: GrantFlags::ROOT,
    }
}

fn decode(bytes: &[u8; RECORD_SIZE]) -> vibeos_core::store::DecodedRecord {
    let DecodeStatus::Valid(decoded) = StoreRecord::decode(bytes).unwrap() else {
        panic!("fresh record was not valid")
    };
    decoded
}

fn prefix(bytes: &[u8; RECORD_SIZE], cut: usize) -> [u8; RECORD_SIZE] {
    let mut result = [0u8; RECORD_SIZE];
    result[..cut].copy_from_slice(&bytes[..cut]);
    result
}

fn refresh_crc(bytes: &mut [u8; RECORD_SIZE]) {
    let crc = crc32c(&bytes[..CRC_OFFSET]);
    bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    bytes[CRC_OFFSET + 4..CRC_OFFSET + 8].copy_from_slice(&(!crc).to_le_bytes());
}

fn recover_store(sectors: &[[u8; RECORD_SIZE]]) -> Result<RecoveredStore, RecoveryError> {
    recover(sectors, RecoveryPolicy { store_id: store() })
}

fn recover_authority_with(
    sectors: &[[u8; RECORD_SIZE]],
    roots: &[GrantRecord],
) -> Result<vibeos_durable_format::RecoveredStore, AuthorityRecoveryError> {
    let roots: Vec<_> = roots
        .iter()
        .cloned()
        .map(|grant| RootPolicy { grant })
        .collect();
    recover_authority(
        sectors,
        AuthorityRecoveryPolicy {
            store_id: store(),
            roots: &roots,
        },
    )
}

struct TestLog {
    chain: RecordChain,
    sectors: Vec<[u8; RECORD_SIZE]>,
}

impl TestLog {
    fn formatted() -> Self {
        Self::with_high_water(HIGH_WATER)
    }

    fn with_high_water(high_water: u128) -> Self {
        let mut this = Self {
            chain: RecordChain::new(store()),
            sectors: Vec::new(),
        };
        this.push(None, RecordBody::Format);
        this.push(
            None,
            RecordBody::IdHighWater {
                exclusive_end: high_water,
            },
        );
        this
    }

    fn push(
        &mut self,
        transaction_id: Option<TransactionId>,
        body: RecordBody,
    ) -> vibeos_core::store::DecodedRecord {
        let bytes = self.chain.append(transaction_id, body).unwrap();
        let decoded = decode(&bytes);
        self.sectors.push(bytes);
        decoded
    }

    fn object(
        &mut self,
        transaction_id: TransactionId,
        object_id: ObjectId,
        object_kind: ObjectKind,
        bytes: &[u8],
    ) -> Vec<[u8; RECORD_SIZE]> {
        let encoded = encode_object_transaction(
            &mut self.chain,
            transaction_id,
            object_id,
            object_kind,
            bytes,
        )
        .unwrap();
        self.sectors.extend_from_slice(&encoded.records);
        encoded.records
    }
}

#[test]
fn record_kinds_are_canonical_little_endian_and_round_trip() {
    let bytes: Vec<_> = (0..731).map(|index| (index * 17) as u8).collect();
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), &bytes);

    assert_eq!(
        u16::from_le_bytes(log.sectors[0][0x0a..0x0c].try_into().unwrap()),
        1
    );
    assert_eq!(
        u16::from_le_bytes(log.sectors[1][0x0a..0x0c].try_into().unwrap()),
        2
    );
    assert_eq!(
        u16::from_le_bytes(log.sectors[2][0x0a..0x0c].try_into().unwrap()),
        6
    );
    assert_eq!(
        u16::from_le_bytes(log.sectors[3][0x0a..0x0c].try_into().unwrap()),
        7
    );
    assert_eq!(
        u16::from_le_bytes(log.sectors.last().unwrap()[0x0a..0x0c].try_into().unwrap()),
        8
    );
    assert_eq!(&log.sectors[0][..8], b"VIBECAP\0");
    assert_eq!(&log.sectors[0][0x1f0..], b"VIBECAP-COMMIT!!");
    assert_eq!(
        u128::from_le_bytes(
            log.sectors[2][PAYLOAD_OFFSET..PAYLOAD_OFFSET + 16]
                .try_into()
                .unwrap()
        ),
        20
    );

    for sector in &log.sectors {
        let decoded = decode(sector);
        assert_eq!(decoded.record.encode().unwrap(), *sector);
        assert_eq!(
            decoded.crc32c,
            u32::from_le_bytes(sector[CRC_OFFSET..CRC_OFFSET + 4].try_into().unwrap())
        );
    }
}

#[test]
fn chunk_payload_is_fixed_at_360_bytes_and_tail_is_canonical_zero() {
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), b"short");
    let chunk = &log.sectors[3];
    assert_eq!(
        u16::from_le_bytes(chunk[0x0e..0x10].try_into().unwrap()),
        384
    );
    assert_eq!(
        u16::from_le_bytes(
            chunk[PAYLOAD_OFFSET + 20..PAYLOAD_OFFSET + 22]
                .try_into()
                .unwrap()
        ),
        5
    );
    assert_eq!(&chunk[PAYLOAD_OFFSET + 24..PAYLOAD_OFFSET + 29], b"short");
    assert!(
        chunk[PAYLOAD_OFFSET + 29..PAYLOAD_OFFSET + 24 + CHUNK_DATA_SIZE]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn every_prefix_of_every_record_is_empty_or_torn_until_complete() {
    let bytes: Vec<_> = (0..721).map(|index| index as u8).collect();
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), &bytes);

    for sector in &log.sectors {
        for cut in 0..=RECORD_SIZE {
            let image = prefix(sector, cut);
            match (cut, StoreRecord::decode(&image).unwrap()) {
                (0, DecodeStatus::Empty) => {}
                (RECORD_SIZE, DecodeStatus::Valid(_)) => {}
                (_, DecodeStatus::Torn) => {}
                other => panic!("cut {cut} decoded as {other:?}"),
            }
        }
    }
}

#[test]
fn multi_chunk_and_empty_objects_recover_exactly_after_commit() {
    let bytes: Vec<_> = (0..(CHUNK_DATA_SIZE * 2 + 11))
        .map(|index| (index * 29) as u8)
        .collect();
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), &bytes);
    log.object(tx(31), object(21), kind(8), b"");

    let recovered = recover_store(&log.sectors).unwrap();
    assert_eq!(recovered.id_high_water, HIGH_WATER);
    assert_eq!(recovered.objects.len(), 2);
    assert_eq!(recovered.objects[0].object_id, object(20));
    assert_eq!(recovered.objects[0].object_kind, kind(7));
    assert_eq!(recovered.objects[0].bytes, bytes);
    assert_eq!(recovered.objects[1].object_id, object(21));
    assert!(recovered.objects[1].bytes.is_empty());
    assert!(recovered.objects[0].prepare_sequence < recovered.objects[0].commit_sequence);
}

#[test]
fn large_fixed_region_object_recovers_without_commit_time_payload_clone() {
    const BYTE_LEN: usize = 100_000;
    const EXPECTED_CHUNKS: usize = 278;
    let bytes: Vec<_> = (0..BYTE_LEN)
        .map(|index| (index.wrapping_mul(131) ^ (index >> 7)) as u8)
        .collect();
    assert_eq!(bytes.len().div_ceil(CHUNK_DATA_SIZE), EXPECTED_CHUNKS);

    let mut log = TestLog::formatted();
    let transaction = log.object(tx(30), object(20), kind(7), &bytes);
    assert_eq!(transaction.len(), EXPECTED_CHUNKS + 2);
    assert_eq!(log.sectors.len(), EXPECTED_CHUNKS + 4);
    assert!(
        log.sectors.len() < 512,
        "fits the kernel's fixed journal region"
    );

    // Recovery necessarily holds the decoded journal chunks and one assembled
    // object buffer. Commit removes the non-Clone transaction state and moves
    // that buffer into the result, so it cannot create a third 100 KiB copy.
    let recovered = recover_store(&log.sectors).unwrap();
    assert_eq!(recovered.objects.len(), 1);
    assert_eq!(recovered.objects[0].bytes, bytes);
}

#[test]
fn densest_single_object_fills_but_does_not_exceed_512_journal_sectors() {
    const CHUNKS: usize = 508;
    const BYTE_LEN: usize = CHUNKS * CHUNK_DATA_SIZE;
    let bytes: Vec<_> = (0..BYTE_LEN)
        .map(|index| (index.wrapping_mul(17) ^ (index >> 9)) as u8)
        .collect();
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), &bytes);
    assert_eq!(log.sectors.len(), 512);

    let recovered = recover_store(&log.sectors).unwrap();
    assert_eq!(recovered.objects[0].bytes, bytes);
}

#[test]
fn kinds_one_through_eight_share_one_interleaved_journal_and_decoder() {
    let content = b"one canonical journal";
    let root = grant(10, 100, 20, 3);
    let mut log = TestLog::formatted();

    let object_prepare = log.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(100),
            object_kind: kind(7),
            byte_len: content.len() as u64,
            chunk_count: 1,
            content_crc32c: crc32c(content),
        }),
    );
    let grant_prepare = log.push(Some(tx(40)), RecordBody::GrantPrepare(root.clone()));
    let object_chunk = log.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(100),
            chunk_index: 0,
            data: content.to_vec(),
        }),
    );
    log.push(
        Some(tx(40)),
        RecordBody::GrantCommit {
            prepare_sequence: grant_prepare.record.sequence,
            prepare_crc32c: grant_prepare.crc32c,
            derivation_id: root.derivation_id,
        },
    );
    log.push(
        Some(tx(41)),
        RecordBody::RevokeTombstone {
            derivation_id: deriv(11),
        },
    );
    log.push(
        Some(tx(30)),
        RecordBody::ObjectCommit(ObjectCommit {
            object_id: object(100),
            prepare_sequence: object_prepare.record.sequence,
            prepare_crc32c: object_prepare.crc32c,
            chunk_count: 1,
            first_chunk_sequence: object_chunk.record.sequence,
            chunks_crc32c: crc32c(&object_chunk.crc32c.to_le_bytes()),
            content_crc32c: crc32c(content),
        }),
    );

    let kinds: Vec<_> = log
        .sectors
        .iter()
        .map(|sector| u16::from_le_bytes(sector[0x0a..0x0c].try_into().unwrap()))
        .collect();
    assert_eq!(kinds, [1, 2, 6, 3, 7, 4, 5, 8]);
    for sector in &log.sectors {
        let decoded = decode(sector);
        assert_eq!(decoded.record.encode().unwrap(), *sector);
    }

    let objects = recover_store(&log.sectors).unwrap();
    assert_eq!(objects.objects.len(), 1);
    assert_eq!(objects.objects[0].bytes, content);
    let authority = recover_authority_with(&log.sectors, core::slice::from_ref(&root)).unwrap();
    assert_eq!(authority.grants.len(), 1);
    assert_eq!(authority.tombstones, [deriv(11)]);
    assert_eq!(authority.last_sequence, objects.last_sequence);
    assert_eq!(authority.last_crc32c, objects.last_crc32c);
}

fn assert_cross_kind_collision(log: &TestLog) {
    assert!(matches!(
        recover_store(&log.sectors),
        Err(RecoveryError::IdClassCollision { .. })
    ));
    assert!(matches!(
        recover_authority_with(&log.sectors, &[]),
        Err(AuthorityRecoveryError::IdClassCollision { .. })
    ));
}

#[test]
fn object_derivation_space_and_transaction_ids_share_one_numeric_namespace() {
    let mut object_vs_derivation = TestLog::formatted();
    object_vs_derivation.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(50),
            object_kind: kind(7),
            byte_len: 0,
            chunk_count: 0,
            content_crc32c: 0,
        }),
    );
    object_vs_derivation.push(
        Some(tx(31)),
        RecordBody::GrantPrepare(grant(50, 100, 20, 0)),
    );
    assert_cross_kind_collision(&object_vs_derivation);

    let mut object_vs_space = TestLog::formatted();
    object_vs_space.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(50),
            object_kind: kind(7),
            byte_len: 0,
            chunk_count: 0,
            content_crc32c: 0,
        }),
    );
    object_vs_space.push(
        Some(tx(31)),
        RecordBody::GrantPrepare(grant(10, 100, 50, 0)),
    );
    assert_cross_kind_collision(&object_vs_space);

    let mut object_vs_transaction = TestLog::formatted();
    object_vs_transaction.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(50),
            object_kind: kind(7),
            byte_len: 0,
            chunk_count: 0,
            content_crc32c: 0,
        }),
    );
    object_vs_transaction.push(
        Some(tx(50)),
        RecordBody::GrantPrepare(grant(10, 100, 20, 0)),
    );
    assert_cross_kind_collision(&object_vs_transaction);

    let mut derivation_vs_transaction = TestLog::formatted();
    derivation_vs_transaction.push(
        Some(tx(30)),
        RecordBody::GrantPrepare(grant(50, 100, 20, 0)),
    );
    derivation_vs_transaction.push(
        Some(tx(50)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(101),
            object_kind: kind(7),
            byte_len: 0,
            chunk_count: 0,
            content_crc32c: 0,
        }),
    );
    assert_cross_kind_collision(&derivation_vs_transaction);
}

#[test]
fn transaction_ids_cannot_be_reused_across_authority_and_object_kinds() {
    let mut object_then_grant = TestLog::formatted();
    object_then_grant.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(100),
            object_kind: kind(7),
            byte_len: 0,
            chunk_count: 0,
            content_crc32c: 0,
        }),
    );
    object_then_grant.push(
        Some(tx(30)),
        RecordBody::GrantPrepare(grant(10, 100, 20, 0)),
    );
    assert!(matches!(
        recover_store(&object_then_grant.sectors),
        Err(RecoveryError::DuplicateTransaction { .. })
    ));
    assert!(matches!(
        recover_authority_with(&object_then_grant.sectors, &[]),
        Err(AuthorityRecoveryError::DuplicateTransaction { .. })
    ));
}

#[test]
fn every_transaction_prefix_and_flush_boundary_publishes_only_after_commit() {
    let bytes: Vec<_> = (0..721).map(|index| (index * 13) as u8).collect();
    let mut base = TestLog::formatted();
    let base_len = base.sectors.len();
    let records = encode_object_transaction(&mut base.chain, tx(30), object(20), kind(7), &bytes)
        .unwrap()
        .records;

    for boundary in 0..=records.len() {
        let mut image = base.sectors.clone();
        image.extend_from_slice(&records[..boundary]);
        let recovered = recover_store(&image).unwrap();
        assert_eq!(
            recovered.objects.len(),
            usize::from(boundary == records.len())
        );
    }

    for (record_index, record) in records.iter().enumerate() {
        for cut in 0..=RECORD_SIZE {
            let mut image = base.sectors.clone();
            image.extend_from_slice(&records[..record_index]);
            image.push(prefix(record, cut));
            let recovered = recover_store(&image).unwrap();
            let committed = record_index + 1 == records.len() && cut == RECORD_SIZE;
            assert_eq!(
                recovered.objects.len(),
                usize::from(committed),
                "record {record_index}, cut {cut}, base {base_len}"
            );
        }
    }
}

#[test]
fn torn_physical_hole_can_be_retried_with_the_exact_logical_record() {
    let mut log = TestLog::formatted();
    let records =
        encode_object_transaction(&mut log.chain, tx(30), object(20), kind(7), b"retry me")
            .unwrap()
            .records;
    log.sectors.push(prefix(&records[0], 277));
    log.sectors.extend_from_slice(&records);
    let recovered = recover_store(&log.sectors).unwrap();
    assert_eq!(recovered.objects[0].bytes, b"retry me");
}

#[test]
fn high_water_must_be_sealed_before_either_stable_id_is_used() {
    let mut too_low = TestLog::with_high_water(100);
    too_low.object(tx(150), object(151), kind(7), b"no");
    assert!(matches!(
        recover_store(&too_low.sectors),
        Err(RecoveryError::IdNotReserved { .. })
    ));

    let mut reserved = TestLog::with_high_water(100);
    let next_mark = reserved
        .chain
        .append(None, RecordBody::IdHighWater { exclusive_end: 200 })
        .unwrap();
    for cut in 0..=RECORD_SIZE {
        let mut image = reserved.sectors.clone();
        image.push(prefix(&next_mark, cut));
        let recovered = recover_store(&image).unwrap();
        assert_eq!(
            recovered.id_high_water,
            if cut == RECORD_SIZE { 200 } else { 100 }
        );
    }
    reserved.sectors.push(next_mark);
    reserved.object(tx(150), object(151), kind(7), b"yes");
    assert_eq!(recover_store(&reserved.sectors).unwrap().objects.len(), 1);
}

#[test]
fn high_water_is_strictly_monotonic_and_ids_share_one_numeric_namespace() {
    let mut descending = TestLog::with_high_water(100);
    descending.push(None, RecordBody::IdHighWater { exclusive_end: 99 });
    assert_eq!(
        recover_store(&descending.sectors),
        Err(RecoveryError::NonMonotonicHighWater)
    );

    let mut collision = TestLog::formatted();
    collision.object(tx(30), object(30), kind(7), b"same numeric id");
    assert!(matches!(
        recover_store(&collision.sectors),
        Err(RecoveryError::IdClassCollision { .. })
    ));
}

#[test]
fn size_chunk_count_and_sequence_arithmetic_are_bounded() {
    let mut chain = RecordChain::new(store());
    let too_large = vec![0u8; MAX_OBJECT_SIZE + 1];
    assert_eq!(
        encode_object_transaction(&mut chain, tx(30), object(20), kind(7), &too_large),
        Err(EncodeError::ObjectTooLarge)
    );
    assert_eq!(chain.next_sequence(), 1);

    let mut log = TestLog::formatted();
    let mut prepare = log
        .chain
        .append(
            Some(tx(30)),
            RecordBody::ObjectPrepare(ObjectMetadata {
                object_id: object(20),
                object_kind: kind(7),
                byte_len: 1,
                chunk_count: 1,
                content_crc32c: 0,
            }),
        )
        .unwrap();
    prepare[PAYLOAD_OFFSET + 24..PAYLOAD_OFFSET + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    refresh_crc(&mut prepare);
    assert_eq!(
        StoreRecord::decode(&prepare),
        Err(DecodeError::ObjectTooLarge)
    );

    let checkpoint = ChainCheckpoint {
        next_sequence: u64::MAX,
        previous_sequence: u64::MAX - 1,
        previous_crc32c: 1,
    };
    let mut exhausted = RecordChain::from_checkpoint(store(), checkpoint).unwrap();
    assert_eq!(
        exhausted.append(None, RecordBody::IdHighWater { exclusive_end: 2 }),
        Err(EncodeError::SequenceOverflow)
    );
}

#[test]
fn many_maximum_incomplete_prepares_do_not_allocate_their_declared_contents() {
    const PREPARES: usize = 2_048;
    let mut log = TestLog::with_high_water((PREPARES * 2 + 100) as u128);
    for index in 0..PREPARES {
        log.push(
            Some(tx((index * 2 + 10) as u128)),
            RecordBody::ObjectPrepare(ObjectMetadata {
                object_id: object((index * 2 + 11) as u128),
                object_kind: kind(7),
                byte_len: MAX_OBJECT_SIZE as u64,
                chunk_count: (MAX_OBJECT_SIZE / CHUNK_DATA_SIZE) as u32,
                content_crc32c: 0,
            }),
        );
    }

    // The image contains about one MiB of sectors but declares 720 MiB of
    // incomplete content. Recovery must retain only transaction metadata; no
    // object is published and no declared-content capacity is reserved.
    let recovered = recover_store(&log.sectors).unwrap();
    assert!(recovered.objects.is_empty());
    assert_eq!(recovered.last_sequence, PREPARES as u64 + 2);
}

#[test]
fn invalid_checkpoints_and_preview_failure_do_not_advance_the_live_chain() {
    assert_eq!(
        RecordChain::from_checkpoint(
            store(),
            ChainCheckpoint {
                next_sequence: 8,
                previous_sequence: 5,
                previous_crc32c: 1
            }
        )
        .unwrap_err(),
        EncodeError::BadCheckpoint
    );

    let chain = RecordChain::new(store());
    let before = chain.checkpoint();
    let (_, next) =
        preview_object_transaction(&chain, tx(30), object(20), kind(7), b"preview").unwrap();
    assert_eq!(chain.checkpoint(), before);
    assert!(next.next_sequence() > chain.next_sequence());
}

#[test]
fn recovered_checkpoint_resumes_the_exact_sequence_and_crc_chain() {
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), b"first");
    let recovered = recover_store(&log.sectors).unwrap();
    let mut resumed =
        RecordChain::from_checkpoint(store(), recovered.chain_checkpoint().unwrap()).unwrap();
    let next = resumed
        .append(
            None,
            RecordBody::IdHighWater {
                exclusive_end: HIGH_WATER + 1,
            },
        )
        .unwrap();
    log.sectors.push(next);
    assert_eq!(
        recover_store(&log.sectors).unwrap().id_high_water,
        HIGH_WATER + 1
    );
}

#[test]
fn duplicate_transaction_object_chunk_and_commit_are_rejected() {
    let mut duplicate_tx = TestLog::formatted();
    duplicate_tx.object(tx(30), object(20), kind(7), b"one");
    duplicate_tx.object(tx(30), object(21), kind(7), b"two");
    assert!(matches!(
        recover_store(&duplicate_tx.sectors),
        Err(RecoveryError::DuplicateTransaction { .. })
    ));

    let mut duplicate_object = TestLog::formatted();
    duplicate_object.object(tx(30), object(20), kind(7), b"one");
    duplicate_object.object(tx(31), object(20), kind(7), b"two");
    assert!(matches!(
        recover_store(&duplicate_object.sectors),
        Err(RecoveryError::DuplicateObject { .. })
    ));

    let mut duplicate_chunk = TestLog::formatted();
    let data = vec![9u8; 1];
    duplicate_chunk.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(20),
            object_kind: kind(7),
            byte_len: 1,
            chunk_count: 1,
            content_crc32c: crc32c(&data),
        }),
    );
    duplicate_chunk.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data: data.clone(),
        }),
    );
    duplicate_chunk.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data,
        }),
    );
    assert!(matches!(
        recover_store(&duplicate_chunk.sectors),
        Err(RecoveryError::UnexpectedObjectChunkIndex { .. })
    ));
}

#[test]
fn missing_wrong_order_and_wrong_length_chunks_fail_closed() {
    let content = vec![3u8; CHUNK_DATA_SIZE + 1];

    let mut missing = TestLog::formatted();
    let prepare = missing.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(20),
            object_kind: kind(7),
            byte_len: content.len() as u64,
            chunk_count: 2,
            content_crc32c: crc32c(&content),
        }),
    );
    let chunk = missing.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data: content[..CHUNK_DATA_SIZE].to_vec(),
        }),
    );
    missing.push(
        Some(tx(30)),
        RecordBody::ObjectCommit(ObjectCommit {
            object_id: object(20),
            prepare_sequence: prepare.record.sequence,
            prepare_crc32c: prepare.crc32c,
            chunk_count: 2,
            first_chunk_sequence: chunk.record.sequence,
            chunks_crc32c: crc32c(&chunk.crc32c.to_le_bytes()),
            content_crc32c: crc32c(&content),
        }),
    );
    assert!(matches!(
        recover_store(&missing.sectors),
        Err(RecoveryError::MissingObjectChunks { .. })
    ));

    let mut wrong_order = TestLog::formatted();
    wrong_order.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(20),
            object_kind: kind(7),
            byte_len: content.len() as u64,
            chunk_count: 2,
            content_crc32c: crc32c(&content),
        }),
    );
    wrong_order.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 1,
            data: vec![3],
        }),
    );
    assert!(matches!(
        recover_store(&wrong_order.sectors),
        Err(RecoveryError::UnexpectedObjectChunkIndex { .. })
    ));

    let mut wrong_length = TestLog::formatted();
    wrong_length.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(20),
            object_kind: kind(7),
            byte_len: content.len() as u64,
            chunk_count: 2,
            content_crc32c: crc32c(&content),
        }),
    );
    wrong_length.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data: vec![3; CHUNK_DATA_SIZE - 1],
        }),
    );
    assert!(matches!(
        recover_store(&wrong_length.sectors),
        Err(RecoveryError::ObjectChunkLength { .. })
    ));
}

#[test]
fn chunks_and_commits_cannot_be_spliced_between_transactions_or_objects() {
    let mut chunk_splice = TestLog::formatted();
    for (transaction, object_id) in [(tx(30), object(20)), (tx(31), object(21))] {
        chunk_splice.push(
            Some(transaction),
            RecordBody::ObjectPrepare(ObjectMetadata {
                object_id,
                object_kind: kind(7),
                byte_len: 1,
                chunk_count: 1,
                content_crc32c: crc32c(b"x"),
            }),
        );
    }
    chunk_splice.push(
        Some(tx(31)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data: b"x".to_vec(),
        }),
    );
    assert!(matches!(
        recover_store(&chunk_splice.sectors),
        Err(RecoveryError::ObjectIdentityMismatch { .. })
    ));

    let mut orphan = TestLog::formatted();
    orphan.push(
        Some(tx(30)),
        RecordBody::ObjectCommit(ObjectCommit {
            object_id: object(20),
            prepare_sequence: 2,
            prepare_crc32c: 1,
            chunk_count: 0,
            first_chunk_sequence: 0,
            chunks_crc32c: 0,
            content_crc32c: 0,
        }),
    );
    assert!(matches!(
        recover_store(&orphan.sectors),
        Err(RecoveryError::ObjectCommitWithoutPrepare { .. })
    ));
}

#[test]
fn every_commit_binding_field_is_exact() {
    type Mutator = fn(&mut ObjectCommit);
    let variants: &[(Mutator, bool)] = &[
        (|commit| commit.prepare_sequence += 1, false),
        (|commit| commit.prepare_crc32c ^= 1, false),
        (|commit| commit.chunk_count = 1, false),
        (|commit| commit.first_chunk_sequence += 1, false),
        (|commit| commit.chunks_crc32c ^= 1, false),
        (|commit| commit.content_crc32c ^= 1, false),
        (|commit| commit.object_id = object(21), true),
    ];

    for (mutate, object_mismatch) in variants {
        let data = vec![5u8; CHUNK_DATA_SIZE + 1];
        let mut log = TestLog::formatted();
        log.object(tx(30), object(20), kind(7), &data);
        let final_index = log.sectors.len() - 1;
        let mut record = decode(&log.sectors[final_index]).record;
        let RecordBody::ObjectCommit(commit) = &mut record.body else {
            unreachable!()
        };
        mutate(commit);
        log.sectors[final_index] = record.encode().unwrap();
        let error = recover_store(&log.sectors).unwrap_err();
        if *object_mismatch {
            assert!(matches!(
                error,
                RecoveryError::ObjectIdentityMismatch { .. }
            ));
        } else {
            assert!(matches!(error, RecoveryError::ObjectCommitMismatch { .. }));
        }
    }
}

#[test]
fn whole_content_crc_detects_reencoded_but_wrong_payload() {
    let mut log = TestLog::formatted();
    let intended = b"abc";
    let actual = b"abd";
    let prepare = log.push(
        Some(tx(30)),
        RecordBody::ObjectPrepare(ObjectMetadata {
            object_id: object(20),
            object_kind: kind(7),
            byte_len: intended.len() as u64,
            chunk_count: 1,
            content_crc32c: crc32c(intended),
        }),
    );
    let chunk = log.push(
        Some(tx(30)),
        RecordBody::ObjectChunk(ObjectChunk {
            object_id: object(20),
            chunk_index: 0,
            data: actual.to_vec(),
        }),
    );
    log.push(
        Some(tx(30)),
        RecordBody::ObjectCommit(ObjectCommit {
            object_id: object(20),
            prepare_sequence: prepare.record.sequence,
            prepare_crc32c: prepare.crc32c,
            chunk_count: 1,
            first_chunk_sequence: chunk.record.sequence,
            chunks_crc32c: crc32c(&chunk.crc32c.to_le_bytes()),
            content_crc32c: crc32c(intended),
        }),
    );
    assert!(matches!(
        recover_store(&log.sectors),
        Err(RecoveryError::ObjectContentCrcMismatch { .. })
    ));
}

#[test]
fn sealed_crc_reserved_padding_and_kind_corruption_fail_closed() {
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), b"abc");
    let chunk_index = 3;

    let mut bad_crc = log.sectors[chunk_index];
    bad_crc[PAYLOAD_OFFSET + 24] ^= 1;
    assert_eq!(StoreRecord::decode(&bad_crc), Err(DecodeError::BadCrc));

    let mut bad_tail = log.sectors[chunk_index];
    bad_tail[PAYLOAD_OFFSET + 24 + 10] = 1;
    refresh_crc(&mut bad_tail);
    assert_eq!(
        StoreRecord::decode(&bad_tail),
        Err(DecodeError::NonCanonicalPadding)
    );

    let mut bad_reserved = log.sectors[chunk_index];
    bad_reserved[PAYLOAD_OFFSET + 22] = 1;
    refresh_crc(&mut bad_reserved);
    assert_eq!(
        StoreRecord::decode(&bad_reserved),
        Err(DecodeError::NonZeroReserved)
    );

    let mut unknown_kind = log.sectors[chunk_index];
    unknown_kind[0x0a..0x0c].copy_from_slice(&99u16.to_le_bytes());
    refresh_crc(&mut unknown_kind);
    assert_eq!(
        StoreRecord::decode(&unknown_kind),
        Err(DecodeError::UnknownKind)
    );

    let mut bad_complement = log.sectors[chunk_index];
    bad_complement[CRC_OFFSET + 4] ^= 1;
    assert_eq!(
        StoreRecord::decode(&bad_complement),
        Err(DecodeError::BadCrcComplement)
    );

    let mut image = log.sectors.clone();
    image[chunk_index] = bad_crc;
    assert!(matches!(
        recover_store(&image),
        Err(RecoveryError::SealedRecord {
            source: DecodeError::BadCrc,
            ..
        })
    ));
}

#[test]
fn chain_store_and_format_invariants_fail_closed() {
    let mut log = TestLog::formatted();
    log.object(tx(30), object(20), kind(7), b"abc");

    let mut broken = log.sectors.clone();
    let mut record = decode(&broken[2]).record;
    record.previous_crc32c ^= 1;
    broken[2] = record.encode().unwrap();
    assert!(matches!(
        recover_store(&broken),
        Err(RecoveryError::BrokenSequence { .. })
    ));

    assert_eq!(recover_store(&[]), Err(RecoveryError::MissingFormat));
    assert_eq!(
        recover_store(&log.sectors[1..]),
        Err(RecoveryError::FormatNotFirst)
    );

    let mut duplicate_format = TestLog::formatted();
    duplicate_format.push(None, RecordBody::Format);
    assert_eq!(
        recover_store(&duplicate_format.sectors),
        Err(RecoveryError::DuplicateFormat)
    );

    let mut wrong_store = log.sectors.clone();
    let decoded = decode(&wrong_store[2]);
    let mut record = decoded.record;
    record.store_id = StoreId::new(9_001).unwrap();
    wrong_store[2] = record.encode().unwrap();
    assert!(matches!(
        recover_store(&wrong_store),
        Err(RecoveryError::WrongStore { .. })
    ));
}
