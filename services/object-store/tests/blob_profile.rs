use vibeos_blob_format::{verify_proof, BlobError, BlobView, HEADER_SIZE, LEAF_SIZE};
use vibeos_object_store::{
    encode_blob_object, encode_object_transaction, journal_object_kind, recover,
    verify_blob_object, verify_blob_object_chunk, BlobStoreError, ObjectId, RecordBody,
    RecordChain, RecoveryPolicy, StoreError, StoreId, TransactionId,
};

fn kind(value: u32) -> vibeos_object_store::ObjectKind {
    journal_object_kind(value).unwrap()
}

#[test]
fn journal_profile_round_trips_verified_content() {
    let content: Vec<u8> = (0..LEAF_SIZE * 2 + 31).map(|index| index as u8).collect();
    let encoded = encode_blob_object(kind(0x424c_4f42), &content).unwrap();
    let verified = verify_blob_object(kind(0x424c_4f42), &encoded).unwrap();
    assert_eq!(verified.bytes, content);
    assert_eq!(verified.descriptor.object_kind, 0x424c_4f42);
    assert_eq!(verified.descriptor.byte_len, content.len() as u64);
}

#[test]
fn durable_kind_is_bound_independently_of_inner_descriptor() {
    let encoded = encode_blob_object(kind(7), b"same bytes").unwrap();
    assert_eq!(
        verify_blob_object(kind(8), &encoded),
        Err(BlobStoreError::ObjectKindMismatch)
    );
}

#[test]
fn chunk_read_returns_an_independently_verifiable_proof() {
    let content = vec![0x6d; LEAF_SIZE * 3 + 7];
    let encoded = encode_blob_object(kind(9), &content).unwrap();
    let chunk = verify_blob_object_chunk(kind(9), &encoded, 2).unwrap();
    assert_eq!(chunk.bytes, vec![0x6d; LEAF_SIZE]);
    verify_proof(chunk.descriptor, &chunk.bytes, &chunk.proof).unwrap();

    let tail = verify_blob_object_chunk(kind(9), &encoded, 3).unwrap();
    assert_eq!(tail.bytes, vec![0x6d; 7]);
    verify_proof(tail.descriptor, &tail.bytes, &tail.proof).unwrap();
}

#[test]
fn full_read_rejects_content_corruption_even_when_header_still_parses() {
    let mut encoded = encode_blob_object(kind(10), &vec![0xa7; LEAF_SIZE + 3]).unwrap();
    encoded[HEADER_SIZE + 4] ^= 1;
    assert!(BlobView::decode(&encoded).is_ok());
    assert_eq!(
        verify_blob_object(kind(10), &encoded),
        Err(BlobStoreError::Format(BlobError::TreeMismatch))
    );
}

#[test]
fn current_journal_limit_is_checked_before_encoding() {
    let content = vec![0u8; vibeos_object_store::MAX_OBJECT_SIZE];
    assert_eq!(
        encode_blob_object(kind(11), &content),
        Err(BlobStoreError::Store(StoreError::ObjectTooLarge))
    );
}

#[test]
fn every_durable_commit_boundary_hides_or_recovers_a_verified_blob() {
    let store_id = StoreId::new(90).unwrap();
    let mut chain = RecordChain::new(store_id);
    let format = chain.append(None, RecordBody::Format).unwrap();
    let high_water = chain
        .append(None, RecordBody::IdHighWater { exclusive_end: 100 })
        .unwrap();
    let content: Vec<u8> = (0..LEAF_SIZE + 107)
        .map(|index| ((index * 29 + 7) % 251) as u8)
        .collect();
    let object_kind = kind(0x424c_4f42);
    let encoded = encode_blob_object(object_kind, &content).unwrap();
    let transaction = encode_object_transaction(
        &mut chain,
        TransactionId::new(10).unwrap(),
        ObjectId::new(11).unwrap(),
        object_kind,
        &encoded,
    )
    .unwrap();

    for boundary in 0..=transaction.records.len() {
        let mut image = vec![format, high_water];
        image.extend_from_slice(&transaction.records[..boundary]);
        let recovered = recover(&image, RecoveryPolicy { store_id }).unwrap();
        if boundary == transaction.records.len() {
            assert_eq!(recovered.objects.len(), 1);
            let blob = verify_blob_object(
                recovered.objects[0].object_kind,
                &recovered.objects[0].bytes,
            )
            .unwrap();
            assert_eq!(blob.bytes, content);
        } else {
            assert!(recovered.objects.is_empty());
        }
    }
}
