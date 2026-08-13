use vibeos_blob_format::{
    encode_blob, encoded_len, sha256, verify_proof, BlobError, BlobView, HEADER_SIZE, LEAF_SIZE,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn sha256_matches_standard_vectors_and_block_boundaries() {
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(&vec![0x5a; 1000])),
        "8fe15844cfeedd35f5dc30a9fa5ed38afd849dbe4f8dcae5642d934be0afb13d"
    );
}

#[test]
fn empty_and_multileaf_blobs_round_trip() {
    for bytes in [
        vec![],
        vec![7],
        vec![9; LEAF_SIZE],
        vec![3; LEAF_SIZE * 2 + 17],
    ] {
        let encoded = encode_blob(0x424c_4f42, &bytes).unwrap();
        let blob = BlobView::decode(&encoded).unwrap();
        assert_eq!(blob.data(), bytes);
        assert_eq!(blob.descriptor().byte_len, bytes.len() as u64);
        blob.verify_all().unwrap();
        for index in 0..blob.descriptor().leaf_count {
            blob.verify_chunk(index).unwrap();
        }
    }
}

#[test]
fn proof_is_bound_to_kind_index_length_and_content() {
    let bytes: Vec<u8> = (0..LEAF_SIZE * 3 + 19).map(|index| index as u8).collect();
    let encoded = encode_blob(7, &bytes).unwrap();
    let blob = BlobView::decode(&encoded).unwrap();
    let proof = blob.proof(2).unwrap();
    let chunk = blob.chunk(2).unwrap();
    verify_proof(blob.descriptor(), chunk, &proof).unwrap();

    let mut wrong = chunk.to_vec();
    wrong[0] ^= 1;
    assert_eq!(
        verify_proof(blob.descriptor(), &wrong, &proof),
        Err(BlobError::InvalidProof)
    );
    let mut descriptor = blob.descriptor();
    descriptor.object_kind += 1;
    assert_eq!(
        verify_proof(descriptor, chunk, &proof),
        Err(BlobError::InvalidProof)
    );
    assert_eq!(
        verify_proof(blob.descriptor(), &chunk[..chunk.len() - 1], &proof),
        Err(BlobError::WrongChunkLength)
    );
}

#[test]
fn strict_decoder_rejects_header_tree_data_and_suffix_mutations() {
    let encoded = encode_blob(11, &vec![0x55; LEAF_SIZE + 9]).unwrap();

    let mut bad = encoded.clone();
    bad[0] ^= 1;
    assert!(matches!(BlobView::decode(&bad), Err(BlobError::BadMagic)));

    let mut bad = encoded.clone();
    bad[20] = 1;
    assert!(matches!(
        BlobView::decode(&bad),
        Err(BlobError::NonCanonical)
    ));

    let mut bad = encoded.clone();
    bad[HEADER_SIZE] ^= 1;
    let blob = BlobView::decode(&bad).unwrap();
    assert_eq!(blob.verify_all(), Err(BlobError::TreeMismatch));

    let mut bad = encoded.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(matches!(
        BlobView::decode(&bad),
        Err(BlobError::RootMismatch)
    ));

    let mut bad = encoded.clone();
    bad.push(0);
    assert!(matches!(
        BlobView::decode(&bad),
        Err(BlobError::NonCanonical)
    ));

    assert!(matches!(
        BlobView::decode(&encoded[..encoded.len() - 1]),
        Err(BlobError::Truncated)
    ));
}

#[test]
fn roots_change_at_all_domain_boundaries() {
    let a = encode_blob(1, b"same").unwrap();
    let b = encode_blob(2, b"same").unwrap();
    assert_ne!(
        BlobView::decode(&a).unwrap().descriptor().root,
        BlobView::decode(&b).unwrap().descriptor().root
    );

    let left = encode_blob(1, &vec![1; LEAF_SIZE + 1]).unwrap();
    let right = encode_blob(1, &vec![1; LEAF_SIZE + 2]).unwrap();
    assert_ne!(
        BlobView::decode(&left).unwrap().descriptor().root,
        BlobView::decode(&right).unwrap().descriptor().root
    );
}

#[test]
fn every_prefix_and_tree_node_mutation_fails_closed() {
    let encoded = encode_blob(0x7465_7374, &vec![0xa5; LEAF_SIZE * 3 + 7]).unwrap();
    for cut in 0..encoded.len() {
        assert!(
            BlobView::decode(&encoded[..cut]).is_err(),
            "accepted prefix {cut}"
        );
    }

    let blob = BlobView::decode(&encoded).unwrap();
    let tree_start = HEADER_SIZE + blob.data().len();
    for node in 0..blob.descriptor().tree_node_count as usize {
        let mut bad = encoded.clone();
        bad[tree_start + node * 32] ^= 1;
        match BlobView::decode(&bad) {
            Ok(view) => assert_eq!(view.verify_all(), Err(BlobError::TreeMismatch)),
            Err(BlobError::RootMismatch) => {}
            Err(error) => panic!("unexpected error for node {node}: {error:?}"),
        }
    }
}

#[test]
fn proofs_cover_empty_partial_full_and_padded_leaves() {
    for len in [
        0,
        1,
        LEAF_SIZE - 1,
        LEAF_SIZE,
        LEAF_SIZE + 1,
        LEAF_SIZE * 5 + 13,
    ] {
        let bytes: Vec<u8> = (0..len).map(|index| index.wrapping_mul(31) as u8).collect();
        let encoded = encode_blob(99, &bytes).unwrap();
        let blob = BlobView::decode(&encoded).unwrap();
        for index in 0..blob.descriptor().leaf_count {
            let proof = blob.proof(index).unwrap();
            assert_eq!(
                proof.siblings.len(),
                blob.descriptor().leaf_count.next_power_of_two().ilog2() as usize
            );
            verify_proof(blob.descriptor(), blob.chunk(index).unwrap(), &proof).unwrap();
        }
        assert_eq!(
            blob.proof(blob.descriptor().leaf_count),
            Err(BlobError::ChunkOutOfRange)
        );
    }
}

#[test]
fn canonical_root_is_a_stable_format_vector() {
    let encoded = encode_blob(0x424c_4f42, b"vibeos").unwrap();
    let root = BlobView::decode(&encoded).unwrap().descriptor().root;
    assert_eq!(
        hex(&root),
        "f1ff81f0ff37bdb402131e37e9ef5c2a456bee4a6baf74dafff3ef70683438be"
    );
}

#[test]
fn encoded_length_preflight_is_exact_across_tree_boundaries() {
    for len in [
        0,
        1,
        LEAF_SIZE,
        LEAF_SIZE + 1,
        LEAF_SIZE * 2,
        LEAF_SIZE * 3 + 1,
        LEAF_SIZE * 8,
    ] {
        assert_eq!(
            encoded_len(len).unwrap(),
            encode_blob(1, &vec![0; len]).unwrap().len()
        );
    }
}
