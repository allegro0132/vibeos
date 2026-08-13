use vibeos_blob_format::{
    BlobDescriptor, BlobError, BlobGeometry, BlobView, HASH_SIZE, HEADER_SIZE, Hash, LEAF_SIZE,
    MAX_BLOB_SIZE, MAX_STREAMING_EMISSIONS_PER_STEP, MerkleTreeSink, STREAMING_FRONTIER_BYTES,
    STREAMING_FRONTIER_SLOTS, StreamingError, StreamingMerkle, encode_blob,
};

const _: () = assert!(STREAMING_FRONTIER_BYTES < LEAF_SIZE);

#[derive(Default)]
struct IndexedSink {
    nodes: Vec<Hash>,
    written: Vec<bool>,
}

impl IndexedSink {
    fn canonical_bytes(&self) -> Vec<u8> {
        assert!(self.written.iter().all(|written| *written));
        self.nodes
            .iter()
            .flat_map(|hash| hash.iter().copied())
            .collect()
    }
}

impl MerkleTreeSink for IndexedSink {
    type Error = &'static str;

    fn write_hash(&mut self, index: u32, hash: Hash) -> Result<(), Self::Error> {
        let index = index as usize;
        if self.nodes.len() <= index {
            self.nodes.resize(index + 1, [0; HASH_SIZE]);
            self.written.resize(index + 1, false);
        }
        if self.written[index] {
            return Err("duplicate canonical node index");
        }
        self.nodes[index] = hash;
        self.written[index] = true;
        Ok(())
    }
}

#[derive(Default)]
struct BoundedEmissionSink {
    canonical: IndexedSink,
    pending: usize,
    maximum_pending: usize,
}

impl BoundedEmissionSink {
    fn drain(&mut self) -> usize {
        let emitted = self.pending;
        self.pending = 0;
        emitted
    }
}

impl MerkleTreeSink for BoundedEmissionSink {
    type Error = &'static str;

    fn write_hash(&mut self, index: u32, hash: Hash) -> Result<(), Self::Error> {
        if self.pending == MAX_STREAMING_EMISSIONS_PER_STEP {
            return Err("one builder step exceeded its emission bound");
        }
        self.canonical.write_hash(index, hash)?;
        self.pending += 1;
        self.maximum_pending = self.maximum_pending.max(self.pending);
        Ok(())
    }
}

fn stream(object_kind: u32, content: &[u8]) -> (BlobDescriptor, [u8; HEADER_SIZE], IndexedSink) {
    let mut builder =
        StreamingMerkle::begin(object_kind, content.len() as u64, IndexedSink::default()).unwrap();
    let mut maximum_retained = 0;
    for (index, chunk) in content.chunks(LEAF_SIZE).enumerate() {
        builder.push_chunk(index as u32, chunk).unwrap();
        maximum_retained = maximum_retained.max(builder.retained_hashes());
    }
    assert!(maximum_retained <= STREAMING_FRONTIER_SLOTS);
    let result = builder.commit().unwrap();
    (result.descriptor, result.header, result.sink)
}

fn stream_stepwise(
    object_kind: u32,
    content: &[u8],
) -> (BlobDescriptor, [u8; HEADER_SIZE], IndexedSink, usize) {
    let mut builder = StreamingMerkle::begin(
        object_kind,
        content.len() as u64,
        BoundedEmissionSink::default(),
    )
    .unwrap();
    for (index, chunk) in content.chunks(LEAF_SIZE).enumerate() {
        builder.push_chunk(index as u32, chunk).unwrap();
        let emitted = builder.sink_mut().drain();
        assert!((1..=MAX_STREAMING_EMISSIONS_PER_STEP).contains(&emitted));
    }
    while builder.padding_remaining().unwrap() != 0 {
        let before = builder.padding_remaining().unwrap();
        builder.pad_next().unwrap();
        assert_eq!(builder.padding_remaining().unwrap(), before - 1);
        let emitted = builder.sink_mut().drain();
        assert!((1..=MAX_STREAMING_EMISSIONS_PER_STEP).contains(&emitted));
    }
    assert_eq!(builder.pad_next(), Err(StreamingError::PaddingComplete));
    let result = builder.finalize().unwrap();
    assert_eq!(result.sink.pending, 0);
    (
        result.descriptor,
        result.header,
        result.sink.canonical,
        result.sink.maximum_pending,
    )
}

#[test]
fn streaming_output_is_byte_identical_at_empty_and_tree_boundaries() {
    for len in [
        0,
        1,
        LEAF_SIZE - 1,
        LEAF_SIZE,
        LEAF_SIZE + 1,
        LEAF_SIZE * 2,
        LEAF_SIZE * 3 + 17,
        LEAF_SIZE * 8,
        LEAF_SIZE * 8 + 1,
    ] {
        let content: Vec<u8> = (0..len)
            .map(|index| index.wrapping_mul(37).wrapping_add(11) as u8)
            .collect();
        let encoded = encode_blob(0x5354_524d, &content).unwrap();
        let canonical = BlobView::decode(&encoded).unwrap();
        let (descriptor, header, sink) = stream(0x5354_524d, &content);
        let (step_descriptor, step_header, step_sink, maximum_emissions) =
            stream_stepwise(0x5354_524d, &content);

        assert_eq!(descriptor, canonical.descriptor(), "length {len}");
        assert_eq!(step_descriptor, descriptor, "length {len}");
        assert_eq!(header.as_slice(), &encoded[..HEADER_SIZE], "length {len}");
        assert_eq!(step_header, header, "length {len}");
        assert_eq!(
            sink.canonical_bytes(),
            encoded[HEADER_SIZE + len..],
            "length {len}"
        );
        assert_eq!(
            step_sink.canonical_bytes(),
            sink.canonical_bytes(),
            "length {len}"
        );
        assert_eq!(
            sink.nodes.len(),
            descriptor.tree_node_count as usize,
            "length {len}"
        );
        assert!(maximum_emissions <= MAX_STREAMING_EMISSIONS_PER_STEP);
    }
}

#[test]
fn maximum_64_mib_synthetic_stream_matches_non_streaming_descriptor() {
    let content: Vec<u8> = (0..MAX_BLOB_SIZE)
        .map(|index| index.wrapping_mul(73).wrapping_add(index >> 13) as u8)
        .collect();
    let expected = BlobDescriptor::from_content(0x4d41_5832, &content).unwrap();
    let expected_header = expected.encode().unwrap();
    let (descriptor, header, sink, maximum_emissions) = stream_stepwise(0x4d41_5832, &content);

    assert_eq!(descriptor, expected);
    assert_eq!(header, expected_header);
    assert_eq!(sink.nodes.len(), expected.tree_node_count as usize);
    assert_eq!(maximum_emissions, MAX_STREAMING_EMISSIONS_PER_STEP);
    assert_eq!(STREAMING_FRONTIER_SLOTS, 15);
}

#[test]
fn public_geometry_canonically_preflights_separate_extents() {
    for len in [
        0,
        1,
        LEAF_SIZE,
        LEAF_SIZE + 1,
        LEAF_SIZE * 3 + 7,
        MAX_BLOB_SIZE,
    ] {
        let geometry = BlobGeometry::for_len(len as u64).unwrap();
        let leaf_count = if len == 0 { 1 } else { len.div_ceil(LEAF_SIZE) };
        let padded = leaf_count.next_power_of_two();
        let nodes = padded * 2 - 1;
        assert_eq!(geometry.exact_len(), len as u64);
        assert_eq!(geometry.leaf_count(), leaf_count as u32);
        assert_eq!(geometry.padded_leaf_count(), padded as u32);
        assert_eq!(geometry.tree_node_count(), nodes as u32);
        assert_eq!(geometry.tree_len(), nodes * HASH_SIZE);
        assert_eq!(geometry.tree_offset(), HEADER_SIZE + len);
        assert_eq!(
            geometry.encoded_len(),
            HEADER_SIZE + len + nodes * HASH_SIZE
        );
        assert_eq!(geometry.height() as u32, padded.ilog2());
    }
    assert_eq!(
        BlobGeometry::for_len(MAX_BLOB_SIZE as u64 + 1),
        Err(BlobError::TooLarge)
    );
}

#[test]
fn ordering_and_length_errors_fail_before_commit() {
    let mut builder =
        StreamingMerkle::begin(7, (LEAF_SIZE + 1) as u64, IndexedSink::default()).unwrap();
    assert_eq!(
        builder.push_chunk(1, &[0; LEAF_SIZE]),
        Err(StreamingError::OutOfOrder {
            expected: 0,
            actual: 1
        })
    );
    assert_eq!(
        builder.push_chunk(0, &[0; LEAF_SIZE - 1]),
        Err(StreamingError::WrongChunkLength {
            index: 0,
            expected: LEAF_SIZE,
            actual: LEAF_SIZE - 1
        })
    );
    assert_eq!(
        builder.push_chunk(0, &[0; LEAF_SIZE + 1]),
        Err(StreamingError::ChunkTooLarge {
            actual: LEAF_SIZE + 1
        })
    );
    builder.push_chunk(0, &[0; LEAF_SIZE]).unwrap();
    assert_eq!(
        builder.push_chunk(1, &[]),
        Err(StreamingError::WrongChunkLength {
            index: 1,
            expected: 1,
            actual: 0
        })
    );
    builder.push_chunk(1, &[0]).unwrap();
    assert_eq!(
        builder.push_chunk(1, &[0]),
        Err(StreamingError::OutOfOrder {
            expected: 2,
            actual: 1
        })
    );
    assert_eq!(
        builder.push_chunk(2, &[0]),
        Err(StreamingError::UnexpectedChunk { index: 2 })
    );

    let incomplete = StreamingMerkle::begin(7, 1, IndexedSink::default()).unwrap();
    assert!(matches!(
        incomplete.commit(),
        Err(StreamingError::Incomplete {
            expected: 1,
            received: 0
        })
    ));
    let mut empty = StreamingMerkle::begin(7, 0, IndexedSink::default()).unwrap();
    assert_eq!(
        empty.push_chunk(0, &[]),
        Err(StreamingError::UnexpectedChunk { index: 0 })
    );

    assert!(matches!(
        StreamingMerkle::begin(0, 0, IndexedSink::default()),
        Err(StreamingError::Blob(BlobError::EmptyObjectKind))
    ));
    assert!(matches!(
        StreamingMerkle::begin(1, MAX_BLOB_SIZE as u64 + 1, IndexedSink::default()),
        Err(StreamingError::Blob(BlobError::TooLarge))
    ));
}

#[test]
fn padding_and_finalize_are_a_strict_resumable_state_machine() {
    let mut incomplete =
        StreamingMerkle::begin(13, (LEAF_SIZE + 1) as u64, IndexedSink::default()).unwrap();
    assert_eq!(
        incomplete.padding_remaining(),
        Err(StreamingError::Incomplete {
            expected: (LEAF_SIZE + 1) as u64,
            received: 0
        })
    );
    assert_eq!(
        incomplete.pad_next(),
        Err(StreamingError::Incomplete {
            expected: (LEAF_SIZE + 1) as u64,
            received: 0
        })
    );

    let content = vec![0xa7; LEAF_SIZE * 2 + 1];
    let mut needs_padding =
        StreamingMerkle::begin(13, content.len() as u64, IndexedSink::default()).unwrap();
    for (index, chunk) in content.chunks(LEAF_SIZE).enumerate() {
        needs_padding.push_chunk(index as u32, chunk).unwrap();
    }
    assert_eq!(needs_padding.padding_remaining(), Ok(1));
    assert!(matches!(
        needs_padding.finalize(),
        Err(StreamingError::PaddingRemaining { remaining: 1 })
    ));

    let mut empty = StreamingMerkle::begin(13, 0, IndexedSink::default()).unwrap();
    assert_eq!(empty.padding_remaining(), Ok(1));
    empty.pad_next().unwrap();
    assert_eq!(empty.padding_remaining(), Ok(0));
    assert_eq!(empty.pad_next(), Err(StreamingError::PaddingComplete));
    empty.finalize().unwrap();
}

struct FailingSink {
    writes: usize,
    fail_at: usize,
}

impl MerkleTreeSink for FailingSink {
    type Error = &'static str;

    fn write_hash(&mut self, _index: u32, _hash: Hash) -> Result<(), Self::Error> {
        if self.writes == self.fail_at {
            return Err("injected sink failure");
        }
        self.writes += 1;
        Ok(())
    }
}

#[test]
fn ambiguous_sink_failure_permanently_poisons_the_builder() {
    let mut builder = StreamingMerkle::begin(
        9,
        (LEAF_SIZE * 2) as u64,
        FailingSink {
            writes: 0,
            fail_at: 2,
        },
    )
    .unwrap();
    builder.push_chunk(0, &[1; LEAF_SIZE]).unwrap();
    assert_eq!(
        builder.push_chunk(1, &[2; LEAF_SIZE]),
        Err(StreamingError::Sink("injected sink failure"))
    );
    assert_eq!(
        builder.push_chunk(1, &[2; LEAF_SIZE]),
        Err(StreamingError::Poisoned)
    );

    let content = vec![3; LEAF_SIZE * 2 + 1];
    let mut padding_builder = StreamingMerkle::begin(
        9,
        content.len() as u64,
        FailingSink {
            writes: 0,
            fail_at: 5,
        },
    )
    .unwrap();
    for (index, chunk) in content.chunks(LEAF_SIZE).enumerate() {
        padding_builder.push_chunk(index as u32, chunk).unwrap();
    }
    assert_eq!(
        padding_builder.pad_next(),
        Err(StreamingError::Sink("injected sink failure"))
    );
    assert_eq!(
        padding_builder.padding_remaining(),
        Err(StreamingError::Poisoned)
    );
    assert!(matches!(
        padding_builder.finalize(),
        Err(StreamingError::Poisoned)
    ));
}
