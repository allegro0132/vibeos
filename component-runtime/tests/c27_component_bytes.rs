use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_format::PROFILE_1_LIMITS;
use vibeos_component_runtime::decode::{inspect_component, DecodeError};

const TYPED_COMPONENT: &str =
    include_str!("../../component-format/tests/corpus/component/typed.component.wat");
const RICH_COMPONENT: &str = include_str!("fixtures/rich.component.wat");

const COMPONENT_HEADER: &[u8; 8] = b"\0asm\x0d\0\x01\0";
const SEED: u64 = 0x243f_6a88_85a3_08d3;
const RAW_MAX_LEN: usize = 511;
const PREFIX_TAIL_MAX_LEN: usize = 511;

// These pins make the generated corpus, its byte volume, and every public
// decoder classification reviewable. A fixture, generator, or ordering change
// must deliberately update all three kinds of evidence.
const EXPECTED_INPUTS: usize = 4_323;
const EXPECTED_TOTAL_INPUT_BYTES: u64 = 4_604_005;
const EXPECTED_CORPUS_FNV1A64: u64 = 0x9edc_2bd8_460d_97a4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Classification {
    Accepted,
    NotComponent,
    Malformed,
    Unsupported,
    Limit,
    Allocation,
    InvalidEmbeddedCore,
    DuplicateName,
    TypeGraph,
    InvalidWiring,
    InvalidCallbackSignature,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct StageCounts {
    accepted: usize,
    not_component: usize,
    malformed: usize,
    unsupported: usize,
    limit: usize,
    allocation: usize,
    invalid_embedded_core: usize,
    duplicate_name: usize,
    type_graph: usize,
    invalid_wiring: usize,
    invalid_callback_signature: usize,
}

const EXPECTED_STAGES: StageCounts = StageCounts {
    accepted: 863,
    not_component: 520,
    malformed: 2_527,
    unsupported: 134,
    limit: 11,
    allocation: 0,
    invalid_embedded_core: 267,
    duplicate_name: 0,
    type_graph: 0,
    invalid_wiring: 1,
    invalid_callback_signature: 0,
};

#[derive(Debug, Default, PartialEq, Eq)]
struct Coverage {
    inputs: usize,
    total_input_bytes: u64,
    max_input_bytes: usize,
    raw: usize,
    component_prefixed: usize,
    originals: usize,
    truncations: usize,
    bit_flips: usize,
    over_limit: usize,
    stages: StageCounts,
}

struct Generator(u64);

impl Generator {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next() as u8;
        }
    }
}

fn classify(result: Result<(), DecodeError>) -> Classification {
    match result {
        Ok(()) => Classification::Accepted,
        Err(DecodeError::NotComponent) => Classification::NotComponent,
        Err(DecodeError::Malformed) => Classification::Malformed,
        Err(DecodeError::Unsupported) => Classification::Unsupported,
        Err(DecodeError::Limit) => Classification::Limit,
        Err(DecodeError::Allocation) => Classification::Allocation,
        Err(DecodeError::InvalidEmbeddedCore) => Classification::InvalidEmbeddedCore,
        Err(DecodeError::DuplicateName) => Classification::DuplicateName,
        Err(DecodeError::TypeGraph) => Classification::TypeGraph,
        Err(DecodeError::InvalidWiring) => Classification::InvalidWiring,
        Err(DecodeError::InvalidCallbackSignature) => Classification::InvalidCallbackSignature,
    }
}

impl StageCounts {
    fn record(&mut self, classification: Classification) {
        match classification {
            Classification::Accepted => self.accepted += 1,
            Classification::NotComponent => self.not_component += 1,
            Classification::Malformed => self.malformed += 1,
            Classification::Unsupported => self.unsupported += 1,
            Classification::Limit => self.limit += 1,
            Classification::Allocation => self.allocation += 1,
            Classification::InvalidEmbeddedCore => self.invalid_embedded_core += 1,
            Classification::DuplicateName => self.duplicate_name += 1,
            Classification::TypeGraph => self.type_graph += 1,
            Classification::InvalidWiring => self.invalid_wiring += 1,
            Classification::InvalidCallbackSignature => self.invalid_callback_signature += 1,
        }
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn hash_case(hash: &mut u64, tag: u8, ordinal: usize, bytes: &[u8]) {
    hash_byte(hash, tag);
    for byte in (ordinal as u64).to_le_bytes() {
        hash_byte(hash, byte);
    }
    for byte in (bytes.len() as u64).to_le_bytes() {
        hash_byte(hash, byte);
    }
    for byte in bytes {
        hash_byte(hash, *byte);
    }
}

fn inspect_without_panic(label: &str, bytes: &[u8]) -> Classification {
    let result = catch_unwind(AssertUnwindSafe(|| inspect_component(bytes).map(|_| ())));
    let result = result.unwrap_or_else(|_| panic!("Component decoder panicked for {label}"));
    classify(result)
}

fn exercise(
    coverage: &mut Coverage,
    digest: &mut u64,
    tag: u8,
    ordinal: usize,
    label: &str,
    bytes: &[u8],
) -> Classification {
    assert!(
        bytes.len() <= PROFILE_1_LIMITS.max_component_bytes + 1,
        "unbounded corpus case {label}"
    );
    hash_case(digest, tag, ordinal, bytes);
    let classification = inspect_without_panic(label, bytes);
    coverage.inputs += 1;
    coverage.total_input_bytes = coverage
        .total_input_bytes
        .checked_add(bytes.len() as u64)
        .expect("bounded corpus byte total");
    coverage.max_input_bytes = coverage.max_input_bytes.max(bytes.len());
    coverage.stages.record(classification);
    classification
}

fn exercise_fixture_mutations(
    coverage: &mut Coverage,
    digest: &mut u64,
    generator: &mut Generator,
    fixture_tag: u8,
    fixture_name: &str,
    fixture: &[u8],
) {
    let original = exercise(
        coverage,
        digest,
        fixture_tag,
        0,
        &format!("{fixture_name}-original"),
        fixture,
    );
    coverage.originals += 1;
    assert_eq!(
        original,
        Classification::Accepted,
        "the pinned {fixture_name} Component must remain accepted"
    );

    for length in 0..fixture.len() {
        exercise(
            coverage,
            digest,
            fixture_tag + 1,
            length,
            &format!("{fixture_name}-truncate-{length}"),
            &fixture[..length],
        );
        coverage.truncations += 1;
    }

    for offset in 0..fixture.len() {
        let mut candidate = fixture.to_vec();
        let bit = 1_u8 << (generator.next() & 7);
        candidate[offset] ^= bit;
        exercise(
            coverage,
            digest,
            fixture_tag + 2,
            offset,
            &format!("{fixture_name}-bit-{offset}"),
            &candidate,
        );
        coverage.bit_flips += 1;
    }
}

#[test]
fn deterministic_component_byte_corpus_is_bounded_and_panic_free() {
    let typed = wat::parse_str(TYPED_COMPONENT).expect("pinned typed Component WAT");
    let rich = wat::parse_str(RICH_COMPONENT).expect("pinned rich Component WAT");
    let mut generator = Generator::new(SEED);
    let mut coverage = Coverage::default();
    let mut digest = 0xcbf2_9ce4_8422_2325_u64;

    for length in 0..=RAW_MAX_LEN {
        let mut bytes = vec![0_u8; length];
        generator.fill(&mut bytes);
        exercise(
            &mut coverage,
            &mut digest,
            0,
            length,
            &format!("raw-{length}"),
            &bytes,
        );
        coverage.raw += 1;
    }

    for tail_length in 0..=PREFIX_TAIL_MAX_LEN {
        let mut bytes = COMPONENT_HEADER.to_vec();
        bytes.resize(COMPONENT_HEADER.len() + tail_length, 0);
        generator.fill(&mut bytes[COMPONENT_HEADER.len()..]);
        exercise(
            &mut coverage,
            &mut digest,
            1,
            tail_length,
            &format!("component-prefix-{tail_length}"),
            &bytes,
        );
        coverage.component_prefixed += 1;
    }

    exercise_fixture_mutations(
        &mut coverage,
        &mut digest,
        &mut generator,
        2,
        "typed",
        &typed,
    );
    exercise_fixture_mutations(&mut coverage, &mut digest, &mut generator, 5, "rich", &rich);

    let mut over_limit = vec![0_u8; PROFILE_1_LIMITS.max_component_bytes + 1];
    over_limit[..COMPONENT_HEADER.len()].copy_from_slice(COMPONENT_HEADER);
    generator.fill(&mut over_limit[COMPONENT_HEADER.len()..]);
    let classification = exercise(
        &mut coverage,
        &mut digest,
        8,
        0,
        "max-component-bytes-plus-one",
        &over_limit,
    );
    coverage.over_limit += 1;
    assert_eq!(classification, Classification::Limit);

    assert_eq!(coverage.raw, RAW_MAX_LEN + 1, "{coverage:?}");
    assert_eq!(
        coverage.component_prefixed,
        PREFIX_TAIL_MAX_LEN + 1,
        "{coverage:?}"
    );
    assert_eq!(coverage.originals, 2, "{coverage:?}");
    assert_eq!(
        coverage.truncations,
        typed.len() + rich.len(),
        "{coverage:?}"
    );
    assert_eq!(coverage.bit_flips, typed.len() + rich.len(), "{coverage:?}");
    assert_eq!(coverage.over_limit, 1, "{coverage:?}");
    assert_eq!(coverage.inputs, EXPECTED_INPUTS, "{coverage:?}");
    assert_eq!(
        coverage.total_input_bytes, EXPECTED_TOTAL_INPUT_BYTES,
        "{coverage:?}"
    );
    assert_eq!(
        coverage.max_input_bytes,
        PROFILE_1_LIMITS.max_component_bytes + 1,
        "{coverage:?}"
    );
    assert_eq!(coverage.stages, EXPECTED_STAGES, "{coverage:?}");
    assert_eq!(
        digest, EXPECTED_CORPUS_FNV1A64,
        "corpus drift: {coverage:?}"
    );
}
