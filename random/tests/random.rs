//! Host evidence for the bounded ChaCha20 random-source state machine.

use std::collections::VecDeque;

use vibeos_random::{
    ChaCha20Random, EntropySource, RandomDomain, RandomError, RandomLimits, RandomSource,
    MAX_BYTES_PER_EPOCH, MAX_REQUEST_BYTES,
};

#[test]
fn pinned_chacha_state_is_zeroized_on_drop() {
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    requires_zeroize_on_drop::<chacha20::ChaCha20Rng>();
    assert!(core::mem::needs_drop::<ChaCha20Random<ScriptedEntropy>>());
}

#[test]
fn pinned_chacha20_matches_the_zero_key_zero_stream_vector() {
    use chacha20::rand_core::{Rng, SeedableRng};

    let expected = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
        0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86,
    ];
    let mut rng = chacha20::ChaCha20Rng::from_seed([0u8; 32]);
    let mut actual = [0u8; 64];
    rng.fill_bytes(&mut actual);

    assert_eq!(actual, expected);
}

#[derive(Clone, Copy)]
enum EntropyStep {
    Seed([u8; 32]),
    Fail,
}

struct ScriptedEntropy {
    steps: VecDeque<EntropyStep>,
}

impl ScriptedEntropy {
    fn new(steps: impl IntoIterator<Item = EntropyStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
        }
    }
}

impl EntropySource for ScriptedEntropy {
    type Error = ();

    fn try_fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), Self::Error> {
        match self.steps.pop_front().unwrap_or(EntropyStep::Fail) {
            EntropyStep::Seed(next) => {
                seed.copy_from_slice(&next);
                Ok(())
            }
            EntropyStep::Fail => {
                seed[..7].fill(0xa5);
                Err(())
            }
        }
    }
}

fn domain(raw: u64) -> RandomDomain {
    RandomDomain::new(raw).unwrap()
}

fn limits(request: usize, epoch: u64) -> RandomLimits {
    RandomLimits::new(request, epoch).unwrap()
}

fn generator(
    steps: impl IntoIterator<Item = EntropyStep>,
    domain_id: u64,
    request: usize,
    epoch: u64,
) -> ChaCha20Random<ScriptedEntropy> {
    ChaCha20Random::new(
        ScriptedEntropy::new(steps),
        domain(domain_id),
        limits(request, epoch),
    )
    .unwrap()
}

#[test]
fn same_seed_domain_and_call_sequence_is_deterministic() {
    let seed = [0x31; 32];
    let mut left = generator([EntropyStep::Seed(seed)], 0x1001, 64, 128);
    let mut right = generator([EntropyStep::Seed(seed)], 0x1001, 64, 128);
    let mut left_first = [0u8; 32];
    let mut right_first = [0u8; 32];
    let mut left_second = [0u8; 64];
    let mut right_second = [0u8; 64];

    left.try_fill_bytes(&mut left_first).unwrap();
    right.try_fill_bytes(&mut right_first).unwrap();
    left.try_fill_bytes(&mut left_second).unwrap();
    right.try_fill_bytes(&mut right_second).unwrap();

    assert_eq!(left_first, right_first);
    assert_eq!(left_second, right_second);
    assert_eq!(left.epoch(), 1);
    assert_eq!(left.bytes_in_epoch(), 96);
}

#[test]
fn distinct_domains_separate_equal_seed_streams() {
    let seed = [0x52; 32];
    let mut kex = generator([EntropyStep::Seed(seed)], 0x2001, 64, 128);
    let mut session = generator([EntropyStep::Seed(seed)], 0x2002, 64, 128);
    let mut kex_bytes = [0u8; 64];
    let mut session_bytes = [0u8; 64];

    kex.try_fill_bytes(&mut kex_bytes).unwrap();
    session.try_fill_bytes(&mut session_bytes).unwrap();

    assert_ne!(kex_bytes, session_bytes);
    assert_eq!(kex.domain(), domain(0x2001));
    assert_eq!(session.domain(), domain(0x2002));
    assert!(RandomDomain::new(0).is_none());
}

#[test]
fn oversized_request_is_rejected_atomically_without_poisoning() {
    let mut random = generator([EntropyStep::Seed([0x63; 32])], 0x3001, 8, 16);
    let mut oversized = [0xa5; 9];

    assert_eq!(
        random.try_fill_bytes(&mut oversized),
        Err(RandomError::RequestTooLarge {
            requested: 9,
            maximum: 8,
        })
    );
    assert_eq!(oversized, [0xa5; 9]);
    assert_eq!(random.bytes_in_epoch(), 0);
    assert!(!random.is_failed());

    let mut accepted = [0u8; 8];
    random.try_fill_bytes(&mut accepted).unwrap();
    assert_ne!(accepted, [0u8; 8]);
}

#[test]
fn request_crossing_epoch_boundary_reseeds_before_writing() {
    let first_seed = [0x74; 32];
    let second_seed = [0x85; 32];
    let mut random = generator(
        [
            EntropyStep::Seed(first_seed),
            EntropyStep::Seed(second_seed),
        ],
        0x4001,
        8,
        8,
    );
    let mut first = [0u8; 8];
    let mut after_reseed = [0u8; 8];

    random.try_fill_bytes(&mut first).unwrap();
    assert_eq!(random.remaining_bytes_in_epoch(), 0);
    random.try_fill_bytes(&mut after_reseed).unwrap();

    assert_eq!(random.epoch(), 2);
    assert_eq!(random.bytes_in_epoch(), 8);
    assert_ne!(first, after_reseed);

    let mut direct = generator([EntropyStep::Seed(second_seed)], 0x4001, 8, 8);
    let mut expected = [0u8; 8];
    direct.try_fill_bytes(&mut expected).unwrap();
    assert_eq!(after_reseed, expected);
}

#[test]
fn explicit_reseed_advances_epoch_and_resets_budget() {
    let mut random = generator(
        [EntropyStep::Seed([0x96; 32]), EntropyStep::Seed([0xa7; 32])],
        0x5001,
        16,
        32,
    );
    let mut bytes = [0u8; 16];
    random.try_fill_bytes(&mut bytes).unwrap();

    assert_eq!(random.reseed(), Ok(2));
    assert_eq!(random.epoch(), 2);
    assert_eq!(random.bytes_in_epoch(), 0);
    assert_eq!(random.remaining_bytes_in_epoch(), 32);
}

#[test]
fn entropy_failure_leaves_request_untouched_and_fails_closed() {
    let mut random = generator(
        [EntropyStep::Seed([0xb8; 32]), EntropyStep::Fail],
        0x6001,
        8,
        8,
    );
    let mut first = [0u8; 8];
    random.try_fill_bytes(&mut first).unwrap();
    let mut destination = [0x5a; 8];

    assert_eq!(
        random.try_fill_bytes(&mut destination),
        Err(RandomError::EntropyUnavailable)
    );
    assert_eq!(destination, [0x5a; 8]);
    assert!(random.is_failed());
    assert_eq!(random.epoch(), 1);
    assert_eq!(
        random.try_fill_bytes(&mut destination),
        Err(RandomError::PermanentlyFailed)
    );
    assert_eq!(random.reseed(), Err(RandomError::PermanentlyFailed));
}

#[test]
fn repeated_seed_is_a_terminal_entropy_failure() {
    let repeated = [0xc9; 32];
    let mut random = generator(
        [EntropyStep::Seed(repeated), EntropyStep::Seed(repeated)],
        0x7001,
        8,
        8,
    );
    let mut first = [0u8; 8];
    random.try_fill_bytes(&mut first).unwrap();
    let mut destination = [0x3c; 8];

    assert_eq!(
        random.try_fill_bytes(&mut destination),
        Err(RandomError::RepeatedEntropy)
    );
    assert_eq!(destination, [0x3c; 8]);
    assert!(random.is_failed());
    assert_eq!(
        random.try_fill_bytes(&mut destination),
        Err(RandomError::PermanentlyFailed)
    );
}

#[test]
fn narrow_capability_reports_and_enforces_its_bound() {
    fn consume(source: &mut dyn RandomSource, destination: &mut [u8]) {
        assert_eq!(source.max_request_bytes(), 12);
        source.try_fill_bytes(destination).unwrap();
    }

    let mut random = generator([EntropyStep::Seed([0xfc; 32])], 0x9001, 12, 24);
    assert_eq!(random.limits(), limits(12, 24));
    let mut destination = [0u8; 12];
    consume(&mut random, &mut destination);
    assert_ne!(destination, [0u8; 12]);
}

#[test]
fn limits_reject_zero_unbounded_and_incoherent_values() {
    let defaults = RandomLimits::default();
    assert_eq!(defaults.request_bytes(), 4 * 1024);
    assert_eq!(defaults.bytes_per_epoch(), 1024 * 1024);

    assert_eq!(RandomLimits::new(0, 1), Err(RandomError::ZeroRequestLimit));
    assert_eq!(
        RandomLimits::new(MAX_REQUEST_BYTES + 1, MAX_BYTES_PER_EPOCH),
        Err(RandomError::RequestLimitTooLarge {
            limit: MAX_REQUEST_BYTES + 1,
            maximum: MAX_REQUEST_BYTES,
        })
    );
    assert_eq!(RandomLimits::new(1, 0), Err(RandomError::ZeroEpochLimit));
    assert_eq!(
        RandomLimits::new(1, MAX_BYTES_PER_EPOCH + 1),
        Err(RandomError::EpochLimitTooLarge {
            limit: MAX_BYTES_PER_EPOCH + 1,
            maximum: MAX_BYTES_PER_EPOCH,
        })
    );
    assert_eq!(
        RandomLimits::new(9, 8),
        Err(RandomError::RequestLimitExceedsEpoch {
            request_limit: 9,
            epoch_limit: 8,
        })
    );
}

#[test]
fn construction_propagates_entropy_failure() {
    let result = ChaCha20Random::new(
        ScriptedEntropy::new([EntropyStep::Fail]),
        domain(0xa001),
        limits(8, 16),
    );

    assert!(matches!(result, Err(RandomError::EntropyUnavailable)));
}
