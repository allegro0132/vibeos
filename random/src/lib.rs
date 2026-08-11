//! Bounded, fallible random-byte generation for kernel services.
//!
//! [`ChaCha20Random`] is deliberately split from its platform entropy source.
//! A target adapter must obtain each complete 256-bit seed from a documented,
//! trusted source; this module does not condition, stretch, or pretend to
//! validate weak entropy. Deterministic providers belong only in test images.
//!
//! Each consumer must be assigned a distinct [`RandomDomain`]. The domain is
//! installed as ChaCha's 64-bit stream identifier, giving disjoint streams for
//! equal seeds without inventing a local KDF. Requests and epochs are bounded,
//! and a request is either filled completely or left untouched.

#![no_std]

use core::fmt;
use core::num::NonZeroU64;

use chacha20::rand_core::{Rng, SeedableRng};
use chacha20::ChaCha20Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Number of trusted entropy bytes required for each seed or reseed.
pub const SEED_BYTES: usize = 32;

/// Hard ceiling for one random-byte request.
///
/// This is an implementation/resource bound, not an entropy estimate.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Hard ceiling for bytes emitted from one seed and domain stream.
///
/// This remains far below ChaCha20's stream period and also bounds the amount
/// of output exposed before fresh entropy is required.
pub const MAX_BYTES_PER_EPOCH: u64 = 4 * 1024 * 1024 * 1024;

/// Default upper bound for one request (4 KiB).
pub const DEFAULT_REQUEST_BYTES: usize = 4 * 1024;

/// Default reseed interval (1 MiB of emitted bytes).
pub const DEFAULT_BYTES_PER_EPOCH: u64 = 1024 * 1024;

/// Stable, non-zero identifier for one random-output purpose.
///
/// Domain identifiers are public coordination values, not secrets. Assign
/// them from one audited registry and never reuse an identifier for unrelated
/// protocols or purposes. They map directly to ChaCha20's stream identifier.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RandomDomain(NonZeroU64);

impl RandomDomain {
    /// Construct a domain, rejecting the unassigned zero value.
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(domain) => Some(Self(domain)),
            None => None,
        }
    }

    /// Return the stable stream identifier.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Resource limits enforced before any output is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomLimits {
    request_bytes: usize,
    bytes_per_epoch: u64,
}

impl RandomLimits {
    /// Validate request and epoch limits against the module's hard ceilings.
    pub const fn new(request_bytes: usize, bytes_per_epoch: u64) -> Result<Self, RandomError> {
        if request_bytes == 0 {
            return Err(RandomError::ZeroRequestLimit);
        }
        if request_bytes > MAX_REQUEST_BYTES {
            return Err(RandomError::RequestLimitTooLarge {
                limit: request_bytes,
                maximum: MAX_REQUEST_BYTES,
            });
        }
        if bytes_per_epoch == 0 {
            return Err(RandomError::ZeroEpochLimit);
        }
        if bytes_per_epoch > MAX_BYTES_PER_EPOCH {
            return Err(RandomError::EpochLimitTooLarge {
                limit: bytes_per_epoch,
                maximum: MAX_BYTES_PER_EPOCH,
            });
        }
        if request_bytes as u64 > bytes_per_epoch {
            return Err(RandomError::RequestLimitExceedsEpoch {
                request_limit: request_bytes,
                epoch_limit: bytes_per_epoch,
            });
        }
        Ok(Self {
            request_bytes,
            bytes_per_epoch,
        })
    }

    /// Maximum number of bytes accepted by one call.
    pub const fn request_bytes(self) -> usize {
        self.request_bytes
    }

    /// Maximum number of bytes emitted before a mandatory reseed.
    pub const fn bytes_per_epoch(self) -> u64 {
        self.bytes_per_epoch
    }
}

impl Default for RandomLimits {
    fn default() -> Self {
        // Both constants are statically within the hard ceilings.
        Self {
            request_bytes: DEFAULT_REQUEST_BYTES,
            bytes_per_epoch: DEFAULT_BYTES_PER_EPOCH,
        }
    }
}

/// Failure returned by construction, reseeding, or random-byte requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    ZeroRequestLimit,
    RequestLimitTooLarge {
        limit: usize,
        maximum: usize,
    },
    ZeroEpochLimit,
    EpochLimitTooLarge {
        limit: u64,
        maximum: u64,
    },
    RequestLimitExceedsEpoch {
        request_limit: usize,
        epoch_limit: u64,
    },
    RequestTooLarge {
        requested: usize,
        maximum: usize,
    },
    /// The platform source could not supply one complete trusted seed.
    EntropyUnavailable,
    /// A reseed returned exactly the current seed, indicating a stuck source.
    RepeatedEntropy,
    /// Advancing the monotonically increasing epoch would wrap.
    EpochExhausted,
    /// A terminal error already made this instance unusable.
    PermanentlyFailed,
}

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestLimit => f.write_str("random request limit must be non-zero"),
            Self::RequestLimitTooLarge { limit, maximum } => write!(
                f,
                "random request limit {limit} exceeds hard maximum {maximum}"
            ),
            Self::ZeroEpochLimit => f.write_str("random epoch byte limit must be non-zero"),
            Self::EpochLimitTooLarge { limit, maximum } => write!(
                f,
                "random epoch byte limit {limit} exceeds hard maximum {maximum}"
            ),
            Self::RequestLimitExceedsEpoch {
                request_limit,
                epoch_limit,
            } => write!(
                f,
                "random request limit {request_limit} exceeds epoch byte limit {epoch_limit}"
            ),
            Self::RequestTooLarge { requested, maximum } => write!(
                f,
                "random request for {requested} bytes exceeds maximum {maximum}"
            ),
            Self::EntropyUnavailable => {
                f.write_str("trusted entropy source could not supply a complete seed")
            }
            Self::RepeatedEntropy => {
                f.write_str("trusted entropy source repeated the current seed")
            }
            Self::EpochExhausted => f.write_str("random epoch counter exhausted"),
            Self::PermanentlyFailed => f.write_str("random source has permanently failed"),
        }
    }
}

/// Fallible provider of one complete 256-bit seed.
///
/// Implementations must return `Ok(())` only after filling every byte from a
/// trusted source. On failure they may leave `seed` partially written; the
/// caller always wipes the temporary before returning.
pub trait EntropySource {
    type Error;

    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error>;
}

/// Narrow random-byte capability exposed to consumers.
///
/// Implementations must reject oversized requests without modifying the
/// destination. Other errors likewise leave the destination untouched.
pub trait RandomSource {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError>;

    fn max_request_bytes(&self) -> usize;
}

/// ChaCha20 random generator seeded and reseeded by a trusted source.
///
/// The generator is intentionally not `Clone`: duplicating live state would
/// duplicate output. It owns its entropy provider so recipients of a narrow
/// [`RandomSource`] reference cannot bypass the reseed policy. The pinned
/// RustCrypto implementation is built with `zeroize`, so its key, counter, and
/// buffered output are erased both when this value is dropped and when a
/// reseed replaces the previous generator.
pub struct ChaCha20Random<E> {
    entropy: E,
    rng: Option<ChaCha20Rng>,
    domain: RandomDomain,
    limits: RandomLimits,
    epoch: u64,
    bytes_in_epoch: u64,
    failed: bool,
}

impl<E: EntropySource> ChaCha20Random<E> {
    /// Seed a new generator. The first successfully seeded state is epoch 1.
    pub fn new(
        mut entropy: E,
        domain: RandomDomain,
        limits: RandomLimits,
    ) -> Result<Self, RandomError> {
        let mut seed = [0u8; SEED_BYTES];
        if entropy.try_fill_seed(&mut seed).is_err() {
            seed.zeroize();
            return Err(RandomError::EntropyUnavailable);
        }

        let mut rng = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        rng.set_stream(domain.get());

        Ok(Self {
            entropy,
            rng: Some(rng),
            domain,
            limits,
            epoch: 1,
            bytes_in_epoch: 0,
            failed: false,
        })
    }

    /// Domain assigned to this generator.
    pub const fn domain(&self) -> RandomDomain {
        self.domain
    }

    /// Current monotonically increasing seed epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Bytes emitted from the current seed epoch.
    pub const fn bytes_in_epoch(&self) -> u64 {
        self.bytes_in_epoch
    }

    /// Bytes still available before a mandatory reseed.
    pub const fn remaining_bytes_in_epoch(&self) -> u64 {
        self.limits.bytes_per_epoch - self.bytes_in_epoch
    }

    /// Limits enforced by this generator.
    pub const fn limits(&self) -> RandomLimits {
        self.limits
    }

    /// Whether a terminal failure has permanently disabled output.
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    /// Replace the generator state with a fresh seed and advance the epoch.
    ///
    /// Entropy failure, a repeated seed, or epoch exhaustion permanently
    /// disables this instance. A new instance and a separately validated
    /// entropy path are required after such a failure.
    pub fn reseed(&mut self) -> Result<u64, RandomError> {
        if self.failed {
            return Err(RandomError::PermanentlyFailed);
        }

        let Some(next_epoch) = self.epoch.checked_add(1) else {
            return self.fail_permanently(RandomError::EpochExhausted);
        };

        let mut seed = [0u8; SEED_BYTES];
        if self.entropy.try_fill_seed(&mut seed).is_err() {
            seed.zeroize();
            return self.fail_permanently(RandomError::EntropyUnavailable);
        }

        let mut previous_seed = self
            .rng
            .as_ref()
            .expect("a usable random source retains its zeroizing state")
            .get_seed();
        let repeated = bool::from(seed[..].ct_eq(&previous_seed[..]));
        previous_seed.zeroize();
        if repeated {
            seed.zeroize();
            return self.fail_permanently(RandomError::RepeatedEntropy);
        }

        let mut replacement = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        replacement.set_stream(self.domain.get());

        drop(self.rng.replace(replacement));
        self.epoch = next_epoch;
        self.bytes_in_epoch = 0;
        Ok(next_epoch)
    }

    /// Fill a complete bounded request, reseeding first when it cannot fit in
    /// the current epoch.
    ///
    /// No request is split across epochs. Every validation and any necessary
    /// reseed happens before the destination is modified.
    pub fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        if self.failed {
            return Err(RandomError::PermanentlyFailed);
        }
        if destination.len() > self.limits.request_bytes {
            return Err(RandomError::RequestTooLarge {
                requested: destination.len(),
                maximum: self.limits.request_bytes,
            });
        }

        // The validated request ceiling is only 64 KiB, so this conversion is
        // lossless on every supported target.
        let requested = destination.len() as u64;
        if requested > self.remaining_bytes_in_epoch() {
            self.reseed()?;
        }

        let Some(next_total) = self.bytes_in_epoch.checked_add(requested) else {
            // This is unreachable while private state and validated limits are
            // intact, but a cryptographic service must not wrap open.
            return self.fail_permanently(RandomError::PermanentlyFailed);
        };
        if next_total > self.limits.bytes_per_epoch {
            return self.fail_permanently(RandomError::PermanentlyFailed);
        }

        self.rng
            .as_mut()
            .expect("a usable random source retains its zeroizing state")
            .fill_bytes(destination);
        self.bytes_in_epoch = next_total;
        Ok(())
    }

    fn fail_permanently<T>(&mut self, error: RandomError) -> Result<T, RandomError> {
        self.failed = true;
        // Do not retain a stale key, counter, or buffered output until the
        // owner eventually drops this object. The pinned RustCrypto Drop wipes
        // all of that state here, at the terminal transition itself.
        drop(self.rng.take());
        Err(error)
    }
}

impl<E: EntropySource> RandomSource for ChaCha20Random<E> {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        ChaCha20Random::try_fill_bytes(self, destination)
    }

    fn max_request_bytes(&self) -> usize {
        self.limits.request_bytes
    }
}

impl<E> fmt::Debug for ChaCha20Random<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChaCha20Random")
            .field("domain", &self.domain)
            .field("limits", &self.limits)
            .field("epoch", &self.epoch)
            .field("bytes_in_epoch", &self.bytes_in_epoch)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
