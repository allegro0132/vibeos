//! Deterministic random service for the explicit Milk-V SSH acceptance image.
//!
//! # Security warning
//!
//! This module is deliberately **not an entropy source**. Its fixed seed prefix
//! and boot-local sequence produce the same ChaCha20 streams after every reboot.
//! It exists only to validate DWMAC, DHCP, the SSH wire protocol, and interactive
//! VSH on physical hardware before a real CV1800B entropy and provisioning path
//! exists. It must never be enabled, copied, or treated as suitable for a
//! production image, key generation, long-lived credentials, or secret data.

#![cfg(all(feature = "milkv-duo", feature = "milkv-ssh-acceptance"))]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use vibeos_core::cap::{InvocationLease, Resource, Rights};
use vibeos_core::random::{
    ChaCha20Random, EntropySource, RandomDomain, RandomError as CoreRandomError, RandomLimits,
    SEED_BYTES,
};
use vibeos_core::sync::SpinLock;

/// Match the bounded request surface consumed by the SSH acceptance component.
pub const MAX_RANDOM_BYTES: usize = 64;

const ACCEPTANCE_RANDOM_DOMAIN: u64 = 0x4d56_2d53_5348_2d41;
const DETERMINISTIC_SEED_PREFIX: [u8; SEED_BYTES - 8] = *b"VibeOS-MilkV-SSH-test!!!";

// Seed identifiers are unique only within one boot. Reboot resets this public
// sequence and intentionally reproduces the same output stream.
static NEXT_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    Offline,
    InvalidLength,
    Busy,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    Protocol,
    Unsupported,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
    IdentityExhausted,
}

impl core::fmt::Display for RandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "acceptance random source is offline",
            Self::InvalidLength => "random request length is outside the bounded range",
            Self::Busy => "acceptance random source is busy",
            Self::TimedOut => "acceptance random source timed out",
            Self::DriverCancelled => "acceptance random service was cancelled",
            Self::DriverFault => "acceptance random service faulted",
            Self::DriverRestarted => "acceptance random service restarted",
            Self::Protocol => "acceptance random service failed",
            Self::Unsupported => "acceptance random service is unavailable",
            Self::Quarantined => "acceptance random service is quarantined",
            Self::AuthorityRevoked => "random capability is absent or revoked",
            Self::PermissionDenied => "random capability lacks READ authority",
            Self::IdentityExhausted => "acceptance random seed identity space is exhausted",
        })
    }
}

/// A bounded result whose complete backing storage is erased on drop.
pub struct RandomBytes {
    bytes: [u8; MAX_RANDOM_BYTES],
    len: u8,
}

impl RandomBytes {
    fn zeroed(length: usize) -> Self {
        Self {
            bytes: [0; MAX_RANDOM_BYTES],
            len: length as u8,
        }
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    pub fn copy_to(&self, output: &mut [u8]) -> Result<(), RandomError> {
        if output.len() != self.len() {
            return Err(RandomError::InvalidLength);
        }
        output.copy_from_slice(self.as_slice());
        Ok(())
    }
}

impl Drop for RandomBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            // Keep ordinary cleanup visible to the optimizer even though this
            // acceptance-only output is deterministic and provides no secrecy.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        self.len = 0;
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

struct DeterministicSeeds;

impl EntropySource for DeterministicSeeds {
    type Error = ();

    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error> {
        let sequence = NEXT_SEED_SEQUENCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ())?;
        seed[..DETERMINISTIC_SEED_PREFIX.len()].copy_from_slice(&DETERMINISTIC_SEED_PREFIX);
        seed[DETERMINISTIC_SEED_PREFIX.len()..].copy_from_slice(&sequence.to_le_bytes());
        Ok(())
    }
}

struct AcceptanceState {
    random: ChaCha20Random<DeterministicSeeds>,
    requests: u64,
}

/// Capability resource for the explicit, insecure hardware acceptance image.
pub struct RandomSource {
    state: SpinLock<AcceptanceState>,
}

impl RandomSource {
    fn new() -> Arc<Self> {
        let domain = RandomDomain::new(ACCEPTANCE_RANDOM_DOMAIN)
            .expect("the acceptance random domain is non-zero");
        let limits = RandomLimits::new(MAX_RANDOM_BYTES, MAX_RANDOM_BYTES as u64)
            .expect("the acceptance random limits are valid");
        let random = ChaCha20Random::new(DeterministicSeeds, domain, limits)
            .expect("the boot-local acceptance seed sequence starts available");
        Arc::new(Self {
            state: SpinLock::new(AcceptanceState {
                random,
                requests: 0,
            }),
        })
    }

    fn bytes(&self, length: usize) -> Result<RandomBytes, RandomError> {
        if !(1..=MAX_RANDOM_BYTES).contains(&length) {
            return Err(RandomError::InvalidLength);
        }

        let mut output = RandomBytes::zeroed(length);
        let mut state = self.state.lock();
        let next_request = state
            .requests
            .checked_add(1)
            .ok_or(RandomError::IdentityExhausted)?;

        // Every accepted request after the first receives a distinct seed.
        // The seed sequence itself is public and repeats after reboot.
        if state.requests != 0 {
            state.random.reseed().map_err(map_core_error)?;
        }
        state
            .random
            .try_fill_bytes(&mut output.bytes[..length])
            .map_err(map_core_error)?;
        state.requests = next_request;
        Ok(output)
    }
}

impl Resource for RandomSource {
    fn kind(&self) -> &'static str {
        "random-source"
    }

    fn describe(&self) -> String {
        String::from("INSECURE deterministic Milk-V SSH acceptance RNG [max 64 bytes]")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct RandomResources {
    pub source: Arc<RandomSource>,
}

/// Provision the deterministic service for the explicitly insecure image.
///
/// Every call consumes a new boot-local seed identity, but the whole sequence
/// repeats after reboot and therefore provides no unpredictability whatsoever.
pub fn provision() -> RandomResources {
    RandomResources {
        source: RandomSource::new(),
    }
}

/// Return exactly `length` deterministic acceptance bytes under READ authority.
pub async fn bytes_with(
    lease: InvocationLease<RandomSource>,
    length: usize,
) -> Result<RandomBytes, RandomError> {
    if !lease.authorizes(Rights::READ) {
        return Err(RandomError::PermissionDenied);
    }
    let result = lease.with(|source| source.bytes(length));
    drop(lease);
    result
}

fn map_core_error(error: CoreRandomError) -> RandomError {
    match error {
        CoreRandomError::RequestTooLarge { .. }
        | CoreRandomError::ZeroRequestLimit
        | CoreRandomError::RequestLimitTooLarge { .. }
        | CoreRandomError::ZeroEpochLimit
        | CoreRandomError::EpochLimitTooLarge { .. }
        | CoreRandomError::RequestLimitExceedsEpoch { .. } => RandomError::InvalidLength,
        CoreRandomError::EpochExhausted => RandomError::IdentityExhausted,
        CoreRandomError::EntropyUnavailable
        | CoreRandomError::RepeatedEntropy
        | CoreRandomError::PermanentlyFailed => RandomError::Protocol,
    }
}
