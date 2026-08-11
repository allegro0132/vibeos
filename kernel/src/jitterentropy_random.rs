//! Production random service for Milk-V Duo, seeded by jitterentropy-rs.

extern crate alloc;

use alloc::{string::String, sync::Arc};
use core::{
    any::Any,
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

use jitterentropy::{EntropyCollector, EntropyCollectorBuilder, Flags, Timer};
use vibeos_core::cap::{InvocationLease, Resource, Rights};
use vibeos_core::sync::SpinLock;
use vibeos_random::{
    ChaCha20Random, EntropySource, RandomDomain, RandomError as CoreError, RandomLimits, SEED_BYTES,
};

pub const MAX_RANDOM_BYTES: usize = 64;
const OSR: u32 = 3;
const MEMORY_SIZE: usize = 256 * 1024;
const DOMAIN: u64 = 0x4d56_2d53_5348_2d50;
const FLAGS: Flags = Flags(
    Flags::DISABLE_INTERNAL_TIMER.bits() | Flags::FORCE_FIPS.bits() | (9 << Flags::MEMSIZE_SHIFT),
);

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

pub struct RandomBytes {
    bytes: [u8; MAX_RANDOM_BYTES],
    len: u8,
}
impl RandomBytes {
    fn zeroed(len: usize) -> Self {
        Self {
            bytes: [0; MAX_RANDOM_BYTES],
            len: len as u8,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}
impl Drop for RandomBytes {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            unsafe { ptr::write_volatile(byte, 0) };
        }
        self.len = 0;
        compiler_fence(Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
struct SbiTimer;
impl Timer for SbiTimer {
    fn now(&mut self) -> Option<u64> {
        Some(crate::sbi::time())
    }
}

struct JitterSeeds(EntropyCollector<SbiTimer>);
unsafe impl Send for JitterSeeds {}
impl EntropySource for JitterSeeds {
    type Error = ();
    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error> {
        self.0.fill_bytes(seed).map_err(|_| ())
    }
}

pub struct RandomSource {
    state: SpinLock<ChaCha20Random<JitterSeeds>>,
}
impl RandomSource {
    fn new() -> Result<Arc<Self>, RandomError> {
        let collector = EntropyCollectorBuilder::new()
            .osr(OSR)
            .flags(FLAGS)
            .memory_size(MEMORY_SIZE)
            .build_with_timer(SbiTimer)
            .map_err(|_| RandomError::Offline)?;
        let domain = RandomDomain::new(DOMAIN).ok_or(RandomError::IdentityExhausted)?;
        let limits = RandomLimits::new(MAX_RANDOM_BYTES, 1024 * 1024).map_err(map_core)?;
        let random =
            ChaCha20Random::new(JitterSeeds(collector), domain, limits).map_err(map_core)?;
        Ok(Arc::new(Self {
            state: SpinLock::new(random),
        }))
    }
    fn bytes(&self, length: usize) -> Result<RandomBytes, RandomError> {
        if !(1..=MAX_RANDOM_BYTES).contains(&length) {
            return Err(RandomError::InvalidLength);
        }
        let mut output = RandomBytes::zeroed(length);
        self.state
            .lock()
            .try_fill_bytes(&mut output.bytes[..length])
            .map_err(map_core)?;
        Ok(output)
    }
}
impl Resource for RandomSource {
    fn kind(&self) -> &'static str {
        "random-source"
    }
    fn describe(&self) -> String {
        String::from("jitterentropy-rs OSR=3 -> ChaCha20 DRBG [max 64 bytes]")
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct RandomResources {
    pub source: Arc<RandomSource>,
}
pub fn provision() -> Result<RandomResources, RandomError> {
    Ok(RandomResources {
        source: RandomSource::new()?,
    })
}
pub fn fill_seed(seed: &mut [u8; SEED_BYTES]) -> Result<(), RandomError> {
    let mut collector = EntropyCollectorBuilder::new()
        .osr(OSR)
        .flags(FLAGS)
        .memory_size(MEMORY_SIZE)
        .build_with_timer(SbiTimer)
        .map_err(|_| RandomError::Offline)?;
    collector
        .fill_bytes(seed)
        .map_err(|_| RandomError::Protocol)
}
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
fn map_core(error: CoreError) -> RandomError {
    match error {
        CoreError::RequestTooLarge { .. }
        | CoreError::ZeroRequestLimit
        | CoreError::RequestLimitTooLarge { .. }
        | CoreError::ZeroEpochLimit
        | CoreError::EpochLimitTooLarge { .. }
        | CoreError::RequestLimitExceedsEpoch { .. } => RandomError::InvalidLength,
        CoreError::EpochExhausted => RandomError::IdentityExhausted,
        CoreError::EntropyUnavailable
        | CoreError::RepeatedEntropy
        | CoreError::PermanentlyFailed => RandomError::Protocol,
    }
}
