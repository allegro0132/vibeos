//! Provisioning consumes the firmware-selected entropy frontend. No identity
//! feature implicitly selects a timer collector or acceptance random source.
#[cfg(all(feature = "jitter-entropy", not(feature = "universal")))]
pub use crate::jitterentropy_random::{bytes_with, RandomError, RandomSource};
#[cfg(all(not(feature = "jitter-entropy"), not(feature = "universal")))]
pub use crate::virtio_rng::{bytes_with, RandomError, RandomSource};

#[cfg(not(feature = "universal"))]
pub async fn fill_seed(output: &mut [u8; 32]) -> Result<(), RandomError> {
    output.fill(0);
    #[cfg(all(feature = "jitter-entropy", not(feature = "universal")))]
    let result = crate::jitterentropy_random::fill_seed(output);
    #[cfg(all(not(feature = "jitter-entropy"), not(feature = "universal")))]
    let result = crate::virtio_rng::fill_seed(output).await;
    if result.is_err() {
        output.fill(0);
    }
    result
}

#[cfg(feature = "universal")]
pub use runtime::*;
#[cfg(feature = "universal")]
mod runtime {
    pub use crate::virtio_rng::{RandomError, RandomSource};
    use vibeos_core::cap::InvocationLease;
    use vibeos_hal::runtime_platform::{get, EntropyBackend};
    pub enum RandomBytes {
        Queued(crate::virtio_rng::RandomBytes),
        #[cfg(feature = "jitter-entropy")]
        Jitter(crate::jitterentropy_random::RandomBytes),
    }
    impl RandomBytes {
        pub fn as_slice(&self) -> &[u8] {
            match self {
                Self::Queued(bytes) => bytes.as_slice(),
                #[cfg(feature = "jitter-entropy")]
                Self::Jitter(bytes) => bytes.as_slice(),
            }
        }
    }
    #[cfg(feature = "jitter-entropy")]
    fn map(error: crate::jitterentropy_random::RandomError) -> RandomError {
        use crate::jitterentropy_random::RandomError as E;
        match error {
            E::Offline => RandomError::Offline,
            E::InvalidLength => RandomError::InvalidLength,
            E::Busy => RandomError::Busy,
            E::TimedOut => RandomError::TimedOut,
            E::DriverCancelled => RandomError::DriverCancelled,
            E::DriverFault => RandomError::DriverFault,
            E::DriverRestarted => RandomError::DriverRestarted,
            E::Protocol => RandomError::Protocol,
            E::Unsupported => RandomError::Unsupported,
            E::Quarantined => RandomError::Quarantined,
            E::AuthorityRevoked => RandomError::AuthorityRevoked,
            E::PermissionDenied => RandomError::PermissionDenied,
            E::IdentityExhausted => RandomError::IdentityExhausted,
        }
    }
    pub async fn bytes_with(
        lease: InvocationLease<RandomSource>,
        length: usize,
    ) -> Result<RandomBytes, RandomError> {
        match get().entropy_backend {
            EntropyBackend::Queued => crate::virtio_rng::bytes_with(lease, length)
                .await
                .map(RandomBytes::Queued),
            #[cfg(feature = "jitter-entropy")]
            EntropyBackend::Jitter => crate::jitterentropy_random::bytes_with(lease, length)
                .await
                .map(RandomBytes::Jitter)
                .map_err(map),
            _ => Err(RandomError::Offline),
        }
    }
    pub async fn fill_seed(output: &mut [u8; 32]) -> Result<(), RandomError> {
        output.fill(0);
        let result = match get().entropy_backend {
            EntropyBackend::Queued => crate::virtio_rng::fill_seed(output).await,
            #[cfg(feature = "jitter-entropy")]
            EntropyBackend::Jitter => crate::jitterentropy_random::fill_seed(output).map_err(map),
            _ => Err(RandomError::Offline),
        };
        if result.is_err() {
            output.fill(0);
        }
        result
    }
}
