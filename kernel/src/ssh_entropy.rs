//! Provisioning consumes the firmware-selected entropy frontend. No identity
//! feature implicitly selects a timer collector or acceptance random source.
#[cfg(feature = "jitter-entropy")]
pub use crate::jitterentropy_random::{bytes_with, RandomError, RandomSource};
#[cfg(not(feature = "jitter-entropy"))]
pub use crate::virtio_rng::{bytes_with, RandomError, RandomSource};

pub async fn fill_seed(output: &mut [u8; 32]) -> Result<(), RandomError> {
    output.fill(0);
    #[cfg(feature = "jitter-entropy")]
    let result = crate::jitterentropy_random::fill_seed(output);
    #[cfg(not(feature = "jitter-entropy"))]
    let result = crate::virtio_rng::fill_seed(output).await;
    if result.is_err() {
        output.fill(0);
    }
    result
}
