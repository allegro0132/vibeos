use crate::error::Result;
use rand_core::{TryCryptoRng, TryRng};
use zeroize::ZeroizeOnDrop;

/// A cryptographically secure random-byte source for one SSH connection.
///
/// Implementations must either fill the whole output slice with fresh,
/// unpredictable bytes or return an error. `Runner` keeps an exclusive borrow of
/// the source for its entire lifetime, so separate connections cannot
/// accidentally share hidden global RNG state.
pub trait RandomSource: Send {
    fn fill_random(&mut self, output: &mut [u8]) -> Result<()>;
}

impl<R> RandomSource for R
where
    R: rand_core::CryptoRng + Send,
{
    fn fill_random(&mut self, output: &mut [u8]) -> Result<()> {
        rand_core::Rng::fill_bytes(self, output);
        Ok(())
    }
}

/// An infallible, short-lived 32-byte adapter seeded from a fallible source.
///
/// `x25519-dalek` 3.0.0's `EphemeralSecret::random_from_rng` consumes exactly
/// one 32-byte fill. This adapter lets us report source failure before calling
/// that infallible API. It records over-consumption and checks it immediately
/// after the call, so a dependency change cannot silently substitute weak
/// bytes. The seed is erased on drop.
#[derive(ZeroizeOnDrop)]
pub(crate) struct FixedRandom32 {
    bytes: [u8; 32],
    offset: usize,
    over_consumed: bool,
}

impl FixedRandom32 {
    pub(crate) fn new(source: &mut dyn RandomSource) -> Result<Self> {
        let mut bytes = [0; 32];
        source.fill_random(&mut bytes)?;
        Ok(Self { bytes, offset: 0, over_consumed: false })
    }

    pub(crate) fn consumed_exactly(self) -> Result<()> {
        if self.offset == self.bytes.len() && !self.over_consumed {
            Ok(())
        } else {
            Err(crate::Error::Random)
        }
    }

    fn fill(&mut self, output: &mut [u8]) {
        let available = self.bytes.len().saturating_sub(self.offset);
        let count = available.min(output.len());
        output[..count]
            .copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;

        if count != output.len() {
            // `TryRng<Error = Infallible>` cannot report this directly. Fill the
            // remainder only to satisfy the trait, then fail `consumed_exactly`.
            output[count..].fill(0);
            self.over_consumed = true;
        }
    }
}

impl TryRng for FixedRandom32 {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(
        &mut self,
        output: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        self.fill(output);
        Ok(())
    }
}

impl TryCryptoRng for FixedRandom32 {}

#[cfg(test)]
pub(crate) mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use sha2::{Digest, Sha256};

    /// Deterministic stream used only by tests. It is deliberately not exported
    /// from the crate's test build as a production default.
    pub(crate) struct TestRandom {
        seed: [u8; 32],
        counter: u64,
        block: [u8; 32],
        offset: usize,
    }

    impl TestRandom {
        pub(crate) fn new(seed: u8) -> Self {
            Self { seed: [seed; 32], counter: 0, block: [0; 32], offset: 32 }
        }

        fn fill(&mut self, mut output: &mut [u8]) {
            while !output.is_empty() {
                if self.offset == self.block.len() {
                    let mut hash = Sha256::new();
                    hash.update(self.seed);
                    hash.update(self.counter.to_be_bytes());
                    self.block.copy_from_slice(&hash.finalize());
                    self.counter = self.counter.wrapping_add(1);
                    self.offset = 0;
                }

                let count = output.len().min(self.block.len() - self.offset);
                let (head, tail) = output.split_at_mut(count);
                head.copy_from_slice(&self.block[self.offset..self.offset + count]);
                self.offset += count;
                output = tail;
            }
        }
    }

    impl TryRng for TestRandom {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut bytes = [0; 4];
            self.fill(&mut bytes);
            Ok(u32::from_le_bytes(bytes))
        }

        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut bytes = [0; 8];
            self.fill(&mut bytes);
            Ok(u64::from_le_bytes(bytes))
        }

        fn try_fill_bytes(
            &mut self,
            output: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            self.fill(output);
            Ok(())
        }
    }

    impl TryCryptoRng for TestRandom {}
}
