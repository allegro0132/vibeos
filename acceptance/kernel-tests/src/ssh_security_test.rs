//! Portable assertions for the QEMU N3 SSH security acceptance image.
//!
//! The kernel supplies only the capability and device operations described by
//! [`Platform`]. Entropy-domain checks, signer-rights checks, and immutable
//! authorization-policy assertions remain board-neutral acceptance policy.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;

use vibeos_core::cap::{CSpace, Cap, Rights};
use vibeos_core::sync::SpinLock;
use vibeos_random::{ChaCha20Random, EntropySource, RandomDomain, RandomLimits, SEED_BYTES};
use vibeos_ssh_identity::{
    AuthorizedKeyPolicyService, AuthorizedProfile, HostPublicKeySnapshot, HostSignatureResult,
    HostSigningInvocationError, HostSigningService, SSH_EXCHANGE_HASH_BYTES,
};
use zeroize::Zeroize;

use crate::ssh_test_fixture::{
    public_key_from_seed, REJECTED_CLIENT_SEED, TEST_CLIENT_SEED, TEST_PROFILE,
};

pub type PlatformFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Owned entropy copied across the kernel/acceptance boundary and scrubbed on
/// ordinary drop. Kernel fault-domain reclamation retains its own arena scrub.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ()> {
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| ())?;
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Kernel entropy transport required by the portable N3 assertions. CSpace and
/// identity-service checks use their board-neutral capability APIs directly.
pub trait Platform: Sync {
    fn entropy<'a>(&'a self, length: usize) -> PlatformFuture<'a, Result<SecretBytes, ()>>;
    fn log(&self, args: fmt::Arguments<'_>);
}

/// Validated values published by the kernel adapter as machine-readable guest
/// acceptance evidence.
pub struct SecurityTestReport {
    pub public: HostPublicKeySnapshot,
    pub signature: HostSignatureResult,
    pub accepted: AuthorizedProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityTestError {
    TrustedEntropyUnavailable,
    InvalidEntropySample,
    KexDrbgSeedFailed,
    SessionDrbgSeedFailed,
    KexDrbgFailed,
    SessionDrbgFailed,
    RandomDomainsCollided,
    HostPublicKeyUnavailable,
    ReadCapabilityAuthorizedSigning,
    InvokeCapabilityExposedPublicKey,
    HostSigningFailed,
    StaleOrZeroSignature,
    AuthorizedKeyLookupFailed,
    RejectedKeyLookupFailed,
    AuthorizedClientDenied,
    AuthorizationPolicyMismatch,
}

impl fmt::Display for SecurityTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TrustedEntropyUnavailable => "trusted entropy unavailable",
            Self::InvalidEntropySample => {
                "virtio-rng returned an all-zero or repeated 256-bit sample"
            }
            Self::KexDrbgSeedFailed => "KEX DRBG seed failed",
            Self::SessionDrbgSeedFailed => "session DRBG seed failed",
            Self::KexDrbgFailed => "KEX DRBG failed",
            Self::SessionDrbgFailed => "session DRBG failed",
            Self::RandomDomainsCollided => {
                "distinct SSH random domains produced the same test block"
            }
            Self::HostPublicKeyUnavailable => "host public-key read failed",
            Self::ReadCapabilityAuthorizedSigning => {
                "READ-only host signer capability unexpectedly authorized signing"
            }
            Self::InvokeCapabilityExposedPublicKey => {
                "INVOKE-only host signer capability unexpectedly exposed the public key"
            }
            Self::HostSigningFailed => "host signing failed",
            Self::StaleOrZeroSignature => {
                "host signer returned a stale generation or zero signature"
            }
            Self::AuthorizedKeyLookupFailed => "authorized-key lookup failed",
            Self::RejectedKeyLookupFailed => "rejected-key lookup failed",
            Self::AuthorizedClientDenied => "fixed authorized client key was denied",
            Self::AuthorizationPolicyMismatch => {
                "binary authorization decision did not match the immutable policy"
            }
        })
    }
}

struct OneSeed(Option<[u8; SEED_BYTES]>);

impl EntropySource for OneSeed {
    type Error = ();

    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error> {
        let next = self.0.take().ok_or(())?;
        seed.copy_from_slice(&next);
        Ok(())
    }
}

/// Exercise real entropy transport through the platform and keep all portable
/// security-policy assertions outside the kernel crate.
pub async fn run(
    platform: &dyn Platform,
    cspace: &SpinLock<CSpace>,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) -> Result<SecurityTestReport, SecurityTestError> {
    let entropy = platform
        .entropy(SEED_BYTES * 2)
        .await
        .map_err(|_| SecurityTestError::TrustedEntropyUnavailable)?;
    let entropy_slice = entropy.as_slice();
    if entropy_slice.len() != SEED_BYTES * 2 {
        return Err(SecurityTestError::InvalidEntropySample);
    }
    let first = &entropy_slice[..SEED_BYTES];
    let second = &entropy_slice[SEED_BYTES..];
    if first.iter().all(|byte| *byte == 0)
        || second.iter().all(|byte| *byte == 0)
        || first == second
    {
        return Err(SecurityTestError::InvalidEntropySample);
    }

    let mut seed = [0u8; SEED_BYTES];
    seed.copy_from_slice(first);
    let mut health_exchange_hash = [0u8; SSH_EXCHANGE_HASH_BYTES];
    health_exchange_hash.copy_from_slice(second);
    let limits = RandomLimits::new(32, 32).expect("test limits are within hard bounds");
    let mut kex = ChaCha20Random::new(
        OneSeed(Some(seed)),
        RandomDomain::new(0x5353_4801).expect("KEX domain is non-zero"),
        limits,
    )
    .map_err(|_| SecurityTestError::KexDrbgSeedFailed)?;
    let mut session = ChaCha20Random::new(
        OneSeed(Some(seed)),
        RandomDomain::new(0x5353_4802).expect("session domain is non-zero"),
        limits,
    )
    .map_err(|_| SecurityTestError::SessionDrbgSeedFailed)?;
    wipe(&mut seed);
    let mut kex_bytes = [0u8; 32];
    let mut session_bytes = [0u8; 32];
    kex.try_fill_bytes(&mut kex_bytes)
        .map_err(|_| SecurityTestError::KexDrbgFailed)?;
    session
        .try_fill_bytes(&mut session_bytes)
        .map_err(|_| SecurityTestError::SessionDrbgFailed)?;
    if kex_bytes == session_bytes {
        wipe(&mut kex_bytes);
        wipe(&mut session_bytes);
        return Err(SecurityTestError::RandomDomainsCollided);
    }
    wipe(&mut kex_bytes);
    wipe(&mut session_bytes);
    drop(entropy);

    let signer_read_lease = cspace
        .lock()
        .lookup_lease::<HostSigningService>(signer_read, Rights::READ)
        .map_err(|_| SecurityTestError::HostPublicKeyUnavailable)?;
    let public = vibeos_ssh_identity::public_key_with(&signer_read_lease)
        .map_err(|_| SecurityTestError::HostPublicKeyUnavailable)?;
    if vibeos_ssh_identity::sign_with(&signer_read_lease, &health_exchange_hash)
        != Err(HostSigningInvocationError::PermissionDenied)
    {
        return Err(SecurityTestError::ReadCapabilityAuthorizedSigning);
    }
    drop(signer_read_lease);

    let signer_invoke_lease = cspace
        .lock()
        .lookup_lease::<HostSigningService>(signer_invoke, Rights::INVOKE)
        .map_err(|_| SecurityTestError::HostSigningFailed)?;
    if vibeos_ssh_identity::public_key_with(&signer_invoke_lease)
        != Err(HostSigningInvocationError::PermissionDenied)
    {
        return Err(SecurityTestError::InvokeCapabilityExposedPublicKey);
    }
    let signature = vibeos_ssh_identity::sign_with(&signer_invoke_lease, &health_exchange_hash)
        .map_err(|_| SecurityTestError::HostSigningFailed)?;
    wipe(&mut health_exchange_hash);
    if public.generation != signature.generation
        || signature.signature.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(SecurityTestError::StaleOrZeroSignature);
    }
    drop(signer_invoke_lease);

    let policy_lease = cspace
        .lock()
        .lookup_lease::<AuthorizedKeyPolicyService>(policy, Rights::READ)
        .map_err(|_| SecurityTestError::AuthorizedKeyLookupFailed)?;
    let accepted = vibeos_ssh_identity::profile_for_with(
        &policy_lease,
        &public_key_from_seed(TEST_CLIENT_SEED),
    )
    .map_err(|_| SecurityTestError::AuthorizedKeyLookupFailed)?;
    let rejected = vibeos_ssh_identity::profile_for_with(
        &policy_lease,
        &public_key_from_seed(REJECTED_CLIENT_SEED),
    )
    .map_err(|_| SecurityTestError::RejectedKeyLookupFailed)?;
    let Some(accepted) = accepted else {
        return Err(SecurityTestError::AuthorizedClientDenied);
    };
    if accepted.generation != public.generation
        || accepted.profile.get() != TEST_PROFILE
        || rejected.is_some()
    {
        return Err(SecurityTestError::AuthorizationPolicyMismatch);
    }

    Ok(SecurityTestReport {
        public,
        signature,
        accepted,
    })
}

/// Run the N3 contract and publish its stable guest-log evidence. The kernel
/// retains only UART transport and the final machine shutdown decision.
pub async fn run_and_report(
    platform: &dyn Platform,
    cspace: &SpinLock<CSpace>,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) -> bool {
    platform.log(format_args!(
        "N3 SSH SECURITY TEST IDENTITY -- NOT FOR PRODUCTION"
    ));
    let report = match run(platform, cspace, signer_read, signer_invoke, policy).await {
        Ok(report) => report,
        Err(error) => {
            platform.log(format_args!("FAIL ssh-security-test: {error}"));
            return false;
        }
    };

    platform.log(format_args!(
        "ssh-security virtio-rng PASS: bounded 64-byte transport sample"
    ));
    platform.log(format_args!(
        "ssh-security DRBG PASS: distinct audited domain streams"
    ));
    let mut host_key_hex = String::with_capacity(64);
    for byte in report.public.public_key.as_bytes() {
        write!(&mut host_key_hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    platform.log(format_args!(
        "ssh-security signer PASS: generation {} host-key {}",
        report.public.generation.get(),
        host_key_hex
    ));
    let mut health_marker = String::with_capacity(128);
    for byte in report.signature.signature.as_bytes() {
        write!(&mut health_marker, "{byte:02x}").expect("writing to a String cannot fail");
    }
    platform.log(format_args!(
        "ssh-security freshness marker: {health_marker}"
    ));
    platform.log(format_args!(
        "ssh-security auth PASS: profile {} accepted, alternate key rejected",
        report.accepted.profile.get()
    ));
    platform.log(format_args!("PASS ssh-security-test"));
    true
}

fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use vibeos_core::cap::{CSpace, Rights};
    use vibeos_core::sync::SpinLock;

    use super::{run, Platform, PlatformFuture, SecretBytes, TEST_PROFILE};
    use crate::ssh_test_fixture::provision;

    struct PassingPlatform;

    impl Platform for PassingPlatform {
        fn entropy<'a>(&'a self, length: usize) -> PlatformFuture<'a, Result<SecretBytes, ()>> {
            Box::pin(async move {
                let bytes: alloc::vec::Vec<u8> = (1..=length).map(|value| value as u8).collect();
                SecretBytes::try_from_slice(&bytes)
            })
        }

        fn log(&self, _args: core::fmt::Arguments<'_>) {}
    }

    fn complete<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the host acceptance mock unexpectedly yielded"),
        }
    }

    #[test]
    fn portable_security_runner_checks_the_complete_contract() {
        let resources = provision();
        let mut cspace = CSpace::new("ssh-security-host-test");
        let signer_read = cspace.mint(resources.signer.clone(), Rights::READ);
        let signer_invoke = cspace.mint(resources.signer, Rights::INVOKE);
        let policy = cspace.mint(resources.policy, Rights::READ);
        let cspace = SpinLock::new(cspace);
        let report = complete(run(
            &PassingPlatform,
            &cspace,
            signer_read,
            signer_invoke,
            policy,
        ))
        .unwrap();
        assert_eq!(report.public.generation.get(), 1);
        assert_eq!(report.signature.generation.get(), 1);
        assert_eq!(report.accepted.profile.get(), TEST_PROFILE);
    }
}
