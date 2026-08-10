//! QEMU-only N3 acceptance component.
//!
//! Fixed identity material lives in the shared QEMU-only fixture module. The
//! image prints an explicit test-identity marker and must never be treated as
//! a provisioned SSH deployment.

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;

use vibeos_core::cap::{Cap, Rights};
use vibeos_core::random::{ChaCha20Random, EntropySource, RandomDomain, RandomLimits, SEED_BYTES};

use crate::ssh_security::{self, AuthorizedKeyPolicyService, HostSigningService};
use crate::ssh_test_fixture::{
    public_key_from_seed, REJECTED_CLIENT_SEED, TEST_CLIENT_SEED, TEST_PROFILE,
};
use crate::virtio_rng::{self, RandomBytes, RandomError};
use crate::world::Space;

const ENTROPY_RETRY_BUDGET: usize = 5_000;

struct OneSeed(Option<[u8; SEED_BYTES]>);

impl EntropySource for OneSeed {
    type Error = ();

    fn try_fill_seed(&mut self, seed: &mut [u8; SEED_BYTES]) -> Result<(), Self::Error> {
        let next = self.0.take().ok_or(())?;
        seed.copy_from_slice(&next);
        Ok(())
    }
}

pub async fn task(
    space: &'static Space,
    random: Cap,
    signer_read: Cap,
    signer_invoke: Cap,
    policy: Cap,
) {
    crate::println!("N3 SSH SECURITY TEST IDENTITY -- NOT FOR PRODUCTION");

    let entropy = match fetch_entropy(space, random).await {
        Ok(bytes) => bytes,
        Err(error) => fail(&alloc::format!("trusted entropy unavailable: {error}")),
    };
    let entropy_slice = entropy.as_slice();
    let first = &entropy_slice[..SEED_BYTES];
    let second = &entropy_slice[SEED_BYTES..];
    if first.iter().all(|byte| *byte == 0)
        || second.iter().all(|byte| *byte == 0)
        || first == second
    {
        fail("virtio-rng returned an all-zero or repeated 256-bit sample");
    }

    let mut seed = [0u8; SEED_BYTES];
    seed.copy_from_slice(first);
    let mut health_exchange_hash = [0u8; ssh_security::SSH_EXCHANGE_HASH_BYTES];
    health_exchange_hash.copy_from_slice(second);
    let limits = RandomLimits::new(32, 32).expect("test limits are within hard bounds");
    let mut kex = ChaCha20Random::new(
        OneSeed(Some(seed)),
        RandomDomain::new(0x5353_4801).expect("KEX domain is non-zero"),
        limits,
    )
    .unwrap_or_else(|error| fail(&alloc::format!("KEX DRBG seed failed: {error}")));
    let mut session = ChaCha20Random::new(
        OneSeed(Some(seed)),
        RandomDomain::new(0x5353_4802).expect("session domain is non-zero"),
        limits,
    )
    .unwrap_or_else(|error| fail(&alloc::format!("session DRBG seed failed: {error}")));
    wipe(&mut seed);
    let mut kex_bytes = [0u8; 32];
    let mut session_bytes = [0u8; 32];
    kex.try_fill_bytes(&mut kex_bytes)
        .unwrap_or_else(|error| fail(&alloc::format!("KEX DRBG failed: {error}")));
    session
        .try_fill_bytes(&mut session_bytes)
        .unwrap_or_else(|error| fail(&alloc::format!("session DRBG failed: {error}")));
    if kex_bytes == session_bytes {
        fail("distinct SSH random domains produced the same test block");
    }
    wipe(&mut kex_bytes);
    wipe(&mut session_bytes);
    drop(entropy);

    let signer_read_lease = space
        .0
        .lock()
        .lookup_lease::<HostSigningService>(signer_read, Rights::READ)
        .unwrap_or_else(|error| fail(&alloc::format!("host signer lookup failed: {error}")));
    let public = ssh_security::public_key_with(&signer_read_lease)
        .unwrap_or_else(|error| fail(&alloc::format!("host public-key read failed: {error}")));
    if ssh_security::sign_with(&signer_read_lease, &health_exchange_hash)
        != Err(ssh_security::HostSigningInvocationError::PermissionDenied)
    {
        fail("READ-only host signer capability unexpectedly authorized signing");
    }
    drop(signer_read_lease);

    let signer_invoke_lease = space
        .0
        .lock()
        .lookup_lease::<HostSigningService>(signer_invoke, Rights::INVOKE)
        .unwrap_or_else(|error| fail(&alloc::format!("host signer lookup failed: {error}")));
    if ssh_security::public_key_with(&signer_invoke_lease)
        != Err(ssh_security::HostSigningInvocationError::PermissionDenied)
    {
        fail("INVOKE-only host signer capability unexpectedly exposed the public key");
    }
    let signature = ssh_security::sign_with(&signer_invoke_lease, &health_exchange_hash)
        .unwrap_or_else(|error| fail(&alloc::format!("host signing failed: {error}")));
    wipe(&mut health_exchange_hash);
    if public.generation != signature.generation
        || signature.signature.as_bytes().iter().all(|byte| *byte == 0)
    {
        fail("host signer returned a stale generation or zero signature");
    }
    drop(signer_invoke_lease);

    let policy_lease = space
        .0
        .lock()
        .lookup_lease::<AuthorizedKeyPolicyService>(policy, Rights::READ)
        .unwrap_or_else(|error| fail(&alloc::format!("auth policy lookup failed: {error}")));
    let accepted =
        ssh_security::profile_for_with(&policy_lease, &public_key_from_seed(TEST_CLIENT_SEED))
            .unwrap_or_else(|error| fail(&alloc::format!("authorized-key lookup failed: {error}")));
    let rejected =
        ssh_security::profile_for_with(&policy_lease, &public_key_from_seed(REJECTED_CLIENT_SEED))
            .unwrap_or_else(|error| fail(&alloc::format!("rejected-key lookup failed: {error}")));
    let Some(accepted) = accepted else {
        fail("fixed authorized client key was denied");
    };
    if accepted.generation != public.generation
        || accepted.profile.get() != TEST_PROFILE
        || rejected.is_some()
    {
        fail("binary authorization decision did not match the immutable policy");
    }

    crate::println!("ssh-security virtio-rng PASS: bounded 64-byte transport sample");
    crate::println!("ssh-security DRBG PASS: distinct audited domain streams");
    let mut host_key_hex = String::with_capacity(64);
    for byte in public.public_key.as_bytes() {
        write!(&mut host_key_hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    crate::println!(
        "ssh-security signer PASS: generation {} host-key {}",
        public.generation.get(),
        host_key_hex
    );
    let mut health_marker = String::with_capacity(128);
    for byte in signature.signature.as_bytes() {
        write!(&mut health_marker, "{byte:02x}").expect("writing to a String cannot fail");
    }
    crate::println!("ssh-security freshness marker: {health_marker}");
    crate::println!(
        "ssh-security auth PASS: profile {} accepted, alternate key rejected",
        accepted.profile.get()
    );
    crate::println!("PASS ssh-security-test");
    crate::sbi::shutdown(false)
}

async fn fetch_entropy(space: &'static Space, random: Cap) -> Result<RandomBytes, RandomError> {
    for _ in 0..ENTROPY_RETRY_BUDGET {
        let lease = space
            .0
            .lock()
            .lookup_lease::<virtio_rng::RandomSource>(random, Rights::READ)
            .map_err(|_| RandomError::AuthorityRevoked)?;
        match virtio_rng::bytes_with(lease, SEED_BYTES * 2).await {
            Ok(bytes) => return Ok(bytes),
            Err(RandomError::Offline | RandomError::Busy | RandomError::DriverRestarted) => {
                crate::exec::sleep_ms(1).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(RandomError::TimedOut)
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn fail(reason: &str) -> ! {
    crate::println!("FAIL ssh-security-test: {reason}");
    crate::sbi::shutdown(true)
}
