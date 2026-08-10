//! Fixed identity and authorization material shared by the QEMU-only N3/N4
//! acceptance images.
//!
//! This module is never compiled into a normal image. Its deterministic host
//! seed exists only so acceptance can verify a stable OpenSSH fingerprint;
//! production SSH must provision a unique seed behind the signer service.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use vibeos_core::random::SEED_BYTES;
use vibeos_core::ssh_identity::{
    AuthorizedKeyEntry, CapabilityProfileId, HostSigner, ProvisionedHostSeed, SshEd25519PublicKey,
};

use crate::ssh_security::{AuthorizedKeyPolicyService, HostSigningService, SecurityGeneration};

const TEST_HOST_SEED: [u8; SEED_BYTES] = [0xa5; SEED_BYTES];
pub(crate) const TEST_HOST_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x29, 0xe5, 0x83, 0x3a, 0x91, 0x5a, 0x64, 0x29, 0xa4, 0xe3, 0xa7, 0x94, 0x84, 0x75, 0xc3, 0x38,
    0xef, 0x43, 0x6e, 0xb8, 0x2b, 0xe8, 0x9c, 0x92, 0xf0, 0x59, 0x70, 0x44, 0x03, 0xdb, 0x9d, 0x55,
];
pub(crate) const TEST_CLIENT_SEED: [u8; SEED_BYTES] = [0xb6; SEED_BYTES];
pub(crate) const REJECTED_CLIENT_SEED: [u8; SEED_BYTES] = [0xc7; SEED_BYTES];
pub(crate) const TEST_PROFILE: u32 = 1;

pub(crate) struct TestSecurityResources {
    pub(crate) signer: Arc<HostSigningService>,
    pub(crate) policy: Arc<AuthorizedKeyPolicyService>,
}

pub(crate) fn provision() -> TestSecurityResources {
    let _expected_host_public = test_host_public_key();
    let generation = SecurityGeneration::new(1).expect("test generation is non-zero");
    let host_seed = ProvisionedHostSeed::from_trusted_bytes(TEST_HOST_SEED)
        .expect("test host seed is an explicit non-zero fixture");
    let signer = HostSigningService::from_provisioned_seed(host_seed, generation)
        .expect("test host seed derives a strong Ed25519 identity");
    let entries: Box<[AuthorizedKeyEntry]> = Box::new([AuthorizedKeyEntry::new(
        public_key_from_seed(TEST_CLIENT_SEED),
        CapabilityProfileId::new(TEST_PROFILE).expect("test profile is non-zero"),
    )]);
    let policy = AuthorizedKeyPolicyService::new(entries, generation)
        .expect("the fixed binary test policy is valid");
    TestSecurityResources { signer, policy }
}

pub(crate) fn test_host_public_key() -> SshEd25519PublicKey {
    let public = public_key_from_seed(TEST_HOST_SEED);
    assert_eq!(
        public.as_bytes(),
        &TEST_HOST_PUBLIC_KEY_BYTES,
        "fixed SSH test host identity changed"
    );
    public
}

pub(crate) fn public_key_from_seed(seed: [u8; SEED_BYTES]) -> SshEd25519PublicKey {
    HostSigner::from_provisioned_seed(
        ProvisionedHostSeed::from_trusted_bytes(seed).expect("test identity seed is non-zero"),
    )
    .expect("test identity seed derives a strong Ed25519 identity")
    .public_key()
}
