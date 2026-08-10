//! Host tests for the minimal SSH identity and binary authorization boundary.
//!
//! The module is included by path until `vibeos-core` wires the implementation
//! into `lib.rs`. Including it here also makes the explicitly test-only signer
//! available under this integration test crate's `cfg(test)`.

#[path = "../src/ssh_identity.rs"]
mod ssh_identity;

use core::mem;

use ed25519_dalek::{Signature, VerifyingKey};
use ssh_identity::{
    AuthorizedKeyEntry, AuthorizedKeyPolicy, AuthorizedKeyPolicyError, CapabilityProfileId,
    DeterministicTestHostSigner, HostSigner, ProvisionedHostSeed, ProvisionedHostSeedError,
    PublicKeyError, SshEd25519PublicKey, ED25519_PRIVATE_SEED_BYTES, SSH_ED25519_PUBLIC_KEY_BYTES,
    SSH_ED25519_SIGNATURE_BYTES,
};

const RFC8032_PUBLIC_KEY: [u8; SSH_ED25519_PUBLIC_KEY_BYTES] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const RFC8032_SIGNATURE: [u8; SSH_ED25519_SIGNATURE_BYTES] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

fn public_key_from_seed(fill: u8) -> SshEd25519PublicKey {
    let seed = ProvisionedHostSeed::from_trusted_bytes([fill; ED25519_PRIVATE_SEED_BYTES]).unwrap();
    HostSigner::from_provisioned_seed(seed)
        .unwrap()
        .public_key()
}

#[test]
fn public_key_boundary_requires_an_exact_valid_strong_key() {
    let key = SshEd25519PublicKey::try_from(RFC8032_PUBLIC_KEY.as_slice()).unwrap();
    assert_eq!(key.as_bytes(), &RFC8032_PUBLIC_KEY);
    assert_eq!(key.to_bytes(), RFC8032_PUBLIC_KEY);

    assert_eq!(
        SshEd25519PublicKey::try_from(&RFC8032_PUBLIC_KEY[..31]),
        Err(PublicKeyError::WrongLength { actual: 31 })
    );

    let mut long = [0u8; SSH_ED25519_PUBLIC_KEY_BYTES + 1];
    long[..SSH_ED25519_PUBLIC_KEY_BYTES].copy_from_slice(&RFC8032_PUBLIC_KEY);
    assert_eq!(
        SshEd25519PublicKey::try_from(long.as_slice()),
        Err(PublicKeyError::WrongLength { actual: 33 })
    );

    let mut identity_point = [0u8; SSH_ED25519_PUBLIC_KEY_BYTES];
    identity_point[0] = 1;
    assert_eq!(
        SshEd25519PublicKey::from_bytes(identity_point),
        Err(PublicKeyError::WeakKey)
    );

    assert_eq!(
        SshEd25519PublicKey::from_bytes([0x02; SSH_ED25519_PUBLIC_KEY_BYTES]),
        Err(PublicKeyError::InvalidEncoding)
    );
}

#[test]
fn profile_ids_are_nonzero() {
    assert_eq!(CapabilityProfileId::new(0), None);
    let profile = CapabilityProfileId::new(17).unwrap();
    assert_eq!(profile.get(), 17);
}

#[test]
fn immutable_binary_policy_selects_only_an_exact_key() {
    let first_key = public_key_from_seed(0x11);
    let second_key = public_key_from_seed(0x22);
    let absent_key = public_key_from_seed(0x33);
    let first_profile = CapabilityProfileId::new(7).unwrap();
    let second_profile = CapabilityProfileId::new(9).unwrap();
    let entries = [
        AuthorizedKeyEntry::new(first_key, first_profile),
        AuthorizedKeyEntry::new(second_key, second_profile),
    ];
    let policy = AuthorizedKeyPolicy::new(&entries).unwrap();

    assert_eq!(policy.len(), 2);
    assert!(!policy.is_empty());
    assert_eq!(entries[0].key(), first_key);
    assert_eq!(entries[1].profile(), second_profile);
    assert_eq!(policy.profile_for(&first_key), Some(first_profile));
    assert_eq!(policy.profile_for(&second_key), Some(second_profile));
    assert_eq!(policy.profile_for(&absent_key), None);

    let present = policy.profile_for_ct(&first_key);
    assert_eq!(present.is_some().unwrap_u8(), 1);
    assert_eq!(present.unwrap(), first_profile);
    assert_eq!(policy.profile_for_ct(&absent_key).is_none().unwrap_u8(), 1);
}

#[test]
fn empty_policy_denies_and_duplicate_keys_fail_provisioning() {
    let empty = AuthorizedKeyPolicy::new(&[]).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.profile_for(&public_key_from_seed(0x44)), None);

    let key = public_key_from_seed(0x55);
    let entries = [
        AuthorizedKeyEntry::new(key, CapabilityProfileId::new(1).unwrap()),
        AuthorizedKeyEntry::new(key, CapabilityProfileId::new(2).unwrap()),
    ];
    assert!(matches!(
        AuthorizedKeyPolicy::new(&entries),
        Err(AuthorizedKeyPolicyError::DuplicateKey {
            first: 0,
            second: 1
        })
    ));
}

#[test]
fn production_seed_boundary_rejects_unprovisioned_sentinel_and_zeroizes() {
    assert!(matches!(
        ProvisionedHostSeed::from_trusted_bytes([0u8; ED25519_PRIVATE_SEED_BYTES]),
        Err(ProvisionedHostSeedError::AllZero)
    ));
    assert!(mem::needs_drop::<ProvisionedHostSeed>());
    assert!(mem::needs_drop::<HostSigner>());
}

#[test]
fn production_signer_exposes_only_public_material_and_signing() {
    let seed = ProvisionedHostSeed::from_trusted_bytes([0xa5; ED25519_PRIVATE_SEED_BYTES]).unwrap();
    let signer = HostSigner::from_provisioned_seed(seed).unwrap();
    let message = b"vibeos ssh exchange hash";
    let signature = signer.sign(message);

    let verifying_key = VerifyingKey::from_bytes(signer.public_key().as_bytes()).unwrap();
    let signature = Signature::from_bytes(signature.as_bytes());
    assert!(verifying_key.verify_strict(message, &signature).is_ok());
    assert!(verifying_key
        .verify_strict(b"different exchange hash", &signature)
        .is_err());
}

#[test]
fn explicitly_test_only_signer_matches_rfc8032_vector_one() {
    let signer = DeterministicTestHostSigner::rfc8032_test_fixture();
    assert_eq!(signer.public_key().as_bytes(), &RFC8032_PUBLIC_KEY);
    assert_eq!(signer.sign(b"").to_bytes(), RFC8032_SIGNATURE);

    // This concrete type is intentionally not `HostSigner`; production-only
    // service constructors should require `HostSigner` exactly.
    fn accepts_test_fixture(_: &DeterministicTestHostSigner) {}
    accepts_test_fixture(&signer);
}
