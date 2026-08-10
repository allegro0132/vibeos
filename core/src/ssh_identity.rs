//! Minimal SSH Ed25519 identity and binary authorized-key policy.
//!
//! This module deliberately stops below SSH wire framing. An
//! [`SshEd25519PublicKey`] is exactly the 32-byte public-key payload associated
//! with the `ssh-ed25519` algorithm name; it is not an OpenSSH text line, a
//! base64 value, or the outer SSH `string` encoding. Authorized keys are
//! provisioned as an immutable binary table, so authentication never consults
//! a pathname or parses comments and options at run time.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte length of the public-key payload for SSH's `ssh-ed25519` algorithm.
pub const SSH_ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Byte length of an Ed25519 signature inside an SSH signature blob.
pub const SSH_ED25519_SIGNATURE_BYTES: usize = 64;

/// Byte length of the seed from which an Ed25519 signing key is derived.
pub const ED25519_PRIVATE_SEED_BYTES: usize = 32;

const _: () = {
    assert!(ed25519_dalek::PUBLIC_KEY_LENGTH == SSH_ED25519_PUBLIC_KEY_BYTES);
    assert!(ed25519_dalek::SIGNATURE_LENGTH == SSH_ED25519_SIGNATURE_BYTES);
    assert!(ed25519_dalek::SECRET_KEY_LENGTH == ED25519_PRIVATE_SEED_BYTES);
};

/// Errors accepted at the binary public-key boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyError {
    /// The SSH key payload was not exactly 32 bytes.
    WrongLength { actual: usize },
    /// The 32 bytes do not encode a point accepted by `ed25519-dalek`.
    InvalidEncoding,
    /// Low-order Ed25519 public keys are never valid authentication identities.
    WeakKey,
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { actual } => write!(
                f,
                "ssh-ed25519 public key is {actual} bytes, expected {SSH_ED25519_PUBLIC_KEY_BYTES}"
            ),
            Self::InvalidEncoding => f.write_str("invalid ssh-ed25519 public-key encoding"),
            Self::WeakKey => f.write_str("weak ssh-ed25519 public key is not authorizable"),
        }
    }
}

/// Exact binary public-key payload for the SSH `ssh-ed25519` algorithm.
///
/// Construction validates the Ed25519 point and rejects low-order keys. The
/// type intentionally does not implement `Hash` or ordering: the authorized
/// policy below performs fixed-size comparisons with [`ConstantTimeEq`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct SshEd25519PublicKey([u8; SSH_ED25519_PUBLIC_KEY_BYTES]);

impl SshEd25519PublicKey {
    /// Validate one exact 32-byte Ed25519 public-key payload.
    pub fn from_bytes(bytes: [u8; SSH_ED25519_PUBLIC_KEY_BYTES]) -> Result<Self, PublicKeyError> {
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| PublicKeyError::InvalidEncoding)?;
        if verifying_key.is_weak() {
            return Err(PublicKeyError::WeakKey);
        }
        Ok(Self(verifying_key.to_bytes()))
    }

    /// Borrow the exact 32-byte SSH public-key payload.
    pub const fn as_bytes(&self) -> &[u8; SSH_ED25519_PUBLIC_KEY_BYTES] {
        &self.0
    }

    /// Copy out the exact 32-byte SSH public-key payload.
    pub const fn to_bytes(self) -> [u8; SSH_ED25519_PUBLIC_KEY_BYTES] {
        self.0
    }

    fn from_validated_verifying_key(verifying_key: VerifyingKey) -> Self {
        debug_assert!(!verifying_key.is_weak());
        Self(verifying_key.to_bytes())
    }
}

impl TryFrom<&[u8]> for SshEd25519PublicKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let exact: [u8; SSH_ED25519_PUBLIC_KEY_BYTES] =
            bytes.try_into().map_err(|_| PublicKeyError::WrongLength {
                actual: bytes.len(),
            })?;
        Self::from_bytes(exact)
    }
}

impl TryFrom<[u8; SSH_ED25519_PUBLIC_KEY_BYTES]> for SshEd25519PublicKey {
    type Error = PublicKeyError;

    fn try_from(bytes: [u8; SSH_ED25519_PUBLIC_KEY_BYTES]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl ConstantTimeEq for SshEd25519PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SshEd25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for SshEd25519PublicKey {}

/// Stable identifier of one immutable, predeclared capability profile.
///
/// Zero is reserved as the internal no-match sentinel. The profile itself is
/// resolved by the session factory; an SSH username is not authority.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityProfileId(u32);

impl CapabilityProfileId {
    const NO_MATCH_PLACEHOLDER: Self = Self(1);

    /// Construct a non-zero profile identifier.
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return the stable non-zero numeric identifier.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl ConditionallySelectable for CapabilityProfileId {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Both operands obey the non-zero invariant, so selection preserves it.
        Self(u32::conditional_select(&a.0, &b.0, choice))
    }
}

/// One provisioned exact-key to capability-profile mapping.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizedKeyEntry {
    key: SshEd25519PublicKey,
    profile: CapabilityProfileId,
}

impl AuthorizedKeyEntry {
    /// Construct one immutable authorization entry.
    pub const fn new(key: SshEd25519PublicKey, profile: CapabilityProfileId) -> Self {
        Self { key, profile }
    }

    /// Return the exact binary key stored in this entry.
    pub const fn key(&self) -> SshEd25519PublicKey {
        self.key
    }

    /// Return the capability profile selected by this entry.
    pub const fn profile(&self) -> CapabilityProfileId {
        self.profile
    }
}

/// Provisioning errors for an immutable authorized-key policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizedKeyPolicyError {
    /// One binary key was assigned more than once, making selection ambiguous.
    DuplicateKey { first: usize, second: usize },
}

impl fmt::Display for AuthorizedKeyPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey { first, second } => {
                write!(
                    f,
                    "authorized key entries {first} and {second} are duplicates"
                )
            }
        }
    }
}

/// Borrowed, immutable binary authorized-key policy.
///
/// The policy allocates nothing and contains no parser. Rust's shared borrow
/// prevents safe mutation of the backing entries for the policy's lifetime.
/// Construction rejects duplicate keys before the table is published.
pub struct AuthorizedKeyPolicy<'a> {
    entries: &'a [AuthorizedKeyEntry],
}

impl<'a> AuthorizedKeyPolicy<'a> {
    /// Validate and borrow an immutable table. An empty table is a valid
    /// deny-all policy.
    pub fn new(entries: &'a [AuthorizedKeyEntry]) -> Result<Self, AuthorizedKeyPolicyError> {
        for first in 0..entries.len() {
            for second in (first + 1)..entries.len() {
                if bool::from(entries[first].key.ct_eq(&entries[second].key)) {
                    return Err(AuthorizedKeyPolicyError::DuplicateKey { first, second });
                }
            }
        }
        Ok(Self { entries })
    }

    /// Number of provisioned exact-key mappings.
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this is the valid deny-all policy.
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Scan every entry and select the profile for one exact public key.
    ///
    /// Every comparison covers the same 32 bytes with `subtle::ConstantTimeEq`,
    /// the scan never exits early, and profile selection uses
    /// `ConditionallySelectable`. Runtime still reveals the provisioned table
    /// length, and whole-system timing depends on compiler, target, and caller;
    /// this is therefore a content-independent best-effort lookup, not a claim
    /// of universal constant-time execution.
    pub fn profile_for_ct(&self, candidate: &SshEd25519PublicKey) -> CtOption<CapabilityProfileId> {
        let mut found = Choice::from(0u8);
        let mut selected = CapabilityProfileId::NO_MATCH_PLACEHOLDER;

        for entry in self.entries {
            let matches = candidate.ct_eq(&entry.key);
            let first_match = matches & !found;
            selected.conditional_assign(&entry.profile, first_match);
            found |= matches;
        }

        CtOption::new(selected, found)
    }

    /// Return the selected profile after a full content-independent scan.
    ///
    /// Turning [`CtOption`] into [`Option`] necessarily reveals the final
    /// authorization decision; call [`Self::profile_for_ct`] when that decision
    /// must remain inside additional constant-time processing.
    pub fn profile_for(&self, candidate: &SshEd25519PublicKey) -> Option<CapabilityProfileId> {
        Option::from(self.profile_for_ct(candidate))
    }
}

/// Exact 64-byte Ed25519 result to place inside an SSH signature blob.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SshEd25519Signature([u8; SSH_ED25519_SIGNATURE_BYTES]);

impl SshEd25519Signature {
    /// Borrow the exact 64-byte Ed25519 signature payload.
    pub const fn as_bytes(&self) -> &[u8; SSH_ED25519_SIGNATURE_BYTES] {
        &self.0
    }

    /// Copy out the exact 64-byte Ed25519 signature payload.
    pub const fn to_bytes(self) -> [u8; SSH_ED25519_SIGNATURE_BYTES] {
        self.0
    }
}

/// Rejected values at the trusted host-seed provisioning boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionedHostSeedError {
    /// A zero seed is an obvious unprovisioned sentinel, not a host identity.
    AllZero,
}

impl fmt::Display for ProvisionedHostSeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllZero => f.write_str("all-zero Ed25519 host seed is not provisioned"),
        }
    }
}

// RFC 8032, section 7.1, test vector 1. This is public test data, not a secret.
#[cfg(test)]
const RFC8032_TEST_FIXTURE_SEED: [u8; ED25519_PRIVATE_SEED_BYTES] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Opaque, single-owner seed accepted by the production host signer.
///
/// The constructor cannot prove entropy provenance. Its caller must obtain the
/// bytes from authenticated persistent provisioning or a trusted, fallible
/// random-source capability. This wrapper prevents subsequent reads through
/// its API and zeroizes its owned copy on drop; upstream copies remain the
/// provisioner's responsibility.
pub struct ProvisionedHostSeed {
    bytes: [u8; ED25519_PRIVATE_SEED_BYTES],
}

impl ProvisionedHostSeed {
    /// Cross the trusted provisioning boundary with one owned seed.
    pub fn from_trusted_bytes(
        bytes: [u8; ED25519_PRIVATE_SEED_BYTES],
    ) -> Result<Self, ProvisionedHostSeedError> {
        if bool::from(bytes.ct_eq(&[0u8; ED25519_PRIVATE_SEED_BYTES])) {
            return Err(ProvisionedHostSeedError::AllZero);
        }
        Ok(Self { bytes })
    }
}

impl Drop for ProvisionedHostSeed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for ProvisionedHostSeed {}

/// Error constructing a production host signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSignerError {
    /// The seed derived a low-order public key and is unusable as an identity.
    WeakDerivedPublicKey,
}

impl fmt::Display for HostSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakDerivedPublicKey => {
                f.write_str("Ed25519 host seed derived a weak public key")
            }
        }
    }
}

struct SignerCore {
    // `ed25519-dalek` must be built with its `zeroize` feature so this field is
    // zeroized on drop. It is intentionally never returned or borrowed.
    signing_key: SigningKey,
    public_key: SshEd25519PublicKey,
}

impl SignerCore {
    fn from_seed(seed: &[u8; ED25519_PRIVATE_SEED_BYTES]) -> Result<Self, HostSignerError> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        if verifying_key.is_weak() {
            return Err(HostSignerError::WeakDerivedPublicKey);
        }
        Ok(Self {
            signing_key,
            public_key: SshEd25519PublicKey::from_validated_verifying_key(verifying_key),
        })
    }

    fn public_key(&self) -> SshEd25519PublicKey {
        self.public_key
    }

    fn sign(&self, message: &[u8]) -> SshEd25519Signature {
        SshEd25519Signature(self.signing_key.sign(message).to_bytes())
    }
}

/// Production Ed25519 host-signing boundary.
///
/// The private seed and `ed25519-dalek::SigningKey` remain private. The public
/// API exposes only the public key and signing operation after construction;
/// the type is deliberately neither `Clone` nor `Debug`.
pub struct HostSigner {
    core: SignerCore,
}

impl HostSigner {
    /// Consume an opaque provisioned seed and derive the production identity.
    pub fn from_provisioned_seed(seed: ProvisionedHostSeed) -> Result<Self, HostSignerError> {
        let core = SignerCore::from_seed(&seed.bytes)?;
        // Erase the provisioning wrapper as soon as the zeroizing SigningKey
        // owns the seed, rather than retaining two live copies in this scope.
        drop(seed);
        Ok(Self { core })
    }

    /// Return the exact binary public host key.
    pub fn public_key(&self) -> SshEd25519PublicKey {
        self.core.public_key()
    }

    /// Sign an already-framed SSH exchange-hash message without exposing key
    /// material.
    pub fn sign(&self, message: &[u8]) -> SshEd25519Signature {
        self.core.sign(message)
    }
}

/// Deterministic public test identity, absent from non-test builds.
///
/// This is a distinct type rather than a `HostSigner`, so code that requires a
/// production signer cannot receive the fixture accidentally. The constructor
/// and its RFC seed do not exist when `cfg(test)` is false.
#[cfg(test)]
pub struct DeterministicTestHostSigner {
    core: SignerCore,
}

#[cfg(test)]
impl DeterministicTestHostSigner {
    /// Construct RFC 8032 section 7.1 test vector 1.
    pub fn rfc8032_test_fixture() -> Self {
        let core = SignerCore::from_seed(&RFC8032_TEST_FIXTURE_SEED)
            .expect("RFC 8032 fixture must derive a strong public key");
        Self { core }
    }

    /// Return the fixture's exact binary public host key.
    pub fn public_key(&self) -> SshEd25519PublicKey {
        self.core.public_key()
    }

    /// Sign with the deterministic test identity.
    pub fn sign(&self, message: &[u8]) -> SshEd25519Signature {
        self.core.sign(message)
    }
}
