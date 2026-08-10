//! Capability boundaries for the minimal SSH server's long-lived secrets.
//!
//! This module does not parse OpenSSH text, usernames, paths, or configuration
//! files. Bootstrap provisions an opaque Ed25519 signer and an immutable table
//! of exact binary public keys. Components can then receive separately scoped
//! capabilities for public-key discovery, host signing, and authorization.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt;
use core::num::NonZeroU64;

use vibeos_core::cap::{InvocationLease, Resource, Rights};
use vibeos_core::ssh_identity::{
    AuthorizedKeyEntry, AuthorizedKeyPolicy,
    AuthorizedKeyPolicyError as CoreAuthorizedKeyPolicyError, CapabilityProfileId, HostSigner,
    HostSignerError, ProvisionedHostSeed, SshEd25519PublicKey, SshEd25519Signature,
};

/// Exact SHA-256 exchange-hash size for the sole acceptance key-exchange profile.
/// A future SHA-512 profile must introduce a distinct typed operation instead
/// of widening this signing boundary.
pub const SSH_EXCHANGE_HASH_BYTES: usize = 32;

/// Maximum number of exact binary client keys in one provisioned policy.
///
/// Provisioning is trusted, but a fixed bound keeps the full-scan lookup and
/// duplicate validation predictable in the no-std kernel.
pub const MAX_AUTHORIZED_KEY_ENTRIES: usize = 32;

/// Non-zero incarnation of provisioned SSH security material.
///
/// Bootstrap chooses the value and must advance it whenever the signer or
/// authorized-key table is replaced. Returning it with security decisions
/// lets the session layer reject results from a superseded service instance.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityGeneration(NonZeroU64);

impl SecurityGeneration {
    /// Construct a generation. Zero is the fail-closed "not provisioned"
    /// sentinel and therefore has no representable value.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the non-zero numeric generation.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Public host identity observed under READ authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPublicKeySnapshot {
    pub generation: SecurityGeneration,
    pub public_key: SshEd25519PublicKey,
}

/// Host signature produced under INVOKE authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSignatureResult {
    pub generation: SecurityGeneration,
    pub signature: SshEd25519Signature,
}

/// Errors at the host-signing capability boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSigningInvocationError {
    PermissionDenied,
}

impl fmt::Display for HostSigningInvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => f.write_str("host-signing capability lacks required rights"),
        }
    }
}

/// Opaque capability resource holding the SSH server's Ed25519 signer.
///
/// The resource deliberately exposes neither its seed nor its `HostSigner`.
/// The only private-key operation is the bounded [`sign_with`] invocation.
/// The type is neither `Clone` nor `Debug`; sharing occurs only through the
/// `Arc` installed in capability spaces.
pub struct HostSigningService {
    signer: HostSigner,
    generation: SecurityGeneration,
}

impl HostSigningService {
    /// Wrap an already-provisioned signer for bootstrap installation.
    pub fn new(signer: HostSigner, generation: SecurityGeneration) -> Arc<Self> {
        Arc::new(Self { signer, generation })
    }

    /// Consume an opaque production or explicitly-marked test seed at the
    /// provisioning boundary, then erase its temporary owned copy through the
    /// core `HostSigner` constructor.
    pub fn from_provisioned_seed(
        seed: ProvisionedHostSeed,
        generation: SecurityGeneration,
    ) -> Result<Arc<Self>, HostSignerError> {
        HostSigner::from_provisioned_seed(seed).map(|signer| Self::new(signer, generation))
    }

    fn public_key_snapshot(&self) -> HostPublicKeySnapshot {
        HostPublicKeySnapshot {
            generation: self.generation,
            public_key: self.signer.public_key(),
        }
    }

    fn sign(&self, input: &[u8]) -> HostSignatureResult {
        HostSignatureResult {
            generation: self.generation,
            signature: self.signer.sign(input),
        }
    }
}

impl Resource for HostSigningService {
    fn kind(&self) -> &'static str {
        "ssh-host-signing"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Read the public host key. This operation never exposes seed or signing-key
/// bytes and requires READ independently of signing authority.
pub fn public_key_with(
    lease: &InvocationLease<HostSigningService>,
) -> Result<HostPublicKeySnapshot, HostSigningInvocationError> {
    if !lease.authorizes(Rights::READ) {
        return Err(HostSigningInvocationError::PermissionDenied);
    }
    Ok(lease.with(HostSigningService::public_key_snapshot))
}

/// Sign one exact SHA-256 SSH exchange hash.
///
/// The SSH transport remains responsible for framing and algorithm policy;
/// the fixed-size type prevents accidental widening to arbitrary short
/// messages and requires INVOKE. In particular, READ authority over the public
/// key does not confer signing authority.
pub fn sign_with(
    lease: &InvocationLease<HostSigningService>,
    exchange_hash: &[u8; SSH_EXCHANGE_HASH_BYTES],
) -> Result<HostSignatureResult, HostSigningInvocationError> {
    if !lease.authorizes(Rights::INVOKE) {
        return Err(HostSigningInvocationError::PermissionDenied);
    }
    Ok(lease.with(|service| service.sign(exchange_hash)))
}

/// A successful exact-key authorization decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizedProfile {
    pub generation: SecurityGeneration,
    pub profile: CapabilityProfileId,
}

/// Provisioning failures for the immutable binary authorized-key table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizedKeyProvisionError {
    TooManyEntries { actual: usize },
    DuplicateKey { first: usize, second: usize },
}

impl From<CoreAuthorizedKeyPolicyError> for AuthorizedKeyProvisionError {
    fn from(error: CoreAuthorizedKeyPolicyError) -> Self {
        match error {
            CoreAuthorizedKeyPolicyError::DuplicateKey { first, second } => {
                Self::DuplicateKey { first, second }
            }
        }
    }
}

impl fmt::Display for AuthorizedKeyProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { actual } => write!(
                f,
                "authorized-key policy has {actual} entries, maximum is {MAX_AUTHORIZED_KEY_ENTRIES}"
            ),
            Self::DuplicateKey { first, second } => write!(
                f,
                "authorized-key entries {first} and {second} contain the same binary key"
            ),
        }
    }
}

/// Errors at the authorized-key lookup capability boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizedKeyLookupError {
    PermissionDenied,
    InvalidProvisionedPolicy,
}

impl fmt::Display for AuthorizedKeyLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionDenied => "authorized-key capability lacks READ authority",
            Self::InvalidProvisionedPolicy => "authorized-key policy failed closed validation",
        })
    }
}

/// Immutable exact-binary-key to capability-profile policy.
///
/// Entries are validated before publication and thereafter owned behind a
/// private boxed slice. There is no runtime `authorized_keys` text parser and
/// no getter that exposes or mutates the complete policy table.
pub struct AuthorizedKeyPolicyService {
    entries: Box<[AuthorizedKeyEntry]>,
    generation: SecurityGeneration,
}

impl AuthorizedKeyPolicyService {
    /// Validate and consume a fixed policy table. An empty table is a valid
    /// deny-all policy; duplicate keys and oversized tables are rejected.
    pub fn new(
        entries: Box<[AuthorizedKeyEntry]>,
        generation: SecurityGeneration,
    ) -> Result<Arc<Self>, AuthorizedKeyProvisionError> {
        if entries.len() > MAX_AUTHORIZED_KEY_ENTRIES {
            return Err(AuthorizedKeyProvisionError::TooManyEntries {
                actual: entries.len(),
            });
        }
        AuthorizedKeyPolicy::new(&entries).map_err(AuthorizedKeyProvisionError::from)?;
        Ok(Arc::new(Self {
            entries,
            generation,
        }))
    }

    fn profile_for(
        &self,
        candidate: &SshEd25519PublicKey,
    ) -> Result<Option<AuthorizedProfile>, AuthorizedKeyLookupError> {
        // Revalidate before every security decision. The table is immutable,
        // so failure is unreachable through safe code; treating it as a
        // recoverable denial keeps corruption fail-closed instead of granting.
        let policy = AuthorizedKeyPolicy::new(&self.entries)
            .map_err(|_| AuthorizedKeyLookupError::InvalidProvisionedPolicy)?;
        Ok(policy
            .profile_for(candidate)
            .map(|profile| AuthorizedProfile {
                generation: self.generation,
                profile,
            }))
    }
}

impl Resource for AuthorizedKeyPolicyService {
    fn kind(&self) -> &'static str {
        "ssh-authorized-key-policy"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Resolve one exact 32-byte `ssh-ed25519` key under READ authority.
///
/// The core policy scans the whole bounded table using its constant-time key
/// comparison and selection primitives. Usernames and textual key encodings
/// are deliberately absent from this boundary.
pub fn profile_for_with(
    lease: &InvocationLease<AuthorizedKeyPolicyService>,
    candidate: &SshEd25519PublicKey,
) -> Result<Option<AuthorizedProfile>, AuthorizedKeyLookupError> {
    if !lease.authorizes(Rights::READ) {
        return Err(AuthorizedKeyLookupError::PermissionDenied);
    }
    lease.with(|service| service.profile_for(candidate))
}
