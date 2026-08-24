//! Authenticated operator admission for canonical Component artifacts.
//!
//! The configured operator policy is independent of durable artifact bytes.
//! Detached evidence carries a complete Ed25519 public key and signature; no
//! key identifier, hash lookup, namespace lookup, or development-pin fallback
//! exists on this path. Successful verification produces a boot-local,
//! move-only wrapper which remains inert until consumed by
//! [`admit_authenticated`].

use core::{cmp::Ordering, fmt};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use vibeos_component_format::{
    ComponentArtifactAuthenticationAlgorithm, ComponentArtifactAuthenticationEvidenceV1,
    ComponentArtifactCommitment, ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind,
    ComponentArtifactInterfaceDirection, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyKind, ComponentArtifactV1, ProfileIdentity, ProfileStage,
    COMPONENT_ARTIFACT_AUTHENTICATION_VERSION, COMPONENT_ARTIFACT_FORMAT_VERSION,
    COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION, PROFILE_1_LIMITS,
};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::world::{
    EntityShape, FunctionEffect, FunctionShape, NamedCaseShape, NamedEntityShape, NamedValueShape,
    TypeShape, ValueShape, WorldContract,
};

use crate::{
    admit_under_exact_rules_with_current_engine, canonical_entity_shape_text_v1, private,
    valid_argument_limits, valid_entrypoint, valid_manifest_text, valid_name,
    validate_policy_tables, AdmissionError, AdmittedComponent, CallerAuthority, CommandStreamMode,
    ComponentArtifact, ComponentIdentity, CurrentValidationEngine, ExactAdmissionRules,
    InstanceLimits, InterfaceCeiling,
};

/// Frozen canonical operator-policy format version.
pub const COMPONENT_ARTIFACT_OPERATOR_POLICY_VERSION: u16 = 1;
/// Frozen signature-transcript format version.
pub const COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_VERSION: u16 = 1;
/// Exact byte length of the C7.3 signature transcript.
pub const COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN: usize = 192;
/// Maximum number of complete operator-role public keys in one policy.
pub const MAX_COMPONENT_ARTIFACT_OPERATOR_SIGNERS: usize = 32;
/// Exact per-source bound frozen by the canonical artifact-v1 format.
pub const MAX_COMPONENT_ARTIFACT_OPERATOR_WIT_SOURCE_BYTES: usize = 256 * 1024;

const OPERATOR_POLICY_DOMAIN: &[u8] = b"vibeos.component-artifact.operator-policy.v1\0";
const SIGNATURE_DOMAIN: &[u8; 48] = b"vibeos.component-artifact.operator-admission.v1\0";
const TRANSCRIPT_ED25519_ALGORITHM: u16 = 1;
const OPERATOR_TRUST_MODE: u8 = 2;

/// Independent semantic identity of the operator signing role.
///
/// This is not an SSH principal, a key identifier, a durable object ID, or a
/// lookup handle. It is committed together with the complete key table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperatorRoleIdentity([u8; 32]);

impl OperatorRoleIdentity {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ArtifactAuthenticationError> {
        if bytes == [0; 32] {
            return Err(ArtifactAuthenticationError::InvalidOperatorRole);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OperatorRoleIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorRoleIdentity(<redacted>)")
    }
}

/// Exact state of one complete operator-role public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OperatorSignerStatus {
    Active = 1,
    Revoked = 2,
}

/// One independently configured, complete operator-role Ed25519 key.
///
/// Construction performs point decoding, canonical recompression, and weak
/// key rejection before the key can enter a trusted policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperatorSignerV1 {
    public_key: [u8; 32],
    status: OperatorSignerStatus,
}

impl OperatorSignerV1 {
    pub fn new(
        public_key: [u8; 32],
        status: OperatorSignerStatus,
    ) -> Result<Self, ArtifactAuthenticationError> {
        validate_operator_public_key(public_key)?;
        Ok(Self { public_key, status })
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub const fn status(&self) -> OperatorSignerStatus {
        self.status
    }
}

impl fmt::Debug for OperatorSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorSignerV1")
            .field("public_key", &"<redacted>")
            .field("status", &self.status)
            .finish()
    }
}

/// SHA-256 commitment to the complete canonical operator admission policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OperatorArtifactPolicyCommitment([u8; 32]);

impl OperatorArtifactPolicyCommitment {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OperatorArtifactPolicyCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperatorArtifactPolicyCommitment(<redacted>)")
    }
}

/// Bounded, canonical, independently configured operator admission policy.
///
/// Every borrowed input remains immutably borrowed for the policy's lifetime.
/// The constructor reparses the exact WIT source and requires its normalized
/// world to equal `exact_world`; an artifact cannot supply either value.
pub struct OperatorArtifactAdmissionPolicy<'a> {
    role: OperatorRoleIdentity,
    generation: u64,
    profile: ProfileIdentity,
    command_name: &'a str,
    entrypoint: &'a str,
    min_args: usize,
    max_args: usize,
    exact_wit_source: &'a str,
    exact_world: &'a WorldContract,
    limits: InstanceLimits,
    stdin: CommandStreamMode,
    stdout: CommandStreamMode,
    stderr: CommandStreamMode,
    interfaces: &'a [InterfaceCeiling<'a>],
    signers: &'a [OperatorSignerV1],
}

impl<'a> OperatorArtifactAdmissionPolicy<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: OperatorRoleIdentity,
        generation: u64,
        profile: ProfileIdentity,
        command_name: &'a str,
        entrypoint: &'a str,
        min_args: usize,
        max_args: usize,
        exact_wit_source: &'a str,
        exact_world: &'a WorldContract,
        limits: InstanceLimits,
        stdin: CommandStreamMode,
        stdout: CommandStreamMode,
        stderr: CommandStreamMode,
        interfaces: &'a [InterfaceCeiling<'a>],
        signers: &'a [OperatorSignerV1],
    ) -> Result<Self, ArtifactAuthenticationError> {
        let policy = Self {
            role,
            generation,
            profile,
            command_name,
            entrypoint,
            min_args,
            max_args,
            exact_wit_source,
            exact_world,
            limits,
            stdin,
            stdout,
            stderr,
            interfaces,
            signers,
        };
        policy.validate()?;
        let _ = policy.commitment()?;
        Ok(policy)
    }

    pub const fn role(&self) -> OperatorRoleIdentity {
        self.role
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn command_name(&self) -> &str {
        self.command_name
    }

    pub const fn entrypoint(&self) -> &str {
        self.entrypoint
    }

    pub const fn min_args(&self) -> usize {
        self.min_args
    }

    pub const fn max_args(&self) -> usize {
        self.max_args
    }

    pub const fn exact_wit_source(&self) -> &str {
        self.exact_wit_source
    }

    pub const fn exact_world(&self) -> &WorldContract {
        self.exact_world
    }

    pub const fn limits(&self) -> InstanceLimits {
        self.limits
    }

    pub const fn stdin(&self) -> CommandStreamMode {
        self.stdin
    }

    pub const fn stdout(&self) -> CommandStreamMode {
        self.stdout
    }

    pub const fn stderr(&self) -> CommandStreamMode {
        self.stderr
    }

    pub const fn interfaces(&self) -> &[InterfaceCeiling<'a>] {
        self.interfaces
    }

    pub const fn signers(&self) -> &[OperatorSignerV1] {
        self.signers
    }

    /// Compute the canonical commitment to every configured policy field.
    pub fn commitment(
        &self,
    ) -> Result<OperatorArtifactPolicyCommitment, ArtifactAuthenticationError> {
        canonical_policy_commitment(self)
    }

    /// Produce the inert, fixed-width transcript used by offline signing.
    ///
    /// This operation neither verifies evidence nor creates a receipt. The
    /// supplied complete key must be an active member of this exact policy.
    pub fn signature_transcript(
        &self,
        artifact: &ComponentArtifactV1,
        signer_public_key: [u8; 32],
    ) -> Result<[u8; COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN], ArtifactAuthenticationError>
    {
        Ok(self
            .signature_material(artifact, signer_public_key)?
            .transcript)
    }

    fn exact_rules(&self) -> ExactAdmissionRules<'_> {
        ExactAdmissionRules {
            command_name: self.command_name,
            entrypoint: self.entrypoint,
            min_args: self.min_args,
            max_args: self.max_args,
            exact_world: self.exact_world,
            profile: self.profile,
            limits: self.limits,
            stdin: self.stdin,
            stdout: self.stdout,
            stderr: self.stderr,
            interfaces: self.interfaces,
        }
    }

    fn validate(&self) -> Result<(), ArtifactAuthenticationError> {
        if self.generation == 0 {
            return Err(ArtifactAuthenticationError::InvalidPolicyGeneration);
        }
        if self.profile != ProfileIdentity::PROFILE_1
            && self.profile != ProfileIdentity::PROFILE_1_ASYNC
        {
            return Err(ArtifactAuthenticationError::ProfileMismatch);
        }
        self.limits
            .validate()
            .map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?;
        if !valid_name(self.command_name)
            || !valid_entrypoint(self.entrypoint)
            || !valid_argument_limits(self.min_args, self.max_args)
            || !valid_manifest_text(&self.exact_world.identity, 256)
            || self.exact_wit_source.is_empty()
            || self.exact_wit_source.len() > MAX_COMPONENT_ARTIFACT_OPERATOR_WIT_SOURCE_BYTES
            || self.exact_wit_source.as_bytes().contains(&0)
        {
            return Err(ArtifactAuthenticationError::InvalidPolicy);
        }
        let parsed = WorldContract::parse(self.exact_wit_source, &self.exact_world.identity)
            .map_err(|_| ArtifactAuthenticationError::WitPolicyMismatch)?;
        if parsed != *self.exact_world {
            return Err(ArtifactAuthenticationError::WitPolicyMismatch);
        }
        // Current normalized shapes preserve own/borrow polarity but not the
        // scoped nominal resource equivalence graph. Until that provenance is
        // part of stable policy identity, reject resources recursively here so
        // direct callers cannot bypass the loader's defense-in-depth gate.
        if !entities_are_resource_free(&parsed.imports)
            || !entities_are_resource_free(&parsed.exports)
        {
            return Err(ArtifactAuthenticationError::UnsupportedResourceShape);
        }
        if self.interfaces.len() > PROFILE_1_LIMITS.max_imports as usize {
            return Err(ArtifactAuthenticationError::InterfaceLimit);
        }
        validate_policy_tables(self.interfaces, &[])
            .map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?;
        if !interfaces_are_canonical(self.interfaces) {
            return Err(ArtifactAuthenticationError::NonCanonicalInterfaces);
        }
        if self.signers.is_empty() || self.signers.len() > MAX_COMPONENT_ARTIFACT_OPERATOR_SIGNERS {
            return Err(ArtifactAuthenticationError::SignerLimit);
        }
        let mut has_active = false;
        for (index, signer) in self.signers.iter().enumerate() {
            validate_operator_public_key(signer.public_key)?;
            if index != 0 && self.signers[index - 1].public_key >= signer.public_key {
                return Err(ArtifactAuthenticationError::NonCanonicalSignerTable);
            }
            has_active |= signer.status == OperatorSignerStatus::Active;
        }
        if !has_active {
            return Err(ArtifactAuthenticationError::NoActiveSigner);
        }
        Ok(())
    }

    fn signer(
        &self,
        public_key: [u8; 32],
    ) -> Result<&OperatorSignerV1, ArtifactAuthenticationError> {
        validate_operator_public_key(public_key)?;
        // Always scan the complete bounded table. The constructor has already
        // rejected duplicate complete keys, so at most one entry can match.
        // There is no key ID, digest index, callback, or ambient lookup.
        let mut signer = None;
        for candidate in self.signers {
            if candidate.public_key == public_key {
                signer = Some(candidate);
            }
        }
        let signer = signer.ok_or(ArtifactAuthenticationError::UnknownSigner)?;
        if signer.status != OperatorSignerStatus::Active {
            return Err(ArtifactAuthenticationError::RevokedSigner);
        }
        Ok(signer)
    }

    fn signature_material(
        &self,
        artifact: &ComponentArtifactV1,
        signer_public_key: [u8; 32],
    ) -> Result<SignatureMaterial, ArtifactAuthenticationError> {
        let signer = self.signer(signer_public_key)?;
        let policy_commitment = self.commitment()?;
        validate_artifact_configuration(artifact, self, policy_commitment)?;
        let encoded = artifact
            .encode()
            .map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
        let encoded_len = u64::try_from(encoded.len())
            .map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
        let artifact_commitment = artifact
            .artifact_commitment()
            .map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
        let transcript = signature_transcript_bytes(
            artifact,
            encoded_len,
            artifact_commitment,
            policy_commitment,
            signer.public_key,
            self.generation,
        );
        Ok(SignatureMaterial {
            transcript,
            artifact_commitment,
            policy_commitment,
            encoded_len,
        })
    }
}

impl fmt::Debug for OperatorArtifactAdmissionPolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorArtifactAdmissionPolicy")
            .field("role", &self.role)
            .field("generation", &self.generation)
            .field("profile", &self.profile)
            .field("command_name", &self.command_name)
            .field("entrypoint", &self.entrypoint)
            .field("wit_source", &"<redacted>")
            .field("interfaces", &self.interfaces.len())
            .field("signers", &self.signers.len())
            .field("runtime_ready", &false)
            .finish()
    }
}

/// One successful signature check, sealed to an exact artifact and rule set.
///
/// The type is deliberately neither `Clone` nor `Copy`, and all fields are
/// private. It carries no durable identity, lookup operation, or invocation
/// authority.
///
/// ```compile_fail
/// use vibeos_component_admission::ArtifactAuthenticationReceipt;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<ArtifactAuthenticationReceipt>();
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::ArtifactAuthenticationReceipt;
/// let _forged = ArtifactAuthenticationReceipt {};
/// ```
pub struct ArtifactAuthenticationReceipt {
    component_identity: ComponentIdentity,
    profile: ProfileIdentity,
    artifact_commitment: ComponentArtifactCommitment,
    policy_commitment: OperatorArtifactPolicyCommitment,
    encoded_len: u64,
    generation: u64,
    signer_public_key: [u8; 32],
    _sealed: private::Seal,
}

impl ArtifactAuthenticationReceipt {
    pub const fn component_identity(&self) -> ComponentIdentity {
        self.component_identity
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn policy_commitment(&self) -> OperatorArtifactPolicyCommitment {
        self.policy_commitment
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

impl fmt::Debug for ArtifactAuthenticationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactAuthenticationReceipt")
            .field("component_identity", &self.component_identity)
            .field("profile", &self.profile)
            .field("policy_commitment", &self.policy_commitment)
            .field("generation", &self.generation)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Move-only decoded artifact plus its exact authentication receipt.
///
/// ```compile_fail
/// use vibeos_component_admission::AuthenticatedComponentArtifact;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<AuthenticatedComponentArtifact>();
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AuthenticatedComponentArtifact;
/// let _forged = AuthenticatedComponentArtifact {};
/// ```
pub struct AuthenticatedComponentArtifact {
    artifact: ComponentArtifactV1,
    receipt: ArtifactAuthenticationReceipt,
    _sealed: private::Seal,
}

impl AuthenticatedComponentArtifact {
    pub const fn artifact(&self) -> &ComponentArtifactV1 {
        &self.artifact
    }

    pub const fn receipt(&self) -> &ArtifactAuthenticationReceipt {
        &self.receipt
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }
}

impl fmt::Debug for AuthenticatedComponentArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedComponentArtifact")
            .field("artifact", &"<redacted>")
            .field("receipt", &self.receipt)
            .field("runtime_ready", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ArtifactAuthenticationError {
    InvalidOperatorRole = 1,
    InvalidPolicyGeneration = 2,
    InvalidPolicy = 3,
    WitPolicyMismatch = 4,
    InterfaceLimit = 5,
    NonCanonicalInterfaces = 6,
    SignerLimit = 7,
    InvalidPublicKey = 8,
    NonCanonicalPublicKey = 9,
    WeakPublicKey = 10,
    NonCanonicalSignerTable = 11,
    NoActiveSigner = 12,
    PolicyCommitment = 13,
    ProfileMismatch = 14,
    InstanceLimitsMismatch = 15,
    SignerPolicyKind = 16,
    PolicyDigestMismatch = 17,
    ArtifactConfiguration = 18,
    UnknownSigner = 19,
    RevokedSigner = 20,
    ArtifactEncoding = 21,
    InvalidSignature = 22,
    ReceiptMismatch = 23,
    UnsupportedResourceShape = 24,
}

impl ArtifactAuthenticationError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for ArtifactAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperatorRole => "operator role identity is invalid",
            Self::InvalidPolicyGeneration => "operator policy generation is invalid",
            Self::InvalidPolicy => "operator admission policy is invalid",
            Self::WitPolicyMismatch => "operator WIT source and world policy differ",
            Self::InterfaceLimit => "operator interface policy exceeds the profile bound",
            Self::NonCanonicalInterfaces => "operator interface policy is not canonical",
            Self::SignerLimit => "operator signer table exceeds its bound",
            Self::InvalidPublicKey => "operator public-key encoding is invalid",
            Self::NonCanonicalPublicKey => "operator public-key encoding is non-canonical",
            Self::WeakPublicKey => "weak operator public key is forbidden",
            Self::NonCanonicalSignerTable => "operator signer table is not canonical",
            Self::NoActiveSigner => "operator policy has no active signer",
            Self::PolicyCommitment => "operator policy commitment is invalid",
            Self::ProfileMismatch => "artifact profile differs from operator policy",
            Self::InstanceLimitsMismatch => "artifact limits differ from operator policy",
            Self::SignerPolicyKind => "artifact does not require operator authentication",
            Self::PolicyDigestMismatch => "artifact operator-policy commitment differs",
            Self::ArtifactConfiguration => "artifact metadata differs from operator policy",
            Self::UnknownSigner => "detached evidence signer is not configured",
            Self::RevokedSigner => "detached evidence signer is revoked",
            Self::ArtifactEncoding => "canonical artifact commitment could not be reproduced",
            Self::InvalidSignature => "detached artifact signature is invalid",
            Self::ReceiptMismatch => "authentication receipt no longer matches exact inputs",
            Self::UnsupportedResourceShape => {
                "authenticated admission does not support nominal resource shapes"
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticatedAdmissionError {
    Authentication(ArtifactAuthenticationError),
    Admission(AdmissionError),
}

impl fmt::Display for AuthenticatedAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => error.fmt(formatter),
            Self::Admission(error) => error.fmt(formatter),
        }
    }
}

impl From<ArtifactAuthenticationError> for AuthenticatedAdmissionError {
    fn from(error: ArtifactAuthenticationError) -> Self {
        Self::Authentication(error)
    }
}

impl From<AdmissionError> for AuthenticatedAdmissionError {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}

struct SignatureMaterial {
    transcript: [u8; COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN],
    artifact_commitment: ComponentArtifactCommitment,
    policy_commitment: OperatorArtifactPolicyCommitment,
    encoded_len: u64,
}

/// Verify detached evidence and seal it to the exact decoded artifact and
/// independently configured policy. No component inspection, allocation of a
/// runtime artifact, or ordinary admission occurs here.
pub fn authenticate_component_artifact(
    artifact: ComponentArtifactV1,
    evidence: &ComponentArtifactAuthenticationEvidenceV1,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> Result<AuthenticatedComponentArtifact, ArtifactAuthenticationError> {
    if evidence.algorithm() != ComponentArtifactAuthenticationAlgorithm::Ed25519 {
        return Err(ArtifactAuthenticationError::InvalidSignature);
    }
    let signer_public_key = evidence.public_key().to_bytes();
    let material = policy.signature_material(&artifact, signer_public_key)?;
    let verifying_key = operator_verifying_key(signer_public_key)?;
    let signature = Signature::from_bytes(evidence.signature().as_bytes());
    verifying_key
        .verify_strict(&material.transcript, &signature)
        .map_err(|_| ArtifactAuthenticationError::InvalidSignature)?;

    let component_identity = component_identity(artifact.component_bytes());
    let receipt = ArtifactAuthenticationReceipt {
        component_identity,
        profile: artifact.profile(),
        artifact_commitment: material.artifact_commitment,
        policy_commitment: material.policy_commitment,
        encoded_len: material.encoded_len,
        generation: policy.generation,
        signer_public_key,
        _sealed: private::Seal,
    };
    Ok(AuthenticatedComponentArtifact {
        artifact,
        receipt,
        _sealed: private::Seal,
    })
}

/// Consume one move-only authentication result and perform full ordinary
/// semantic admission under the exact committed rules.
///
/// Component identity, profile, and the complete rules commitment are
/// recomputed before copying component bytes or invoking the validator. The
/// signed path never constructs or examines [`crate::ArtifactTrust`].
pub fn admit_authenticated(
    authenticated: AuthenticatedComponentArtifact,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedComponent, AuthenticatedAdmissionError> {
    let (component, engine) = revalidate_authenticated_artifact(authenticated, policy)?;
    admit_under_exact_rules_with_current_engine(component, &policy.exact_rules(), caller, &engine)
        .map_err(Into::into)
}

/// Consume a leaf authentication proof and repeat every canonical artifact,
/// signer-policy, WIT, Core, manifest, limit, and current-engine check without
/// performing single-command admission. Graph admission uses this crate-only
/// seam because graph-internal imports are validated as one complete typed
/// graph rather than misclassified as ambient host imports.
pub(crate) fn revalidate_authenticated_graph_artifact(
    authenticated: AuthenticatedComponentArtifact,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> Result<ComponentArtifact, AuthenticatedAdmissionError> {
    revalidate_authenticated_artifact(authenticated, policy).map(|(component, _engine)| component)
}

fn revalidate_authenticated_artifact(
    authenticated: AuthenticatedComponentArtifact,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> Result<(ComponentArtifact, CurrentValidationEngine), AuthenticatedAdmissionError> {
    let AuthenticatedComponentArtifact {
        artifact,
        receipt,
        _sealed: _,
    } = authenticated;

    // These checks are allocation-free and precede both ComponentArtifact's
    // owned copy and every validator/inspection allocation.
    let policy_commitment = policy.commitment()?;
    let observed_identity = component_identity(artifact.component_bytes());
    if receipt.component_identity != observed_identity
        || receipt.profile != artifact.profile()
        || receipt.profile != policy.profile
        || receipt.policy_commitment != policy_commitment
        || receipt.generation != policy.generation
    {
        return Err(ArtifactAuthenticationError::ReceiptMismatch.into());
    }
    // Resolve the validator, WIT frontend, embedded-Core frontend, and inert
    // wasmi configuration from this boot. The proof cannot be supplied by the
    // durable artifact and remains borrowed through all fresh semantic checks.
    let engine = CurrentValidationEngine::for_profile(policy.profile)?;
    let signer = policy.signer(receipt.signer_public_key)?;
    if signer.public_key != receipt.signer_public_key {
        return Err(ArtifactAuthenticationError::ReceiptMismatch.into());
    }
    validate_artifact_configuration(&artifact, policy, policy_commitment)?;

    // Reproduce canonical artifact framing only after the security-critical
    // identity/profile/rules checks above. This may allocate, but still occurs
    // before component inspection or publication of an admitted value.
    let encoded = artifact
        .encode()
        .map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
    let artifact_commitment = artifact
        .artifact_commitment()
        .map_err(|_| ArtifactAuthenticationError::ArtifactEncoding)?;
    if encoded_len != receipt.encoded_len || artifact_commitment != receipt.artifact_commitment {
        return Err(ArtifactAuthenticationError::ReceiptMismatch.into());
    }

    let component = ComponentArtifact::copy_from(artifact.component_bytes(), artifact.profile())?;
    if component.identity() != receipt.component_identity {
        return Err(ArtifactAuthenticationError::ReceiptMismatch.into());
    }
    validate_fresh_artifact_evidence(&artifact, &component, policy, &engine)?;
    Ok((component, engine))
}

fn validate_operator_public_key(public_key: [u8; 32]) -> Result<(), ArtifactAuthenticationError> {
    operator_verifying_key(public_key).map(|_| ())
}

pub(crate) fn operator_verifying_key(
    public_key: [u8; 32],
) -> Result<VerifyingKey, ArtifactAuthenticationError> {
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ArtifactAuthenticationError::InvalidPublicKey)?;
    // `VerifyingKey::to_bytes` retains the original compressed bytes. Perform
    // an actual point recompression so non-canonical encodings cannot enter an
    // operator policy or match detached evidence.
    if verifying_key.to_edwards().compress().to_bytes() != public_key {
        return Err(ArtifactAuthenticationError::NonCanonicalPublicKey);
    }
    if verifying_key.is_weak() {
        return Err(ArtifactAuthenticationError::WeakPublicKey);
    }
    Ok(verifying_key)
}

fn validate_artifact_configuration(
    artifact: &ComponentArtifactV1,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
    policy_commitment: OperatorArtifactPolicyCommitment,
) -> Result<(), ArtifactAuthenticationError> {
    if artifact.profile() != policy.profile || artifact.profile_limits() != PROFILE_1_LIMITS {
        return Err(ArtifactAuthenticationError::ProfileMismatch);
    }
    if !instance_limits_match(artifact, policy.limits) {
        return Err(ArtifactAuthenticationError::InstanceLimitsMismatch);
    }
    let signer_policy = artifact.signer_policy();
    if signer_policy.kind() != ComponentArtifactSignerPolicyKind::OperatorRequired {
        return Err(ArtifactAuthenticationError::SignerPolicyKind);
    }
    if signer_policy.policy_digest().as_bytes() != policy_commitment.as_bytes() {
        return Err(ArtifactAuthenticationError::PolicyDigestMismatch);
    }
    if artifact.runtime_ready()
        || artifact.manifest().world() != policy.exact_world.identity
        || artifact.manifest().wit_packages().len() != 1
    {
        return Err(ArtifactAuthenticationError::ArtifactConfiguration);
    }
    let package = &artifact.manifest().wit_packages()[0];
    let (package_name, package_version) = world_package(&policy.exact_world.identity)
        .ok_or(ArtifactAuthenticationError::ArtifactConfiguration)?;
    if package.name() != package_name
        || package.version() != package_version
        || package.source() != policy.exact_wit_source
    {
        return Err(ArtifactAuthenticationError::ArtifactConfiguration);
    }
    Ok(())
}

fn validate_fresh_artifact_evidence(
    artifact: &ComponentArtifactV1,
    component: &ComponentArtifact,
    policy: &OperatorArtifactAdmissionPolicy<'_>,
    engine: &CurrentValidationEngine,
) -> Result<(), ArtifactAuthenticationError> {
    let fresh_world = WorldContract::parse_with_current_engine(
        policy.exact_wit_source,
        &policy.exact_world.identity,
        engine.component(),
    )
    .map_err(|_| ArtifactAuthenticationError::WitPolicyMismatch)?;
    if fresh_world != *policy.exact_world {
        return Err(ArtifactAuthenticationError::WitPolicyMismatch);
    }
    let inspection = component
        .inspect_with_current_engine(engine)
        .map_err(|_| ArtifactAuthenticationError::ArtifactConfiguration)?;
    let plan = inspection.plan();
    if plan.profile() != artifact.profile()
        || plan.profile() != policy.profile
        || plan.check_world(policy.exact_world).is_err()
        || !interface_manifest_matches(artifact.manifest(), plan.imports(), plan.exports())
        || !artifact.manifest().adapters().is_empty()
        || plan.summary().adapters != 0
    {
        return Err(ArtifactAuthenticationError::ArtifactConfiguration);
    }
    let modules = plan.embedded_modules();
    if modules.len() != artifact.manifest().core_modules().len() {
        return Err(ArtifactAuthenticationError::ArtifactConfiguration);
    }
    for (bytes, expected) in modules.iter().zip(artifact.manifest().core_modules()) {
        let observed = ComponentArtifactCoreModuleV1::from_bytes(bytes)
            .map_err(|_| ArtifactAuthenticationError::ArtifactConfiguration)?;
        if observed.byte_len() != expected.byte_len()
            || observed.commitment() != expected.commitment()
        {
            return Err(ArtifactAuthenticationError::ArtifactConfiguration);
        }
    }
    Ok(())
}

fn interface_manifest_matches(
    manifest: &ComponentArtifactManifestV1,
    imports: &[NamedEntityShape],
    exports: &[NamedEntityShape],
) -> bool {
    let Some(total) = imports.len().checked_add(exports.len()) else {
        return false;
    };
    if manifest.interfaces().len() != total {
        return false;
    }
    manifest.interfaces().iter().all(|claimed| {
        let entities = match claimed.direction() {
            ComponentArtifactInterfaceDirection::Import => imports,
            ComponentArtifactInterfaceDirection::Export => exports,
        };
        entities.iter().any(|fresh| {
            fresh.name == claimed.name()
                && entity_kind(&fresh.entity) == claimed.kind()
                && canonical_entity_shape_text_v1(&fresh.entity)
                    .is_ok_and(|shape| shape == claimed.diagnostic_shape())
        })
    })
}

const fn entity_kind(entity: &EntityShape) -> ComponentArtifactEntityKind {
    match entity {
        EntityShape::Function(_) => ComponentArtifactEntityKind::Function,
        EntityShape::Interface(_) => ComponentArtifactEntityKind::Interface,
        EntityShape::Type(_) => ComponentArtifactEntityKind::Type,
    }
}

fn entities_are_resource_free(entities: &[NamedEntityShape]) -> bool {
    entities
        .iter()
        .all(|entity| entity_is_resource_free(&entity.entity))
}

fn entity_is_resource_free(entity: &EntityShape) -> bool {
    match entity {
        EntityShape::Function(function) => {
            function
                .parameters
                .iter()
                .all(|parameter| value_is_resource_free(&parameter.value))
                && function.result.as_ref().is_none_or(value_is_resource_free)
        }
        EntityShape::Interface(entities) => entities_are_resource_free(entities),
        EntityShape::Type(TypeShape::Resource) => false,
        EntityShape::Type(TypeShape::Value(value)) => value_is_resource_free(value),
    }
}

fn value_is_resource_free(value: &ValueShape) -> bool {
    match value {
        ValueShape::List(value) | ValueShape::Option(value) => value_is_resource_free(value),
        ValueShape::Tuple(values) => values.iter().all(value_is_resource_free),
        ValueShape::Record(fields) => fields
            .iter()
            .all(|field| value_is_resource_free(&field.value)),
        ValueShape::Result { ok, error } => {
            ok.as_deref().is_none_or(value_is_resource_free)
                && error.as_deref().is_none_or(value_is_resource_free)
        }
        ValueShape::Variant(cases) => cases
            .iter()
            .all(|case| case.value.as_ref().is_none_or(value_is_resource_free)),
        ValueShape::Future(value) | ValueShape::Stream(value) => {
            value.as_deref().is_none_or(value_is_resource_free)
        }
        ValueShape::Own(_) | ValueShape::Borrow(_) => false,
        ValueShape::Bool
        | ValueShape::U8
        | ValueShape::U16
        | ValueShape::U32
        | ValueShape::U64
        | ValueShape::S8
        | ValueShape::S16
        | ValueShape::S32
        | ValueShape::S64
        | ValueShape::Char
        | ValueShape::String
        | ValueShape::Flags(_)
        | ValueShape::Enum(_) => true,
    }
}

fn instance_limits_match(artifact: &ComponentArtifactV1, expected: InstanceLimits) -> bool {
    let observed = artifact.instance_limits();
    u64::try_from(expected.memory_bytes).ok() == Some(observed.memory_bytes())
        && expected.total_fuel == observed.total_fuel()
        && expected.poll_quantum == observed.poll_quantum()
        && u64::from(expected.resources) == observed.resources()
}

fn world_package(world: &str) -> Option<(&str, &str)> {
    let (package, selected) = world.rsplit_once('/')?;
    let (_, version) = selected.rsplit_once('@')?;
    (!package.is_empty() && !version.is_empty()).then_some((package, version))
}

fn component_identity(bytes: &[u8]) -> ComponentIdentity {
    ComponentIdentity(Sha256::digest(bytes).into())
}

fn interfaces_are_canonical(interfaces: &[InterfaceCeiling<'_>]) -> bool {
    interfaces
        .windows(2)
        .all(|pair| compare_interfaces(&pair[0], &pair[1]) == Ordering::Less)
}

fn compare_interfaces(left: &InterfaceCeiling<'_>, right: &InterfaceCeiling<'_>) -> Ordering {
    left.label
        .cmp(right.label)
        .then_with(|| left.interface.cmp(right.interface))
        .then_with(|| host_kind_raw(left.kind).cmp(&host_kind_raw(right.kind)))
        .then_with(|| left.rights.bits().cmp(&right.rights.bits()))
}

fn canonical_policy_commitment(
    policy: &OperatorArtifactAdmissionPolicy<'_>,
) -> Result<OperatorArtifactPolicyCommitment, ArtifactAuthenticationError> {
    let mut hasher = Sha256::new();
    hasher.update(OPERATOR_POLICY_DOMAIN);
    put_u16(&mut hasher, COMPONENT_ARTIFACT_OPERATOR_POLICY_VERSION);
    put_u64(&mut hasher, policy.generation);
    hasher.update(policy.role.as_bytes());
    put_u16(
        &mut hasher,
        u16::try_from(policy.signers.len())
            .map_err(|_| ArtifactAuthenticationError::SignerLimit)?,
    );
    for signer in policy.signers {
        hasher.update(signer.public_key);
        put_u8(&mut hasher, signer.status as u8);
    }
    put_u8(&mut hasher, OPERATOR_TRUST_MODE);
    encode_profile(&mut hasher, policy.profile)?;
    put_text(&mut hasher, policy.command_name)?;
    put_text(&mut hasher, policy.entrypoint)?;
    put_u64(
        &mut hasher,
        u64::try_from(policy.min_args).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    put_u64(
        &mut hasher,
        u64::try_from(policy.max_args).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    put_text(&mut hasher, &policy.exact_world.identity)?;
    encode_named_entities(&mut hasher, &policy.exact_world.imports)?;
    encode_named_entities(&mut hasher, &policy.exact_world.exports)?;
    put_u64(
        &mut hasher,
        u64::try_from(policy.limits.memory_bytes)
            .map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    put_u64(&mut hasher, policy.limits.total_fuel);
    put_u64(&mut hasher, policy.limits.poll_quantum);
    put_u16(&mut hasher, policy.limits.resources);
    put_u8(&mut hasher, stream_mode_raw(policy.stdin));
    put_u8(&mut hasher, stream_mode_raw(policy.stdout));
    put_u8(&mut hasher, stream_mode_raw(policy.stderr));
    put_u16(
        &mut hasher,
        u16::try_from(policy.interfaces.len())
            .map_err(|_| ArtifactAuthenticationError::InterfaceLimit)?,
    );
    for interface in policy.interfaces {
        put_text(&mut hasher, interface.label)?;
        put_text(&mut hasher, interface.interface)?;
        put_u8(&mut hasher, host_kind_raw(interface.kind));
        put_u32(&mut hasher, interface.rights.bits());
    }
    put_u64(
        &mut hasher,
        u64::try_from(policy.exact_wit_source.len())
            .map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    hasher.update(policy.exact_wit_source.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(ArtifactAuthenticationError::PolicyCommitment);
    }
    Ok(OperatorArtifactPolicyCommitment(digest))
}

fn encode_profile(
    hasher: &mut Sha256,
    profile: ProfileIdentity,
) -> Result<(), ArtifactAuthenticationError> {
    put_u16(hasher, profile.artifact_abi);
    put_u16(hasher, profile.component_profile);
    put_u16(hasher, profile.core_profile);
    put_u16(hasher, profile.runtime_abi);
    put_u64(hasher, profile.canonical_features);
    put_u16(hasher, profile_stage_raw(profile.stage));
    for revision in [
        profile.core_revision,
        profile.component_revision,
        profile.canonical_abi_revision,
        profile.wasm_tools_revision,
        profile.wasi_revision,
    ] {
        put_text(hasher, revision)?;
    }
    Ok(())
}

fn encode_named_entities(
    hasher: &mut Sha256,
    entities: &[NamedEntityShape],
) -> Result<(), ArtifactAuthenticationError> {
    put_u32(
        hasher,
        u32::try_from(entities.len()).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    let mut previous: Option<&str> = None;
    for _ in 0..entities.len() {
        let entity = entities
            .iter()
            .filter(|entity| previous.is_none_or(|name| entity.name.as_str() > name))
            .min_by(|left, right| left.name.cmp(&right.name))
            .ok_or(ArtifactAuthenticationError::InvalidPolicy)?;
        put_text(hasher, &entity.name)?;
        encode_entity_shape(hasher, &entity.entity)?;
        previous = Some(&entity.name);
    }
    Ok(())
}

fn encode_entity_shape(
    hasher: &mut Sha256,
    entity: &EntityShape,
) -> Result<(), ArtifactAuthenticationError> {
    match entity {
        EntityShape::Function(function) => {
            put_u8(hasher, 0);
            encode_function_shape(hasher, function)
        }
        EntityShape::Interface(members) => {
            put_u8(hasher, 1);
            encode_named_entities(hasher, members)
        }
        EntityShape::Type(TypeShape::Resource) => {
            put_u8(hasher, 2);
            put_u8(hasher, 0);
            Ok(())
        }
        EntityShape::Type(TypeShape::Value(value)) => {
            put_u8(hasher, 2);
            put_u8(hasher, 1);
            encode_value_shape(hasher, value)
        }
    }
}

fn encode_function_shape(
    hasher: &mut Sha256,
    function: &FunctionShape,
) -> Result<(), ArtifactAuthenticationError> {
    put_u8(
        hasher,
        match function.effect {
            FunctionEffect::Sync => 0,
            FunctionEffect::Async => 1,
        },
    );
    encode_named_values(hasher, &function.parameters)?;
    encode_optional_value(hasher, function.result.as_ref())
}

fn encode_named_values(
    hasher: &mut Sha256,
    values: &[NamedValueShape],
) -> Result<(), ArtifactAuthenticationError> {
    put_u32(
        hasher,
        u32::try_from(values.len()).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    for value in values {
        put_text(hasher, &value.name)?;
        encode_value_shape(hasher, &value.value)?;
    }
    Ok(())
}

fn encode_named_cases(
    hasher: &mut Sha256,
    cases: &[NamedCaseShape],
) -> Result<(), ArtifactAuthenticationError> {
    put_u32(
        hasher,
        u32::try_from(cases.len()).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    for case in cases {
        put_text(hasher, &case.name)?;
        encode_optional_value(hasher, case.value.as_ref())?;
    }
    Ok(())
}

fn encode_strings(
    hasher: &mut Sha256,
    values: &[alloc::string::String],
) -> Result<(), ArtifactAuthenticationError> {
    put_u32(
        hasher,
        u32::try_from(values.len()).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    for value in values {
        put_text(hasher, value)?;
    }
    Ok(())
}

fn encode_optional_value(
    hasher: &mut Sha256,
    value: Option<&ValueShape>,
) -> Result<(), ArtifactAuthenticationError> {
    match value {
        Some(value) => {
            put_u8(hasher, 1);
            encode_value_shape(hasher, value)
        }
        None => {
            put_u8(hasher, 0);
            Ok(())
        }
    }
}

fn encode_value_shape(
    hasher: &mut Sha256,
    value: &ValueShape,
) -> Result<(), ArtifactAuthenticationError> {
    match value {
        ValueShape::Bool => put_u8(hasher, 0),
        ValueShape::U8 => put_u8(hasher, 1),
        ValueShape::U16 => put_u8(hasher, 2),
        ValueShape::U32 => put_u8(hasher, 3),
        ValueShape::U64 => put_u8(hasher, 4),
        ValueShape::S8 => put_u8(hasher, 5),
        ValueShape::S16 => put_u8(hasher, 6),
        ValueShape::S32 => put_u8(hasher, 7),
        ValueShape::S64 => put_u8(hasher, 8),
        ValueShape::Char => put_u8(hasher, 9),
        ValueShape::String => put_u8(hasher, 10),
        ValueShape::List(item) => {
            put_u8(hasher, 11);
            encode_value_shape(hasher, item)?;
        }
        ValueShape::Tuple(items) => {
            put_u8(hasher, 12);
            put_u32(
                hasher,
                u32::try_from(items.len())
                    .map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
            );
            for item in items {
                encode_value_shape(hasher, item)?;
            }
        }
        ValueShape::Record(fields) => {
            put_u8(hasher, 13);
            encode_named_values(hasher, fields)?;
        }
        ValueShape::Flags(flags) => {
            put_u8(hasher, 14);
            encode_strings(hasher, flags)?;
        }
        ValueShape::Enum(cases) => {
            put_u8(hasher, 15);
            encode_strings(hasher, cases)?;
        }
        ValueShape::Option(item) => {
            put_u8(hasher, 16);
            encode_value_shape(hasher, item)?;
        }
        ValueShape::Result { ok, error } => {
            put_u8(hasher, 17);
            encode_optional_value(hasher, ok.as_deref())?;
            encode_optional_value(hasher, error.as_deref())?;
        }
        ValueShape::Variant(cases) => {
            put_u8(hasher, 18);
            encode_named_cases(hasher, cases)?;
        }
        ValueShape::Future(item) => {
            put_u8(hasher, 19);
            encode_optional_value(hasher, item.as_deref())?;
        }
        ValueShape::Stream(item) => {
            put_u8(hasher, 20);
            encode_optional_value(hasher, item.as_deref())?;
        }
        ValueShape::Own(resource) => {
            put_u8(hasher, 21);
            put_text(hasher, resource)?;
        }
        ValueShape::Borrow(resource) => {
            put_u8(hasher, 22);
            put_text(hasher, resource)?;
        }
    }
    Ok(())
}

fn signature_transcript_bytes(
    artifact: &ComponentArtifactV1,
    encoded_len: u64,
    artifact_commitment: ComponentArtifactCommitment,
    policy_commitment: OperatorArtifactPolicyCommitment,
    signer_public_key: [u8; 32],
    policy_generation: u64,
) -> [u8; COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN] {
    let mut out = [0_u8; COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_LEN];
    out[0..48].copy_from_slice(SIGNATURE_DOMAIN);
    out[48..50].copy_from_slice(&COMPONENT_ARTIFACT_SIGNATURE_TRANSCRIPT_VERSION.to_le_bytes());
    out[50..52].copy_from_slice(&COMPONENT_ARTIFACT_AUTHENTICATION_VERSION.to_le_bytes());
    out[52..54].copy_from_slice(&TRANSCRIPT_ED25519_ALGORITHM.to_le_bytes());
    out[54..56].copy_from_slice(&COMPONENT_ARTIFACT_FORMAT_VERSION.to_le_bytes());
    out[56..58].copy_from_slice(&COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION.to_le_bytes());
    out[58..60].copy_from_slice(&COMPONENT_ARTIFACT_OPERATOR_POLICY_VERSION.to_le_bytes());
    let profile = artifact.profile();
    out[60..62].copy_from_slice(&profile.artifact_abi.to_le_bytes());
    out[62..64].copy_from_slice(&profile.component_profile.to_le_bytes());
    out[64..66].copy_from_slice(&profile.core_profile.to_le_bytes());
    out[66..68].copy_from_slice(&profile.runtime_abi.to_le_bytes());
    out[68..70].copy_from_slice(&profile_stage_raw(profile.stage).to_le_bytes());
    // 70..72 is a frozen zero reservation.
    out[72..80].copy_from_slice(&profile.canonical_features.to_le_bytes());
    out[80..88].copy_from_slice(&encoded_len.to_le_bytes());
    out[88..120].copy_from_slice(artifact_commitment.as_bytes());
    out[120..152].copy_from_slice(policy_commitment.as_bytes());
    out[152..184].copy_from_slice(&signer_public_key);
    out[184..192].copy_from_slice(&policy_generation.to_le_bytes());
    out
}

fn put_text(hasher: &mut Sha256, value: &str) -> Result<(), ArtifactAuthenticationError> {
    put_u32(
        hasher,
        u32::try_from(value.len()).map_err(|_| ArtifactAuthenticationError::InvalidPolicy)?,
    );
    hasher.update(value.as_bytes());
    Ok(())
}

fn put_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn put_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}

fn put_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn put_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

const fn profile_stage_raw(stage: ProfileStage) -> u16 {
    match stage {
        ProfileStage::Executable => 1,
        ProfileStage::ValidationOnly => 2,
    }
}

const fn stream_mode_raw(mode: CommandStreamMode) -> u8 {
    match mode {
        CommandStreamMode::Required => 1,
        CommandStreamMode::Optional => 2,
        CommandStreamMode::Closed => 3,
    }
}

const fn host_kind_raw(kind: HostResourceKind) -> u8 {
    match kind {
        HostResourceKind::Clock => 1,
        HostResourceKind::Random => 2,
        HostResourceKind::Blob => 3,
        HostResourceKind::StructuredLog => 4,
        HostResourceKind::ByteStreamReader => 5,
        HostResourceKind::ByteStreamWriter => 6,
    }
}
