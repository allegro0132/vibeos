//! Canonical detached authentication evidence for one Component artifact.
//!
//! This module owns only the fixed-width wire representation supplied to the
//! C7.3 admission boundary. Decoding proves canonical framing and rejects
//! obvious zero sentinels; it does not validate an Ed25519 curve point, reject
//! a weak key, verify a signature, select an operator policy, or make an
//! artifact executable. Those decisions require independently configured
//! admission policy and remain outside the format crate.

use core::fmt;

/// Canonical detached-evidence magic.
pub const COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC: [u8; 8] = *b"VIBESIG\0";
/// Sole detached-evidence format version.
pub const COMPONENT_ARTIFACT_AUTHENTICATION_VERSION: u16 = 1;
/// Exact encoded size of [`ComponentArtifactAuthenticationEvidenceV1`].
pub const COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN: usize = 112;
/// Stable durable ObjectKind for one canonical, detached operator evidence
/// value. The tag selects this exact 112-byte decoder only; it is not an object
/// name, lookup key, authentication receipt, capability, or execution right.
pub const COMPONENT_ARTIFACT_OPERATOR_EVIDENCE_OBJECT_KIND_RAW: u32 = 0x434d_4531;
/// Exact byte length of an operator-role Ed25519 public key.
pub const COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN: usize = 32;
/// Exact byte length of an Ed25519 signature.
pub const COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN: usize = 64;

const VERSION_OFFSET: usize = 8;
const TOTAL_LEN_OFFSET: usize = 10;
const ALGORITHM_OFFSET: usize = 12;
const FLAGS_OFFSET: usize = 14;
const PUBLIC_KEY_OFFSET: usize = 16;
const SIGNATURE_OFFSET: usize = 48;

/// Signature algorithm selected by detached authentication evidence v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentArtifactAuthenticationAlgorithm {
    Ed25519 = 1,
}

impl ComponentArtifactAuthenticationAlgorithm {
    pub const fn as_raw(self) -> u16 {
        self as u16
    }

    const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// Exact binary operator-role public-key payload carried by untrusted evidence.
///
/// Construction rejects only the all-zero format sentinel. Admission must
/// still require the unique canonical Ed25519 encoding, reject weak points,
/// and match the complete key against an explicit operator policy.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentArtifactOperatorPublicKey([u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN]);

impl ComponentArtifactOperatorPublicKey {
    pub fn from_bytes(
        bytes: [u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN],
    ) -> Result<Self, ComponentArtifactAuthenticationError> {
        if is_zero(&bytes) {
            return Err(ComponentArtifactAuthenticationError::ZeroPublicKey);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN] {
        self.0
    }
}

impl fmt::Debug for ComponentArtifactOperatorPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentArtifactOperatorPublicKey(<redacted>)")
    }
}

/// Exact Ed25519 signature payload carried by untrusted detached evidence.
///
/// The format layer rejects only the all-zero sentinel. Admission must parse
/// and verify the signature with strict malleability checks.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentArtifactEd25519Signature([u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN]);

impl ComponentArtifactEd25519Signature {
    pub fn from_bytes(
        bytes: [u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ComponentArtifactAuthenticationError> {
        if is_zero(&bytes) {
            return Err(ComponentArtifactAuthenticationError::ZeroSignature);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN] {
        self.0
    }
}

impl fmt::Debug for ComponentArtifactEd25519Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentArtifactEd25519Signature(<redacted>)")
    }
}

/// Canonical, detached, and still-untrusted Component authentication evidence.
///
/// The fields are private so callers cannot bypass the fixed wire contract.
/// Construction does not assert signer authenticity and this value is never an
/// admission receipt or execution authority.
///
/// ```compile_fail
/// use vibeos_component_format::ComponentArtifactAuthenticationEvidenceV1;
///
/// let _ = ComponentArtifactAuthenticationEvidenceV1 {
///     public_key: [1; 32],
///     signature: [2; 64],
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentArtifactAuthenticationEvidenceV1 {
    public_key: ComponentArtifactOperatorPublicKey,
    signature: ComponentArtifactEd25519Signature,
}

impl ComponentArtifactAuthenticationEvidenceV1 {
    /// Construct exact detached evidence while rejecting zero sentinels.
    pub fn new(
        public_key: [u8; COMPONENT_ARTIFACT_OPERATOR_PUBLIC_KEY_LEN],
        signature: [u8; COMPONENT_ARTIFACT_ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ComponentArtifactAuthenticationError> {
        Ok(Self {
            public_key: ComponentArtifactOperatorPublicKey::from_bytes(public_key)?,
            signature: ComponentArtifactEd25519Signature::from_bytes(signature)?,
        })
    }

    pub const fn algorithm(&self) -> ComponentArtifactAuthenticationAlgorithm {
        ComponentArtifactAuthenticationAlgorithm::Ed25519
    }

    pub const fn public_key(&self) -> ComponentArtifactOperatorPublicKey {
        self.public_key
    }

    pub const fn signature(&self) -> ComponentArtifactEd25519Signature {
        self.signature
    }

    pub const fn encoded_len(&self) -> usize {
        COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN
    }

    /// Detached evidence is inert even after canonical decoding.
    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Encode the sole fixed-width little-endian v1 representation.
    pub fn encode(&self) -> [u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN] {
        let mut out = [0_u8; COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN];
        out[..COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC.len()]
            .copy_from_slice(&COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC);
        out[VERSION_OFFSET..VERSION_OFFSET + 2]
            .copy_from_slice(&COMPONENT_ARTIFACT_AUTHENTICATION_VERSION.to_le_bytes());
        out[TOTAL_LEN_OFFSET..TOTAL_LEN_OFFSET + 2]
            .copy_from_slice(&(COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN as u16).to_le_bytes());
        out[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 2]
            .copy_from_slice(&self.algorithm().as_raw().to_le_bytes());
        out[FLAGS_OFFSET..FLAGS_OFFSET + 2].copy_from_slice(&0_u16.to_le_bytes());
        out[PUBLIC_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(self.public_key.as_bytes());
        out[SIGNATURE_OFFSET..].copy_from_slice(self.signature.as_bytes());
        out
    }

    /// Decode only an exact 112-byte canonical detached-evidence value.
    pub fn decode(bytes: &[u8]) -> Result<Self, ComponentArtifactAuthenticationError> {
        if bytes.len() != COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN {
            return Err(ComponentArtifactAuthenticationError::EncodedLength {
                actual: bytes.len(),
            });
        }
        if bytes[..COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC.len()]
            != COMPONENT_ARTIFACT_AUTHENTICATION_MAGIC
        {
            return Err(ComponentArtifactAuthenticationError::Magic);
        }
        let version = read_u16(bytes, VERSION_OFFSET);
        if version != COMPONENT_ARTIFACT_AUTHENTICATION_VERSION {
            return Err(ComponentArtifactAuthenticationError::Version { actual: version });
        }
        let declared_len = read_u16(bytes, TOTAL_LEN_OFFSET);
        if usize::from(declared_len) != COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN {
            return Err(ComponentArtifactAuthenticationError::DeclaredLength {
                actual: declared_len,
            });
        }
        let algorithm = read_u16(bytes, ALGORITHM_OFFSET);
        if ComponentArtifactAuthenticationAlgorithm::from_raw(algorithm)
            != Some(ComponentArtifactAuthenticationAlgorithm::Ed25519)
        {
            return Err(ComponentArtifactAuthenticationError::Algorithm { actual: algorithm });
        }
        let flags = read_u16(bytes, FLAGS_OFFSET);
        if flags != 0 {
            return Err(ComponentArtifactAuthenticationError::Flags { actual: flags });
        }

        let public_key = bytes[PUBLIC_KEY_OFFSET..SIGNATURE_OFFSET]
            .try_into()
            .expect("fixed public-key field");
        let signature = bytes[SIGNATURE_OFFSET..]
            .try_into()
            .expect("fixed signature field");
        Self::new(public_key, signature)
    }
}

impl fmt::Debug for ComponentArtifactAuthenticationEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactAuthenticationEvidenceV1")
            .field("algorithm", &self.algorithm())
            .field("public_key", &self.public_key)
            .field("signature", &self.signature)
            .field("runtime_ready", &false)
            .finish()
    }
}

/// Canonical detached-evidence decode or construction failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentArtifactAuthenticationError {
    EncodedLength { actual: usize },
    Magic,
    Version { actual: u16 },
    DeclaredLength { actual: u16 },
    Algorithm { actual: u16 },
    Flags { actual: u16 },
    ZeroPublicKey,
    ZeroSignature,
}

impl fmt::Display for ComponentArtifactAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLength { actual } => write!(
                formatter,
                "component authentication evidence is {actual} bytes, expected {COMPONENT_ARTIFACT_AUTHENTICATION_ENCODED_LEN}"
            ),
            Self::Magic => formatter.write_str("component authentication evidence magic is invalid"),
            Self::Version { .. } => {
                formatter.write_str("component authentication evidence version is unsupported")
            }
            Self::DeclaredLength { .. } => formatter
                .write_str("component authentication evidence declared length is invalid"),
            Self::Algorithm { .. } => formatter
                .write_str("component authentication evidence algorithm is unsupported"),
            Self::Flags { .. } => {
                formatter.write_str("component authentication evidence flags are non-zero")
            }
            Self::ZeroPublicKey => formatter
                .write_str("component authentication evidence public key is the zero sentinel"),
            Self::ZeroSignature => formatter
                .write_str("component authentication evidence signature is the zero sentinel"),
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed u16 field"),
    )
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
