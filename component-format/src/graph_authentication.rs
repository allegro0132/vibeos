//! Canonical detached authentication evidence for one Component graph version.
//!
//! This fixed-width value is deliberately domain-separated from the
//! Component-artifact evidence codec. It carries only a complete Ed25519
//! public key and signature and does not verify either, select policy, name a
//! durable object, or make a graph executable.

use core::fmt;

pub const COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC: [u8; 8] = *b"VIBEGSG\0";
pub const COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION: u16 = 1;
pub const COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN: usize = 112;
pub const COMPONENT_GRAPH_VERSION_AUTHENTICATION_OBJECT_KIND_RAW: u32 = 0x4347_4531;
pub const COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN: usize = 32;
pub const COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN: usize = 64;

const VERSION_OFFSET: usize = 8;
const TOTAL_LEN_OFFSET: usize = 10;
const ALGORITHM_OFFSET: usize = 12;
const FLAGS_OFFSET: usize = 14;
const PUBLIC_KEY_OFFSET: usize = 16;
const SIGNATURE_OFFSET: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentGraphVersionAuthenticationAlgorithm {
    Ed25519 = 1,
}

impl ComponentGraphVersionAuthenticationAlgorithm {
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

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentGraphVersionOperatorPublicKey(
    [u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN],
);

impl ComponentGraphVersionOperatorPublicKey {
    pub fn from_bytes(
        bytes: [u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN],
    ) -> Result<Self, ComponentGraphVersionAuthenticationError> {
        if is_zero(&bytes) {
            return Err(ComponentGraphVersionAuthenticationError::ZeroPublicKey);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN] {
        self.0
    }
}

impl fmt::Debug for ComponentGraphVersionOperatorPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentGraphVersionOperatorPublicKey(<redacted>)")
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentGraphVersionEd25519Signature(
    [u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN],
);

impl ComponentGraphVersionEd25519Signature {
    pub fn from_bytes(
        bytes: [u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ComponentGraphVersionAuthenticationError> {
        if is_zero(&bytes) {
            return Err(ComponentGraphVersionAuthenticationError::ZeroSignature);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN] {
        &self.0
    }

    pub const fn to_bytes(self) -> [u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN] {
        self.0
    }
}

impl fmt::Debug for ComponentGraphVersionEd25519Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentGraphVersionEd25519Signature(<redacted>)")
    }
}

/// Canonical, detached, and still-untrusted graph-version evidence.
///
/// ```compile_fail
/// use vibeos_component_format::ComponentGraphVersionAuthenticationEvidenceV1;
/// let _ = ComponentGraphVersionAuthenticationEvidenceV1 {
///     public_key: [1; 32],
///     signature: [2; 64],
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentGraphVersionAuthenticationEvidenceV1 {
    public_key: ComponentGraphVersionOperatorPublicKey,
    signature: ComponentGraphVersionEd25519Signature,
}

impl ComponentGraphVersionAuthenticationEvidenceV1 {
    pub fn new(
        public_key: [u8; COMPONENT_GRAPH_VERSION_OPERATOR_PUBLIC_KEY_LEN],
        signature: [u8; COMPONENT_GRAPH_VERSION_ED25519_SIGNATURE_LEN],
    ) -> Result<Self, ComponentGraphVersionAuthenticationError> {
        Ok(Self {
            public_key: ComponentGraphVersionOperatorPublicKey::from_bytes(public_key)?,
            signature: ComponentGraphVersionEd25519Signature::from_bytes(signature)?,
        })
    }

    pub const fn algorithm(&self) -> ComponentGraphVersionAuthenticationAlgorithm {
        ComponentGraphVersionAuthenticationAlgorithm::Ed25519
    }

    pub const fn public_key(&self) -> ComponentGraphVersionOperatorPublicKey {
        self.public_key
    }

    pub const fn signature(&self) -> ComponentGraphVersionEd25519Signature {
        self.signature
    }

    pub const fn encoded_len(&self) -> usize {
        COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    pub fn encode(&self) -> [u8; COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN] {
        let mut out = [0_u8; COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN];
        out[..8].copy_from_slice(&COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC);
        out[VERSION_OFFSET..VERSION_OFFSET + 2]
            .copy_from_slice(&COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION.to_le_bytes());
        out[TOTAL_LEN_OFFSET..TOTAL_LEN_OFFSET + 2].copy_from_slice(
            &(COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN as u16).to_le_bytes(),
        );
        out[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 2]
            .copy_from_slice(&self.algorithm().as_raw().to_le_bytes());
        out[FLAGS_OFFSET..FLAGS_OFFSET + 2].copy_from_slice(&0_u16.to_le_bytes());
        out[PUBLIC_KEY_OFFSET..SIGNATURE_OFFSET].copy_from_slice(self.public_key.as_bytes());
        out[SIGNATURE_OFFSET..].copy_from_slice(self.signature.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ComponentGraphVersionAuthenticationError> {
        if bytes.len() != COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN {
            return Err(ComponentGraphVersionAuthenticationError::EncodedLength {
                actual: bytes.len(),
            });
        }
        if bytes[..8] != COMPONENT_GRAPH_VERSION_AUTHENTICATION_MAGIC {
            return Err(ComponentGraphVersionAuthenticationError::Magic);
        }
        let version = read_u16(bytes, VERSION_OFFSET);
        if version != COMPONENT_GRAPH_VERSION_AUTHENTICATION_VERSION {
            return Err(ComponentGraphVersionAuthenticationError::Version { actual: version });
        }
        let declared_len = read_u16(bytes, TOTAL_LEN_OFFSET);
        if usize::from(declared_len) != COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN {
            return Err(ComponentGraphVersionAuthenticationError::DeclaredLength {
                actual: declared_len,
            });
        }
        let algorithm = read_u16(bytes, ALGORITHM_OFFSET);
        if ComponentGraphVersionAuthenticationAlgorithm::from_raw(algorithm)
            != Some(ComponentGraphVersionAuthenticationAlgorithm::Ed25519)
        {
            return Err(ComponentGraphVersionAuthenticationError::Algorithm { actual: algorithm });
        }
        let flags = read_u16(bytes, FLAGS_OFFSET);
        if flags != 0 {
            return Err(ComponentGraphVersionAuthenticationError::Flags { actual: flags });
        }
        let public_key = bytes[PUBLIC_KEY_OFFSET..SIGNATURE_OFFSET]
            .try_into()
            .expect("fixed graph public-key field");
        let signature = bytes[SIGNATURE_OFFSET..]
            .try_into()
            .expect("fixed graph signature field");
        Self::new(public_key, signature)
    }
}

impl fmt::Debug for ComponentGraphVersionAuthenticationEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphVersionAuthenticationEvidenceV1")
            .field("algorithm", &self.algorithm())
            .field("public_key", &self.public_key)
            .field("signature", &self.signature)
            .field("runtime_ready", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphVersionAuthenticationError {
    EncodedLength { actual: usize },
    Magic,
    Version { actual: u16 },
    DeclaredLength { actual: u16 },
    Algorithm { actual: u16 },
    Flags { actual: u16 },
    ZeroPublicKey,
    ZeroSignature,
}

impl fmt::Display for ComponentGraphVersionAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLength { actual } => write!(
                formatter,
                "component graph authentication evidence is {actual} bytes, expected {COMPONENT_GRAPH_VERSION_AUTHENTICATION_ENCODED_LEN}"
            ),
            Self::Magic => formatter.write_str("component graph authentication evidence magic is invalid"),
            Self::Version { .. } => formatter.write_str("component graph authentication evidence version is unsupported"),
            Self::DeclaredLength { .. } => formatter.write_str("component graph authentication evidence declared length is invalid"),
            Self::Algorithm { .. } => formatter.write_str("component graph authentication evidence algorithm is unsupported"),
            Self::Flags { .. } => formatter.write_str("component graph authentication evidence flags are non-zero"),
            Self::ZeroPublicKey => formatter.write_str("component graph authentication evidence public key is the zero sentinel"),
            Self::ZeroSignature => formatter.write_str("component graph authentication evidence signature is the zero sentinel"),
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed graph evidence u16 field"),
    )
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
