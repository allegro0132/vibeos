//! Canonical, inert durable envelope for one Component artifact.
//!
//! This module owns bytes and metadata only. Decoding proves a unique v1 wire
//! representation and content commitments; it does not validate Component
//! code, authenticate a signer, consult an object store, or grant execution
//! authority. C7 admission must independently validate the exact Component and
//! WIT inputs and authenticate the configured signer policy before deriving a
//! volatile command.

use alloc::{string::String, vec::Vec};
use core::{cmp::Ordering, fmt};
use sha2::{Digest, Sha256};

use crate::{ProfileIdentity, ProfileLimits, ProfileStage, ARTIFACT_MAGIC, PROFILE_1_LIMITS};

/// Stable durable ObjectKind tag for the canonical ComponentArtifact v1 body.
///
/// This number is content metadata only. It is never a lookup key or execution
/// right, and a future storage adapter must still require an exact trusted
/// ObjectKind policy before selecting this decoder.
pub const COMPONENT_ARTIFACT_OBJECT_KIND_RAW: u32 = 0x434d_5031;
pub const COMPONENT_ARTIFACT_FORMAT_VERSION: u16 = 1;
pub const COMPONENT_ARTIFACT_HEADER_LEN: usize = 352;
pub const COMPONENT_ARTIFACT_HASH_SHA256: u16 = 1;
pub const COMPONENT_ARTIFACT_MANIFEST_VERSION: u16 = 1;
pub const COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION: u16 = 1;

pub const MAX_COMPONENT_ARTIFACT_METADATA_BYTES: usize = 384 * 1024;
/// Aggregate durable-envelope ceiling: fixed header + bounded metadata + the
/// Profile 1 raw Component ceiling. This is deliberately separate from
/// [`ProfileLimits::max_artifact_bytes`], which governs the pre-C7 raw code
/// input. A cross-crate test proves this aggregate still fits one durable v1
/// object without making the portable codec depend on storage types.
pub const MAX_COMPONENT_ARTIFACT_ENCODED_BYTES: usize = COMPONENT_ARTIFACT_HEADER_LEN
    + MAX_COMPONENT_ARTIFACT_METADATA_BYTES
    + PROFILE_1_LIMITS.max_component_bytes;
pub const MAX_COMPONENT_ARTIFACT_WIT_PACKAGES: usize = 256;
pub const MAX_COMPONENT_ARTIFACT_INTERFACES: usize =
    PROFILE_1_LIMITS.max_imports as usize + PROFILE_1_LIMITS.max_exports as usize;
pub const MAX_COMPONENT_ARTIFACT_CORE_MODULES: usize =
    PROFILE_1_LIMITS.max_embedded_modules as usize;
pub const MAX_COMPONENT_ARTIFACT_ADAPTERS: usize = PROFILE_1_LIMITS.max_adapters as usize;

const CONTRACT_MAGIC: [u8; 8] = *b"VIBECTR\0";
const CONTRACT_VERSION: u16 = 1;
const CONTRACT_HEADER_LEN: usize = 24;
const MANIFEST_MAGIC: [u8; 8] = *b"VIBEMNF\0";
const MANIFEST_HEADER_LEN: usize = 40;
const PROFILE_REVISION_FIELD_COUNT: u16 = 5;
const PROFILE_LIMIT_FIELD_COUNT: u16 = 44;
const INSTANCE_LIMIT_FIELD_COUNT: u16 = 4;

const FLAGS_OFFSET: usize = 12;
const OBJECT_KIND_OFFSET: usize = 16;
const HASH_ALGORITHM_OFFSET: usize = 20;
const PROFILE_CODE_OFFSET: usize = 22;
const PROFILE_STAGE_OFFSET: usize = 24;
const MANIFEST_VERSION_OFFSET: usize = 26;
const SIGNER_KIND_OFFSET: usize = 28;
const SIGNER_VERSION_OFFSET: usize = 30;
const ARTIFACT_ABI_OFFSET: usize = 32;
const COMPONENT_PROFILE_OFFSET: usize = 34;
const CORE_PROFILE_OFFSET: usize = 36;
const RUNTIME_ABI_OFFSET: usize = 38;
const CANONICAL_FEATURES_OFFSET: usize = 40;
const CONTRACT_LEN_OFFSET: usize = 48;
const MANIFEST_LEN_OFFSET: usize = 56;
const COMPONENT_LEN_OFFSET: usize = 64;
const TOTAL_LEN_OFFSET: usize = 72;
const WIT_COUNT_OFFSET: usize = 80;
const INTERFACE_COUNT_OFFSET: usize = 84;
const MODULE_COUNT_OFFSET: usize = 88;
const ADAPTER_COUNT_OFFSET: usize = 92;
const PROFILE_LIMIT_COUNT_OFFSET: usize = 96;
const INSTANCE_LIMIT_COUNT_OFFSET: usize = 98;
const REVISION_COUNT_OFFSET: usize = 100;
const HEADER_RESERVED0_OFFSET: usize = 102;
const COMPONENT_HASH_OFFSET: usize = 104;
const CONTRACT_HASH_OFFSET: usize = 136;
const MANIFEST_HASH_OFFSET: usize = 168;
const BODY_HASH_OFFSET: usize = 200;
const SIGNER_POLICY_DIGEST_OFFSET: usize = 232;
const ARTIFACT_COMMITMENT_OFFSET: usize = 264;
const HEADER_RESERVED1_OFFSET: usize = 296;

const MAX_WORLD_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 256;
const MAX_VERSION_BYTES: usize = 512;
const MAX_SHAPE_BYTES: usize = 64 * 1024;
const MAX_WIT_SOURCE_BYTES: usize = 256 * 1024;
const MAX_ADAPTER_BYTES: usize = 64 * 1024;

const BODY_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.body.v1\0";
const COMMITMENT_DOMAIN: &[u8] = b"vibeos.component-artifact.commitment.v1\0";
const COMPONENT_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.component.v1\0";
const CONTRACT_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.contract.v1\0";
const MANIFEST_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.manifest.v1\0";
const WIT_SOURCE_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.wit-source.v1\0";
const CORE_MODULE_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.core-module.v1\0";
const ADAPTER_HASH_DOMAIN: &[u8] = b"vibeos.component-artifact.adapter.v1\0";
const COMPONENT_ARTIFACT_RUNTIME_READY: bool = false;
const _: () = assert!(!COMPONENT_ARTIFACT_RUNTIME_READY);

macro_rules! redacted_digest {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) fn checked(bytes: [u8; 32]) -> Result<Self, ComponentArtifactError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    Err(ComponentArtifactError::ZeroDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

redacted_digest!(ComponentArtifactComponentCommitment);
redacted_digest!(ComponentArtifactCommitment);
redacted_digest!(ComponentArtifactPolicyDigest);
redacted_digest!(ComponentArtifactWitSourceCommitment);
redacted_digest!(ComponentArtifactCoreModuleCommitment);
redacted_digest!(ComponentArtifactAdapterCommitment);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComponentArtifactInterfaceDirection {
    Import = 1,
    Export = 2,
}

impl ComponentArtifactInterfaceDirection {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Import),
            2 => Some(Self::Export),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComponentArtifactEntityKind {
    Function = 1,
    Interface = 2,
    Type = 3,
}

impl ComponentArtifactEntityKind {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Function),
            2 => Some(Self::Interface),
            3 => Some(Self::Type),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ComponentArtifactSignerPolicyKind {
    DevelopmentImagePin = 1,
    OperatorRequired = 2,
}

impl ComponentArtifactSignerPolicyKind {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::DevelopmentImagePin),
            2 => Some(Self::OperatorRequired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComponentArtifactSignerPolicyV1 {
    kind: ComponentArtifactSignerPolicyKind,
    policy_digest: ComponentArtifactPolicyDigest,
}

impl ComponentArtifactSignerPolicyV1 {
    /// Bind a development artifact to one externally trusted image-policy
    /// descriptor. The digest identifies that descriptor; it does not
    /// authenticate itself.
    pub fn development_image_pin(policy_sha256: [u8; 32]) -> Result<Self, ComponentArtifactError> {
        Self::new(
            ComponentArtifactSignerPolicyKind::DevelopmentImagePin,
            policy_sha256,
        )
    }

    /// Require an externally configured operator policy. C7.3 owns the
    /// algorithm, key set, signature verification, and authenticity decision.
    pub fn operator_required(policy_sha256: [u8; 32]) -> Result<Self, ComponentArtifactError> {
        Self::new(
            ComponentArtifactSignerPolicyKind::OperatorRequired,
            policy_sha256,
        )
    }

    fn new(
        kind: ComponentArtifactSignerPolicyKind,
        policy_sha256: [u8; 32],
    ) -> Result<Self, ComponentArtifactError> {
        Ok(Self {
            kind,
            policy_digest: ComponentArtifactPolicyDigest::checked(policy_sha256)
                .map_err(|_| ComponentArtifactError::SignerPolicy)?,
        })
    }

    pub const fn kind(&self) -> ComponentArtifactSignerPolicyKind {
        self.kind
    }

    pub const fn policy_digest(&self) -> ComponentArtifactPolicyDigest {
        self.policy_digest
    }
}

impl fmt::Debug for ComponentArtifactSignerPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactSignerPolicyV1")
            .field("kind", &self.kind)
            .field("policy_digest", &self.policy_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentArtifactInstanceLimitsV1 {
    memory_bytes: u64,
    total_fuel: u64,
    poll_quantum: u64,
    resources: u64,
}

impl ComponentArtifactInstanceLimitsV1 {
    pub fn new(
        memory_bytes: u64,
        total_fuel: u64,
        poll_quantum: u64,
        resources: u64,
    ) -> Result<Self, ComponentArtifactError> {
        let maximum_memory = u64::from(PROFILE_1_LIMITS.max_memory_pages) * 65_536;
        if memory_bytes == 0
            || memory_bytes > maximum_memory
            || total_fuel == 0
            || total_fuel > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_fuel
            || resources == 0
            || resources > u64::from(PROFILE_1_LIMITS.max_resources)
        {
            return Err(ComponentArtifactError::Limits);
        }
        Ok(Self {
            memory_bytes,
            total_fuel,
            poll_quantum,
            resources,
        })
    }

    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    pub const fn total_fuel(self) -> u64 {
        self.total_fuel
    }

    pub const fn poll_quantum(self) -> u64 {
        self.poll_quantum
    }

    pub const fn resources(self) -> u64 {
        self.resources
    }

    fn values(self) -> [u64; INSTANCE_LIMIT_FIELD_COUNT as usize] {
        [
            self.memory_bytes,
            self.total_fuel,
            self.poll_quantum,
            self.resources,
        ]
    }
}

#[derive(PartialEq, Eq)]
pub struct ComponentArtifactWitPackageV1 {
    name: String,
    version: String,
    source: String,
    source_commitment: ComponentArtifactWitSourceCommitment,
}

impl ComponentArtifactWitPackageV1 {
    pub fn new(name: &str, version: &str, source: &str) -> Result<Self, ComponentArtifactError> {
        let source = copied_source(source)?;
        Ok(Self {
            name: copied_token(name, MAX_NAME_BYTES)?,
            version: copied_token(version, MAX_VERSION_BYTES)?,
            source_commitment: ComponentArtifactWitSourceCommitment::checked(hash_role(
                WIT_SOURCE_HASH_DOMAIN,
                source.as_bytes(),
            ))?,
            source,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Exact UTF-8 WIT source bytes. No package, filesystem, hash, or name
    /// lookup is needed to recover this inert input on a later boot.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub const fn source_commitment(&self) -> ComponentArtifactWitSourceCommitment {
        self.source_commitment
    }
}

impl fmt::Debug for ComponentArtifactWitPackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactWitPackageV1")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("source_bytes", &self.source.len())
            .field("source_commitment", &self.source_commitment)
            .finish()
    }
}

/// A bounded diagnostic/revalidation copy of one selected world entity.
///
/// `diagnostic_shape` is never admission authority: C7.5 must parse the exact
/// embedded WIT source and Component bytes again and compare fresh typed
/// validator evidence. In particular, this text cannot repair or authorize a
/// nominal resource identity.
#[derive(Debug, PartialEq, Eq)]
pub struct ComponentArtifactInterfaceV1 {
    direction: ComponentArtifactInterfaceDirection,
    kind: ComponentArtifactEntityKind,
    name: String,
    diagnostic_shape: String,
}

impl ComponentArtifactInterfaceV1 {
    pub fn new(
        direction: ComponentArtifactInterfaceDirection,
        kind: ComponentArtifactEntityKind,
        name: &str,
        diagnostic_shape: &str,
    ) -> Result<Self, ComponentArtifactError> {
        Ok(Self {
            direction,
            kind,
            name: copied_token(name, MAX_NAME_BYTES)?,
            diagnostic_shape: copied_token(diagnostic_shape, MAX_SHAPE_BYTES)?,
        })
    }

    pub const fn direction(&self) -> ComponentArtifactInterfaceDirection {
        self.direction
    }

    pub const fn kind(&self) -> ComponentArtifactEntityKind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn diagnostic_shape(&self) -> &str {
        &self.diagnostic_shape
    }
}

#[derive(PartialEq, Eq)]
pub struct ComponentArtifactCoreModuleV1 {
    byte_len: u32,
    commitment: ComponentArtifactCoreModuleCommitment,
}

impl ComponentArtifactCoreModuleV1 {
    /// Record one embedded Core module in exact Component traversal order.
    /// The bytes remain in the Component payload; C7.5 must rediscover them
    /// with a fresh validator and compare this length/hash diagnostic copy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ComponentArtifactError> {
        if bytes.is_empty() || bytes.len() > PROFILE_1_LIMITS.max_core_module_bytes {
            return Err(ComponentArtifactError::Manifest);
        }
        Ok(Self {
            byte_len: usize_u32(bytes.len())?,
            commitment: ComponentArtifactCoreModuleCommitment::checked(hash_role(
                CORE_MODULE_HASH_DOMAIN,
                bytes,
            ))?,
        })
    }

    fn from_parts(byte_len: u32, commitment: [u8; 32]) -> Result<Self, ComponentArtifactError> {
        let byte_len = u32_usize(byte_len)?;
        if byte_len == 0 || byte_len > PROFILE_1_LIMITS.max_core_module_bytes {
            return Err(ComponentArtifactError::Manifest);
        }
        Ok(Self {
            byte_len: usize_u32(byte_len)?,
            commitment: ComponentArtifactCoreModuleCommitment::checked(commitment)?,
        })
    }

    pub const fn byte_len(&self) -> u32 {
        self.byte_len
    }

    pub const fn commitment(&self) -> ComponentArtifactCoreModuleCommitment {
        self.commitment
    }
}

impl fmt::Debug for ComponentArtifactCoreModuleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactCoreModuleV1")
            .field("byte_len", &self.byte_len)
            .field("commitment", &self.commitment)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct ComponentArtifactAdapterV1 {
    ordinal: u32,
    revision: String,
    bytes: Vec<u8>,
    commitment: ComponentArtifactAdapterCommitment,
}

impl ComponentArtifactAdapterV1 {
    pub fn new(ordinal: u32, revision: &str, bytes: &[u8]) -> Result<Self, ComponentArtifactError> {
        if bytes.is_empty() || bytes.len() > MAX_ADAPTER_BYTES {
            return Err(ComponentArtifactError::Manifest);
        }
        let bytes = copied_bytes(bytes)?;
        Ok(Self {
            ordinal,
            revision: copied_token(revision, MAX_VERSION_BYTES)?,
            commitment: ComponentArtifactAdapterCommitment::checked(hash_role(
                ADAPTER_HASH_DOMAIN,
                &bytes,
            ))?,
            bytes,
        })
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Exact bounded descriptor bytes supplied by a future validator. C7.1
    /// treats them as an untrusted claim; C7.5 must recompute them from the
    /// exact Component before admission. They never select an ambient adapter.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn commitment(&self) -> ComponentArtifactAdapterCommitment {
        self.commitment
    }
}

impl fmt::Debug for ComponentArtifactAdapterV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactAdapterV1")
            .field("ordinal", &self.ordinal)
            .field("revision", &self.revision)
            .field("bytes", &self.bytes.len())
            .field("commitment", &self.commitment)
            .finish()
    }
}

#[derive(PartialEq, Eq)]
pub struct ComponentArtifactManifestV1 {
    world: String,
    wit_packages: Vec<ComponentArtifactWitPackageV1>,
    interfaces: Vec<ComponentArtifactInterfaceV1>,
    core_modules: Vec<ComponentArtifactCoreModuleV1>,
    adapters: Vec<ComponentArtifactAdapterV1>,
}

impl ComponentArtifactManifestV1 {
    pub fn new(
        world: &str,
        mut wit_packages: Vec<ComponentArtifactWitPackageV1>,
        mut interfaces: Vec<ComponentArtifactInterfaceV1>,
        core_modules: Vec<ComponentArtifactCoreModuleV1>,
        mut adapters: Vec<ComponentArtifactAdapterV1>,
    ) -> Result<Self, ComponentArtifactError> {
        if wit_packages.is_empty()
            || wit_packages.len() > MAX_COMPONENT_ARTIFACT_WIT_PACKAGES
            || interfaces.len() > MAX_COMPONENT_ARTIFACT_INTERFACES
            || core_modules.len() > MAX_COMPONENT_ARTIFACT_CORE_MODULES
            || adapters.len() > MAX_COMPONENT_ARTIFACT_ADAPTERS
        {
            return Err(ComponentArtifactError::Manifest);
        }
        let import_count = interfaces
            .iter()
            .filter(|interface| interface.direction == ComponentArtifactInterfaceDirection::Import)
            .count();
        let export_count = interfaces.len() - import_count;
        if import_count > u32_usize(PROFILE_1_LIMITS.max_imports)?
            || export_count > u32_usize(PROFILE_1_LIMITS.max_exports)?
        {
            return Err(ComponentArtifactError::Manifest);
        }
        let world = copied_token(world, MAX_WORLD_BYTES)?;
        wit_packages.sort_unstable_by(compare_wit_packages);
        interfaces.sort_unstable_by(compare_interfaces);
        adapters.sort_unstable_by_key(|adapter| adapter.ordinal);
        if wit_packages
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name && pair[0].version == pair[1].version)
            || interfaces
                .windows(2)
                .any(|pair| pair[0].direction == pair[1].direction && pair[0].name == pair[1].name)
            || adapters
                .windows(2)
                .any(|pair| pair[0].ordinal == pair[1].ordinal)
        {
            return Err(ComponentArtifactError::DuplicateManifestEntry);
        }
        for module in &core_modules {
            reject_zero_digest(module.commitment.as_bytes())?;
        }
        for package in &wit_packages {
            reject_zero_digest(package.source_commitment.as_bytes())?;
        }
        for (expected_ordinal, adapter) in adapters.iter().enumerate() {
            if adapter.ordinal != usize_u32(expected_ordinal)? {
                return Err(ComponentArtifactError::Manifest);
            }
            reject_zero_digest(adapter.commitment.as_bytes())?;
        }
        let manifest = Self {
            world,
            wit_packages,
            interfaces,
            core_modules,
            adapters,
        };
        let encoded = manifest.encode()?;
        if encoded.len() > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        Ok(manifest)
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub fn wit_packages(&self) -> &[ComponentArtifactWitPackageV1] {
        &self.wit_packages
    }

    pub fn interfaces(&self) -> &[ComponentArtifactInterfaceV1] {
        &self.interfaces
    }

    pub fn core_modules(&self) -> &[ComponentArtifactCoreModuleV1] {
        &self.core_modules
    }

    pub fn adapters(&self) -> &[ComponentArtifactAdapterV1] {
        &self.adapters
    }
}

fn encode_contract(
    profile: ProfileIdentity,
    instance_limits: ComponentArtifactInstanceLimitsV1,
) -> Result<Vec<u8>, ComponentArtifactError> {
    profile_code(profile).ok_or(ComponentArtifactError::Profile)?;
    let revisions = profile_revisions(profile);
    let mut total = CONTRACT_HEADER_LEN;
    for revision in revisions {
        validate_token(revision, MAX_VERSION_BYTES)?;
        total = checked_add_many(total, &[4, revision.len()])?;
    }
    total = PROFILE_LIMIT_FIELD_COUNT
        .checked_add(INSTANCE_LIMIT_FIELD_COUNT)
        .and_then(|count| usize::from(count).checked_mul(8))
        .and_then(|bytes| total.checked_add(bytes))
        .ok_or(ComponentArtifactError::Length)?;
    if total > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
        return Err(ComponentArtifactError::TooLarge);
    }

    let mut out = zeroed(total)?;
    out[0..8].copy_from_slice(&CONTRACT_MAGIC);
    put_u16(&mut out, 8, CONTRACT_VERSION)?;
    put_u16(&mut out, 10, usize_u16(CONTRACT_HEADER_LEN)?)?;
    put_u32(&mut out, 12, 0)?;
    put_u16(&mut out, 16, PROFILE_REVISION_FIELD_COUNT)?;
    put_u16(&mut out, 18, PROFILE_LIMIT_FIELD_COUNT)?;
    put_u16(&mut out, 20, INSTANCE_LIMIT_FIELD_COUNT)?;
    put_u16(&mut out, 22, 0)?;

    let mut offset = CONTRACT_HEADER_LEN;
    for revision in revisions {
        write_u32(&mut out, &mut offset, usize_u32(revision.len())?)?;
        write_bytes(&mut out, &mut offset, revision.as_bytes())?;
    }
    for value in profile_limit_values()? {
        write_u64(&mut out, &mut offset, value)?;
    }
    for value in instance_limits.values() {
        write_u64(&mut out, &mut offset, value)?;
    }
    if offset != total {
        return Err(ComponentArtifactError::Length);
    }
    Ok(out)
}

fn decode_contract(
    bytes: &[u8],
    profile: ProfileIdentity,
) -> Result<ComponentArtifactInstanceLimitsV1, ComponentArtifactError> {
    if bytes.len() < CONTRACT_HEADER_LEN {
        return Err(ComponentArtifactError::Truncated);
    }
    if bytes.len() > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
        return Err(ComponentArtifactError::TooLarge);
    }
    if bytes.get(0..8) != Some(CONTRACT_MAGIC.as_slice()) {
        return Err(ComponentArtifactError::Contract);
    }
    if get_u16(bytes, 8)? != CONTRACT_VERSION
        || usize::from(get_u16(bytes, 10)?) != CONTRACT_HEADER_LEN
        || get_u16(bytes, 16)? != PROFILE_REVISION_FIELD_COUNT
        || get_u16(bytes, 18)? != PROFILE_LIMIT_FIELD_COUNT
        || get_u16(bytes, 20)? != INSTANCE_LIMIT_FIELD_COUNT
    {
        return Err(ComponentArtifactError::Version);
    }
    if get_u32(bytes, 12)? != 0 || get_u16(bytes, 22)? != 0 {
        return Err(ComponentArtifactError::Reserved);
    }

    let mut cursor = Cursor::at(bytes, CONTRACT_HEADER_LEN)?;
    for expected in profile_revisions(profile) {
        let length = u32_usize(cursor.read_u32()?)?;
        if length == 0 || length > MAX_VERSION_BYTES {
            return Err(ComponentArtifactError::Contract);
        }
        let actual = text(cursor.take(length)?)?;
        if actual != expected {
            return Err(ComponentArtifactError::Profile);
        }
    }
    for expected in profile_limit_values()? {
        if cursor.read_u64()? != expected {
            return Err(ComponentArtifactError::Limits);
        }
    }
    let memory_bytes = cursor.read_u64()?;
    let total_fuel = cursor.read_u64()?;
    let poll_quantum = cursor.read_u64()?;
    let resources = cursor.read_u64()?;
    cursor.finish()?;
    let limits =
        ComponentArtifactInstanceLimitsV1::new(memory_bytes, total_fuel, poll_quantum, resources)?;
    if encode_contract(profile, limits)?.as_slice() != bytes {
        return Err(ComponentArtifactError::NonCanonical);
    }
    Ok(limits)
}

fn profile_revisions(profile: ProfileIdentity) -> [&'static str; 5] {
    [
        profile.core_revision,
        profile.component_revision,
        profile.canonical_abi_revision,
        profile.wasm_tools_revision,
        profile.wasi_revision,
    ]
}

fn profile_limit_values(
) -> Result<[u64; PROFILE_LIMIT_FIELD_COUNT as usize], ComponentArtifactError> {
    let limits = PROFILE_1_LIMITS;
    Ok([
        usize_u64(limits.max_artifact_bytes)?,
        usize_u64(limits.max_component_bytes)?,
        usize_u64(limits.max_core_module_bytes)?,
        u64::from(limits.max_component_nesting),
        u64::from(limits.max_core_nesting),
        u64::from(limits.max_types),
        u64::from(limits.max_functions),
        u64::from(limits.max_params_per_function),
        u64::from(limits.max_results_per_function),
        u64::from(limits.max_imports),
        u64::from(limits.max_exports),
        u64::from(limits.max_globals),
        u64::from(limits.max_locals_per_function),
        u64::from(limits.max_memories),
        u64::from(limits.max_initial_memory_pages),
        u64::from(limits.max_memory_pages),
        u64::from(limits.max_tables),
        u64::from(limits.max_table_elements),
        u64::from(limits.max_data_segments),
        u64::from(limits.max_element_segments),
        u64::from(limits.max_custom_sections),
        usize_u64(limits.max_custom_section_bytes)?,
        u64::from(limits.max_embedded_modules),
        u64::from(limits.max_component_instances),
        u64::from(limits.max_component_definitions),
        u64::from(limits.max_aliases),
        u64::from(limits.max_canonical_functions),
        u64::from(limits.max_canonical_options),
        u64::from(limits.max_canonical_options_per_function),
        u64::from(limits.max_async_functions),
        u64::from(limits.max_future_types),
        u64::from(limits.max_stream_types),
        u64::from(limits.max_adapters),
        u64::from(limits.max_resources),
        u64::from(limits.max_call_depth),
        usize_u64(limits.max_canonical_value_bytes)?,
        u64::from(limits.max_canonical_nesting),
        u64::from(limits.max_canonical_values),
        u64::from(limits.max_abi_allocations),
        u64::from(limits.max_cleanup_actions),
        usize_u64(limits.max_string_bytes)?,
        u64::from(limits.max_list_elements),
        limits.total_fuel,
        limits.poll_quantum,
    ])
}

pub(crate) fn profile_code(profile: ProfileIdentity) -> Option<u16> {
    if profile == ProfileIdentity::PROFILE_1_SYNC {
        Some(1)
    } else if profile == ProfileIdentity::PROFILE_1_ASYNC {
        Some(2)
    } else if profile == ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE {
        Some(3)
    } else if profile == ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED {
        Some(4)
    } else {
        None
    }
}

pub(crate) fn profile_from_code(code: u16) -> Option<ProfileIdentity> {
    match code {
        1 => Some(ProfileIdentity::PROFILE_1_SYNC),
        2 => Some(ProfileIdentity::PROFILE_1_ASYNC),
        3 => Some(ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE),
        4 => Some(ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED),
        _ => None,
    }
}

pub(crate) const fn profile_stage_raw(stage: ProfileStage) -> u16 {
    match stage {
        ProfileStage::Executable => 1,
        ProfileStage::ValidationOnly => 2,
    }
}

fn validate_component_len(length: usize) -> Result<(), ComponentArtifactError> {
    if length == 0 {
        return Err(ComponentArtifactError::EmptyComponent);
    }
    if length > PROFILE_1_LIMITS.max_component_bytes {
        return Err(ComponentArtifactError::TooLarge);
    }
    Ok(())
}

fn validate_token(value: &str, maximum: usize) -> Result<(), ComponentArtifactError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(ComponentArtifactError::InvalidText);
    }
    Ok(())
}

fn copied_token(value: &str, maximum: usize) -> Result<String, ComponentArtifactError> {
    validate_token(value, maximum)?;
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentArtifactError::Allocation)?;
    copied.push_str(value);
    Ok(copied)
}

fn copied_source(value: &str) -> Result<String, ComponentArtifactError> {
    if value.is_empty() || value.len() > MAX_WIT_SOURCE_BYTES || value.as_bytes().contains(&0) {
        return Err(ComponentArtifactError::InvalidText);
    }
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| ComponentArtifactError::Allocation)?;
    copied.push_str(value);
    Ok(copied)
}

fn copied_bytes(bytes: &[u8]) -> Result<Vec<u8>, ComponentArtifactError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| ComponentArtifactError::Allocation)?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn reserved_vec<T>(count: usize) -> Result<Vec<T>, ComponentArtifactError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ComponentArtifactError::Allocation)?;
    Ok(values)
}

fn reject_zero_digest(digest: &[u8; 32]) -> Result<(), ComponentArtifactError> {
    if digest.iter().all(|byte| *byte == 0) {
        Err(ComponentArtifactError::ZeroDigest)
    } else {
        Ok(())
    }
}

fn text(bytes: &[u8]) -> Result<&str, ComponentArtifactError> {
    core::str::from_utf8(bytes).map_err(|_| ComponentArtifactError::Utf8)
}

fn checked_add_many(mut total: usize, values: &[usize]) -> Result<usize, ComponentArtifactError> {
    for value in values {
        total = total
            .checked_add(*value)
            .ok_or(ComponentArtifactError::Length)?;
    }
    Ok(total)
}

fn zeroed(length: usize) -> Result<Vec<u8>, ComponentArtifactError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ComponentArtifactError::Allocation)?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn usize_u16(value: usize) -> Result<u16, ComponentArtifactError> {
    u16::try_from(value).map_err(|_| ComponentArtifactError::Length)
}

fn usize_u32(value: usize) -> Result<u32, ComponentArtifactError> {
    u32::try_from(value).map_err(|_| ComponentArtifactError::Length)
}

fn usize_u64(value: usize) -> Result<u64, ComponentArtifactError> {
    u64::try_from(value).map_err(|_| ComponentArtifactError::Length)
}

fn u32_usize(value: u32) -> Result<usize, ComponentArtifactError> {
    usize::try_from(value).map_err(|_| ComponentArtifactError::Length)
}

fn u64_usize(value: u64) -> Result<usize, ComponentArtifactError> {
    usize::try_from(value).map_err(|_| ComponentArtifactError::Length)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), ComponentArtifactError> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), ComponentArtifactError> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), ComponentArtifactError> {
    put_fixed(bytes, offset, &value.to_le_bytes())
}

fn put_fixed(bytes: &mut [u8], offset: usize, value: &[u8]) -> Result<(), ComponentArtifactError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(ComponentArtifactError::Length)?;
    let target = bytes
        .get_mut(offset..end)
        .ok_or(ComponentArtifactError::Length)?;
    target.copy_from_slice(value);
    Ok(())
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, ComponentArtifactError> {
    let raw: [u8; 2] = fixed(bytes, offset)?;
    Ok(u16::from_le_bytes(raw))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, ComponentArtifactError> {
    let raw: [u8; 4] = fixed(bytes, offset)?;
    Ok(u32::from_le_bytes(raw))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, ComponentArtifactError> {
    let raw: [u8; 8] = fixed(bytes, offset)?;
    Ok(u64::from_le_bytes(raw))
}

fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ComponentArtifactError> {
    let end = offset
        .checked_add(N)
        .ok_or(ComponentArtifactError::Length)?;
    bytes
        .get(offset..end)
        .ok_or(ComponentArtifactError::Truncated)?
        .try_into()
        .map_err(|_| ComponentArtifactError::Truncated)
}

fn read_hash(bytes: &[u8], offset: usize) -> Result<[u8; 32], ComponentArtifactError> {
    fixed(bytes, offset)
}

fn write_u8(bytes: &mut [u8], offset: &mut usize, value: u8) -> Result<(), ComponentArtifactError> {
    write_bytes(bytes, offset, &[value])
}

fn write_u16(
    bytes: &mut [u8],
    offset: &mut usize,
    value: u16,
) -> Result<(), ComponentArtifactError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_u32(
    bytes: &mut [u8],
    offset: &mut usize,
    value: u32,
) -> Result<(), ComponentArtifactError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_u64(
    bytes: &mut [u8],
    offset: &mut usize,
    value: u64,
) -> Result<(), ComponentArtifactError> {
    write_bytes(bytes, offset, &value.to_le_bytes())
}

fn write_bytes(
    bytes: &mut [u8],
    offset: &mut usize,
    value: &[u8],
) -> Result<(), ComponentArtifactError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(ComponentArtifactError::Length)?;
    let target = bytes
        .get_mut(*offset..end)
        .ok_or(ComponentArtifactError::Length)?;
    target.copy_from_slice(value);
    *offset = end;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn at(bytes: &'a [u8], offset: usize) -> Result<Self, ComponentArtifactError> {
        if offset > bytes.len() {
            return Err(ComponentArtifactError::Truncated);
        }
        Ok(Self { bytes, offset })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ComponentArtifactError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ComponentArtifactError::Length)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ComponentArtifactError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, ComponentArtifactError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ComponentArtifactError> {
        let raw: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ComponentArtifactError::Truncated)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn read_u32(&mut self) -> Result<u32, ComponentArtifactError> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ComponentArtifactError::Truncated)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn read_u64(&mut self) -> Result<u64, ComponentArtifactError> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ComponentArtifactError::Truncated)?;
        Ok(u64::from_le_bytes(raw))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], ComponentArtifactError> {
        self.take(32)?
            .try_into()
            .map_err(|_| ComponentArtifactError::Truncated)
    }

    fn finish(self) -> Result<(), ComponentArtifactError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ComponentArtifactError::Length)
        }
    }
}

fn hash_role(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(usize_u64_infallible(bytes.len()).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_body(contract: &[u8], manifest: &[u8], component: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BODY_HASH_DOMAIN);
    hasher.update(usize_u64_infallible(contract.len()).to_le_bytes());
    hasher.update(contract);
    hasher.update(usize_u64_infallible(manifest.len()).to_le_bytes());
    hasher.update(manifest);
    hasher.update(usize_u64_infallible(component.len()).to_le_bytes());
    hasher.update(component);
    hasher.finalize().into()
}

fn hash_commitment(bytes: &[u8]) -> Result<[u8; 32], ComponentArtifactError> {
    if bytes.len() < COMPONENT_ARTIFACT_HEADER_LEN {
        return Err(ComponentArtifactError::Truncated);
    }
    let after = ARTIFACT_COMMITMENT_OFFSET
        .checked_add(32)
        .ok_or(ComponentArtifactError::Length)?;
    let prefix = bytes
        .get(..ARTIFACT_COMMITMENT_OFFSET)
        .ok_or(ComponentArtifactError::Truncated)?;
    let suffix = bytes
        .get(after..)
        .ok_or(ComponentArtifactError::Truncated)?;
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(usize_u64(bytes.len())?.to_le_bytes());
    hasher.update(prefix);
    hasher.update([0_u8; 32]);
    hasher.update(suffix);
    Ok(hasher.finalize().into())
}

const fn usize_u64_infallible(value: usize) -> u64 {
    value as u64
}

impl fmt::Debug for ComponentArtifactManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactManifestV1")
            .field("world", &self.world)
            .field("wit_packages", &self.wit_packages.len())
            .field("interfaces", &self.interfaces.len())
            .field("core_modules", &self.core_modules.len())
            .field("adapters", &self.adapters.len())
            .finish()
    }
}

fn compare_wit_packages(
    left: &ComponentArtifactWitPackageV1,
    right: &ComponentArtifactWitPackageV1,
) -> Ordering {
    left.name
        .cmp(&right.name)
        .then_with(|| left.version.cmp(&right.version))
}

fn compare_interfaces(
    left: &ComponentArtifactInterfaceV1,
    right: &ComponentArtifactInterfaceV1,
) -> Ordering {
    left.direction
        .cmp(&right.direction)
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.diagnostic_shape.cmp(&right.diagnostic_shape))
}

/// Owned canonical v1 envelope. This remains inert after decoding: it has no
/// admission, lookup, installation, invocation, or execution method.
///
/// ```compile_fail
/// use vibeos_component_format::ComponentArtifactV1;
/// fn cannot_invoke(artifact: &ComponentArtifactV1) {
///     artifact.invoke();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::ComponentArtifactV1;
/// fn no_ambient_lookup(artifact: &ComponentArtifactV1) {
///     artifact.lookup_by_name("vibe:ambient");
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_format::ComponentArtifactV1;
/// fn no_durable_identity(artifact: &ComponentArtifactV1) {
///     let _ = artifact.object_id();
/// }
/// ```
#[derive(PartialEq, Eq)]
pub struct ComponentArtifactV1 {
    profile: ProfileIdentity,
    instance_limits: ComponentArtifactInstanceLimitsV1,
    signer_policy: ComponentArtifactSignerPolicyV1,
    manifest: ComponentArtifactManifestV1,
    component: Vec<u8>,
    component_commitment: ComponentArtifactComponentCommitment,
}

impl ComponentArtifactV1 {
    pub fn new(
        component: &[u8],
        profile: ProfileIdentity,
        instance_limits: ComponentArtifactInstanceLimitsV1,
        signer_policy: ComponentArtifactSignerPolicyV1,
        manifest: ComponentArtifactManifestV1,
    ) -> Result<Self, ComponentArtifactError> {
        profile_code(profile).ok_or(ComponentArtifactError::Profile)?;
        validate_component_len(component.len())?;
        // Revalidate even though the public constructor is sealed. This keeps
        // future internal decode paths from bypassing the exact v1 ceilings.
        ComponentArtifactInstanceLimitsV1::new(
            instance_limits.memory_bytes,
            instance_limits.total_fuel,
            instance_limits.poll_quantum,
            instance_limits.resources,
        )?;
        ComponentArtifactSignerPolicyV1::new(
            signer_policy.kind,
            *signer_policy.policy_digest.as_bytes(),
        )?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(component.len())
            .map_err(|_| ComponentArtifactError::Allocation)?;
        owned.extend_from_slice(component);
        let artifact = Self {
            profile,
            instance_limits,
            signer_policy,
            manifest,
            component_commitment: ComponentArtifactComponentCommitment::checked(hash_role(
                COMPONENT_HASH_DOMAIN,
                component,
            ))?,
            component: owned,
        };
        // Prove the combined envelope fits the separately frozen durable
        // aggregate bound before this value can escape.
        let _ = artifact.encode()?;
        Ok(artifact)
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn profile_limits(&self) -> ProfileLimits {
        PROFILE_1_LIMITS
    }

    pub const fn instance_limits(&self) -> ComponentArtifactInstanceLimitsV1 {
        self.instance_limits
    }

    pub const fn signer_policy(&self) -> ComponentArtifactSignerPolicyV1 {
        self.signer_policy
    }

    pub fn manifest(&self) -> &ComponentArtifactManifestV1 {
        &self.manifest
    }

    pub fn component_bytes(&self) -> &[u8] {
        &self.component
    }

    pub const fn component_commitment(&self) -> ComponentArtifactComponentCommitment {
        self.component_commitment
    }

    /// A canonical envelope is still unauthenticated and non-executable.
    pub const fn runtime_ready(&self) -> bool {
        COMPONENT_ARTIFACT_RUNTIME_READY
    }

    /// Stable content commitment over every canonical header and body byte.
    /// It is suitable as C7.3 signature input, but is not authentication by
    /// itself and must never be treated as execution authority.
    pub fn artifact_commitment(
        &self,
    ) -> Result<ComponentArtifactCommitment, ComponentArtifactError> {
        let encoded = self.encode()?;
        ComponentArtifactCommitment::checked(read_hash(&encoded, ARTIFACT_COMMITMENT_OFFSET)?)
    }

    /// Produce the one canonical little-endian v1 representation.
    pub fn encode(&self) -> Result<Vec<u8>, ComponentArtifactError> {
        let contract = encode_contract(self.profile, self.instance_limits)?;
        let manifest = self.manifest.encode()?;
        let metadata_len = contract
            .len()
            .checked_add(manifest.len())
            .ok_or(ComponentArtifactError::Length)?;
        if metadata_len > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        let total = COMPONENT_ARTIFACT_HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|value| value.checked_add(self.component.len()))
            .ok_or(ComponentArtifactError::Length)?;
        if total > MAX_COMPONENT_ARTIFACT_ENCODED_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        let mut out = zeroed(total)?;
        out[0..8].copy_from_slice(&ARTIFACT_MAGIC);
        put_u16(&mut out, 8, COMPONENT_ARTIFACT_FORMAT_VERSION)?;
        put_u16(
            &mut out,
            10,
            u16::try_from(COMPONENT_ARTIFACT_HEADER_LEN)
                .map_err(|_| ComponentArtifactError::Length)?,
        )?;
        put_u32(&mut out, FLAGS_OFFSET, 0)?;
        put_u32(
            &mut out,
            OBJECT_KIND_OFFSET,
            COMPONENT_ARTIFACT_OBJECT_KIND_RAW,
        )?;
        put_u16(
            &mut out,
            HASH_ALGORITHM_OFFSET,
            COMPONENT_ARTIFACT_HASH_SHA256,
        )?;
        put_u16(
            &mut out,
            PROFILE_CODE_OFFSET,
            profile_code(self.profile).ok_or(ComponentArtifactError::Profile)?,
        )?;
        put_u16(
            &mut out,
            PROFILE_STAGE_OFFSET,
            profile_stage_raw(self.profile.stage),
        )?;
        put_u16(
            &mut out,
            MANIFEST_VERSION_OFFSET,
            COMPONENT_ARTIFACT_MANIFEST_VERSION,
        )?;
        put_u16(&mut out, SIGNER_KIND_OFFSET, self.signer_policy.kind as u16)?;
        put_u16(
            &mut out,
            SIGNER_VERSION_OFFSET,
            COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION,
        )?;
        put_u16(&mut out, ARTIFACT_ABI_OFFSET, self.profile.artifact_abi)?;
        put_u16(
            &mut out,
            COMPONENT_PROFILE_OFFSET,
            self.profile.component_profile,
        )?;
        put_u16(&mut out, CORE_PROFILE_OFFSET, self.profile.core_profile)?;
        put_u16(&mut out, RUNTIME_ABI_OFFSET, self.profile.runtime_abi)?;
        put_u64(
            &mut out,
            CANONICAL_FEATURES_OFFSET,
            self.profile.canonical_features,
        )?;
        put_u64(&mut out, CONTRACT_LEN_OFFSET, usize_u64(contract.len())?)?;
        put_u64(&mut out, MANIFEST_LEN_OFFSET, usize_u64(manifest.len())?)?;
        put_u64(
            &mut out,
            COMPONENT_LEN_OFFSET,
            usize_u64(self.component.len())?,
        )?;
        put_u64(&mut out, TOTAL_LEN_OFFSET, usize_u64(total)?)?;
        put_u32(
            &mut out,
            WIT_COUNT_OFFSET,
            usize_u32(self.manifest.wit_packages.len())?,
        )?;
        put_u32(
            &mut out,
            INTERFACE_COUNT_OFFSET,
            usize_u32(self.manifest.interfaces.len())?,
        )?;
        put_u32(
            &mut out,
            MODULE_COUNT_OFFSET,
            usize_u32(self.manifest.core_modules.len())?,
        )?;
        put_u32(
            &mut out,
            ADAPTER_COUNT_OFFSET,
            usize_u32(self.manifest.adapters.len())?,
        )?;
        put_u16(
            &mut out,
            PROFILE_LIMIT_COUNT_OFFSET,
            PROFILE_LIMIT_FIELD_COUNT,
        )?;
        put_u16(
            &mut out,
            INSTANCE_LIMIT_COUNT_OFFSET,
            INSTANCE_LIMIT_FIELD_COUNT,
        )?;
        put_u16(
            &mut out,
            REVISION_COUNT_OFFSET,
            PROFILE_REVISION_FIELD_COUNT,
        )?;
        out[SIGNER_POLICY_DIGEST_OFFSET..SIGNER_POLICY_DIGEST_OFFSET + 32]
            .copy_from_slice(self.signer_policy.policy_digest.as_bytes());

        let contract_start = COMPONENT_ARTIFACT_HEADER_LEN;
        let manifest_start = contract_start + contract.len();
        let component_start = manifest_start + manifest.len();
        out[contract_start..manifest_start].copy_from_slice(&contract);
        out[manifest_start..component_start].copy_from_slice(&manifest);
        out[component_start..].copy_from_slice(&self.component);

        let component_hash = hash_role(COMPONENT_HASH_DOMAIN, &self.component);
        if component_hash != *self.component_commitment.as_bytes() {
            return Err(ComponentArtifactError::ComponentCommitment);
        }
        let contract_hash = hash_role(CONTRACT_HASH_DOMAIN, &contract);
        let manifest_hash = hash_role(MANIFEST_HASH_DOMAIN, &manifest);
        let body_hash = hash_body(&contract, &manifest, &self.component);
        out[COMPONENT_HASH_OFFSET..COMPONENT_HASH_OFFSET + 32].copy_from_slice(&component_hash);
        out[CONTRACT_HASH_OFFSET..CONTRACT_HASH_OFFSET + 32].copy_from_slice(&contract_hash);
        out[MANIFEST_HASH_OFFSET..MANIFEST_HASH_OFFSET + 32].copy_from_slice(&manifest_hash);
        out[BODY_HASH_OFFSET..BODY_HASH_OFFSET + 32].copy_from_slice(&body_hash);

        let commitment = hash_commitment(&out)?;
        out[ARTIFACT_COMMITMENT_OFFSET..ARTIFACT_COMMITMENT_OFFSET + 32]
            .copy_from_slice(&commitment);
        Ok(out)
    }

    /// Decode only the exact v1 representation. All section lengths and
    /// content hashes are checked before attacker-controlled allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ComponentArtifactError> {
        if bytes.len() < COMPONENT_ARTIFACT_HEADER_LEN {
            return Err(ComponentArtifactError::Truncated);
        }
        if bytes.len() > MAX_COMPONENT_ARTIFACT_ENCODED_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        if bytes.get(0..8) != Some(ARTIFACT_MAGIC.as_slice()) {
            return Err(ComponentArtifactError::Magic);
        }
        if get_u16(bytes, 8)? != COMPONENT_ARTIFACT_FORMAT_VERSION {
            return Err(ComponentArtifactError::Version);
        }
        if usize::from(get_u16(bytes, 10)?) != COMPONENT_ARTIFACT_HEADER_LEN
            || get_u32(bytes, FLAGS_OFFSET)? != 0
        {
            return Err(ComponentArtifactError::Header);
        }
        if get_u32(bytes, OBJECT_KIND_OFFSET)? != COMPONENT_ARTIFACT_OBJECT_KIND_RAW {
            return Err(ComponentArtifactError::ObjectKind);
        }
        if get_u16(bytes, HASH_ALGORITHM_OFFSET)? != COMPONENT_ARTIFACT_HASH_SHA256 {
            return Err(ComponentArtifactError::HashAlgorithm);
        }
        if get_u16(bytes, MANIFEST_VERSION_OFFSET)? != COMPONENT_ARTIFACT_MANIFEST_VERSION
            || get_u16(bytes, SIGNER_VERSION_OFFSET)? != COMPONENT_ARTIFACT_SIGNER_POLICY_VERSION
            || get_u16(bytes, PROFILE_LIMIT_COUNT_OFFSET)? != PROFILE_LIMIT_FIELD_COUNT
            || get_u16(bytes, INSTANCE_LIMIT_COUNT_OFFSET)? != INSTANCE_LIMIT_FIELD_COUNT
            || get_u16(bytes, REVISION_COUNT_OFFSET)? != PROFILE_REVISION_FIELD_COUNT
        {
            return Err(ComponentArtifactError::Version);
        }
        if get_u16(bytes, HEADER_RESERVED0_OFFSET)? != 0
            || bytes[HEADER_RESERVED1_OFFSET..COMPONENT_ARTIFACT_HEADER_LEN]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ComponentArtifactError::Reserved);
        }

        let profile = profile_from_code(get_u16(bytes, PROFILE_CODE_OFFSET)?)
            .ok_or(ComponentArtifactError::Profile)?;
        if get_u16(bytes, PROFILE_STAGE_OFFSET)? != profile_stage_raw(profile.stage)
            || get_u16(bytes, ARTIFACT_ABI_OFFSET)? != profile.artifact_abi
            || get_u16(bytes, COMPONENT_PROFILE_OFFSET)? != profile.component_profile
            || get_u16(bytes, CORE_PROFILE_OFFSET)? != profile.core_profile
            || get_u16(bytes, RUNTIME_ABI_OFFSET)? != profile.runtime_abi
            || get_u64(bytes, CANONICAL_FEATURES_OFFSET)? != profile.canonical_features
        {
            return Err(ComponentArtifactError::Profile);
        }
        let signer_kind =
            ComponentArtifactSignerPolicyKind::from_raw(get_u16(bytes, SIGNER_KIND_OFFSET)?)
                .ok_or(ComponentArtifactError::SignerPolicy)?;
        let signer_digest = read_hash(bytes, SIGNER_POLICY_DIGEST_OFFSET)?;
        let signer_policy = ComponentArtifactSignerPolicyV1::new(signer_kind, signer_digest)?;

        let contract_len = u64_usize(get_u64(bytes, CONTRACT_LEN_OFFSET)?)?;
        let manifest_len = u64_usize(get_u64(bytes, MANIFEST_LEN_OFFSET)?)?;
        let component_len = u64_usize(get_u64(bytes, COMPONENT_LEN_OFFSET)?)?;
        validate_component_len(component_len)?;
        let metadata_len = contract_len
            .checked_add(manifest_len)
            .ok_or(ComponentArtifactError::Length)?;
        if metadata_len > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        let total = COMPONENT_ARTIFACT_HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|value| value.checked_add(component_len))
            .ok_or(ComponentArtifactError::Length)?;
        if total != bytes.len() || get_u64(bytes, TOTAL_LEN_OFFSET)? != usize_u64(total)? {
            return Err(ComponentArtifactError::Length);
        }
        let contract_start = COMPONENT_ARTIFACT_HEADER_LEN;
        let manifest_start = contract_start + contract_len;
        let component_start = manifest_start + manifest_len;
        let contract = &bytes[contract_start..manifest_start];
        let manifest_bytes = &bytes[manifest_start..component_start];
        let component = &bytes[component_start..];

        if read_hash(bytes, COMPONENT_HASH_OFFSET)? != hash_role(COMPONENT_HASH_DOMAIN, component) {
            return Err(ComponentArtifactError::ComponentCommitment);
        }
        if read_hash(bytes, CONTRACT_HASH_OFFSET)? != hash_role(CONTRACT_HASH_DOMAIN, contract) {
            return Err(ComponentArtifactError::ContractHash);
        }
        if read_hash(bytes, MANIFEST_HASH_OFFSET)?
            != hash_role(MANIFEST_HASH_DOMAIN, manifest_bytes)
        {
            return Err(ComponentArtifactError::ManifestHash);
        }
        if read_hash(bytes, BODY_HASH_OFFSET)? != hash_body(contract, manifest_bytes, component) {
            return Err(ComponentArtifactError::BodyHash);
        }
        if read_hash(bytes, ARTIFACT_COMMITMENT_OFFSET)? != hash_commitment(bytes)? {
            return Err(ComponentArtifactError::Commitment);
        }

        let instance_limits = decode_contract(contract, profile)?;
        let manifest = ComponentArtifactManifestV1::decode(
            manifest_bytes,
            u32_usize(get_u32(bytes, WIT_COUNT_OFFSET)?)?,
            u32_usize(get_u32(bytes, INTERFACE_COUNT_OFFSET)?)?,
            u32_usize(get_u32(bytes, MODULE_COUNT_OFFSET)?)?,
            u32_usize(get_u32(bytes, ADAPTER_COUNT_OFFSET)?)?,
        )?;
        let artifact = Self::new(component, profile, instance_limits, signer_policy, manifest)?;
        if artifact.encode()?.as_slice() != bytes {
            return Err(ComponentArtifactError::NonCanonical);
        }
        Ok(artifact)
    }
}

impl fmt::Debug for ComponentArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentArtifactV1")
            .field("profile", &self.profile)
            .field("instance_limits", &self.instance_limits)
            .field("signer_policy", &self.signer_policy)
            .field("manifest", &self.manifest)
            .field("component_bytes", &self.component.len())
            .field("component_commitment", &self.component_commitment)
            .field("runtime_ready", &false)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentArtifactError {
    Allocation,
    EmptyComponent,
    TooLarge,
    InvalidText,
    Utf8,
    ZeroDigest,
    Profile,
    Limits,
    SignerPolicy,
    Manifest,
    DuplicateManifestEntry,
    Truncated,
    Magic,
    Version,
    Header,
    ObjectKind,
    HashAlgorithm,
    Reserved,
    Length,
    Contract,
    ComponentCommitment,
    ContractHash,
    ManifestHash,
    WitSourceCommitment,
    AdapterCommitment,
    BodyHash,
    Commitment,
    NonCanonical,
}

impl fmt::Display for ComponentArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "component artifact allocation failed",
            Self::EmptyComponent => "component artifact payload is empty",
            Self::TooLarge => "component artifact exceeds the v1 size bound",
            Self::InvalidText => "component artifact metadata text is not canonical",
            Self::Utf8 => "component artifact metadata is not valid UTF-8",
            Self::ZeroDigest => "component artifact digest is the all-zero sentinel",
            Self::Profile => "component artifact profile identity is unsupported",
            Self::Limits => "component artifact limits are invalid",
            Self::SignerPolicy => "component artifact signer policy is invalid",
            Self::Manifest => "component artifact interface manifest is invalid",
            Self::DuplicateManifestEntry => "component artifact manifest entry is duplicated",
            Self::Truncated => "component artifact is truncated",
            Self::Magic => "component artifact magic is invalid",
            Self::Version => "component artifact format version is unsupported",
            Self::Header => "component artifact header is non-canonical",
            Self::ObjectKind => "component artifact ObjectKind is invalid",
            Self::HashAlgorithm => "component artifact hash algorithm is unsupported",
            Self::Reserved => "component artifact reserved bytes are non-zero",
            Self::Length => "component artifact section length is inconsistent",
            Self::Contract => "component artifact profile contract is invalid",
            Self::ComponentCommitment => "component artifact payload commitment mismatch",
            Self::ContractHash => "component artifact contract hash mismatch",
            Self::ManifestHash => "component artifact manifest hash mismatch",
            Self::WitSourceCommitment => "component artifact WIT source commitment mismatch",
            Self::AdapterCommitment => "component artifact adapter commitment mismatch",
            Self::BodyHash => "component artifact body hash mismatch",
            Self::Commitment => "component artifact commitment mismatch",
            Self::NonCanonical => "component artifact representation is non-canonical",
        })
    }
}

impl ComponentArtifactManifestV1 {
    fn encoded_len(&self) -> Result<usize, ComponentArtifactError> {
        let mut total = MANIFEST_HEADER_LEN
            .checked_add(self.world.len())
            .ok_or(ComponentArtifactError::Length)?;
        for package in &self.wit_packages {
            total = checked_add_many(
                total,
                &[
                    12,
                    package.name.len(),
                    package.version.len(),
                    package.source.len(),
                    32,
                ],
            )?;
        }
        for interface in &self.interfaces {
            total = checked_add_many(
                total,
                &[12, interface.name.len(), interface.diagnostic_shape.len()],
            )?;
        }
        total = self
            .core_modules
            .len()
            .checked_mul(40)
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or(ComponentArtifactError::Length)?;
        for adapter in &self.adapters {
            total = checked_add_many(
                total,
                &[16, adapter.revision.len(), adapter.bytes.len(), 32],
            )?;
        }
        if total > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        Ok(total)
    }

    fn encode(&self) -> Result<Vec<u8>, ComponentArtifactError> {
        let total = self.encoded_len()?;
        let mut out = zeroed(total)?;
        out[0..8].copy_from_slice(&MANIFEST_MAGIC);
        put_u16(&mut out, 8, COMPONENT_ARTIFACT_MANIFEST_VERSION)?;
        put_u16(&mut out, 10, usize_u16(MANIFEST_HEADER_LEN)?)?;
        put_u32(&mut out, 12, 0)?;
        put_u16(&mut out, 16, usize_u16(self.world.len())?)?;
        put_u16(&mut out, 18, 0)?;
        put_u32(&mut out, 20, usize_u32(self.wit_packages.len())?)?;
        put_u32(&mut out, 24, usize_u32(self.interfaces.len())?)?;
        put_u32(&mut out, 28, usize_u32(self.core_modules.len())?)?;
        put_u32(&mut out, 32, usize_u32(self.adapters.len())?)?;
        put_u32(&mut out, 36, 0)?;

        let mut offset = MANIFEST_HEADER_LEN;
        write_bytes(&mut out, &mut offset, self.world.as_bytes())?;
        for package in &self.wit_packages {
            write_u16(&mut out, &mut offset, usize_u16(package.name.len())?)?;
            write_u16(&mut out, &mut offset, usize_u16(package.version.len())?)?;
            write_u32(&mut out, &mut offset, usize_u32(package.source.len())?)?;
            write_u32(&mut out, &mut offset, 0)?;
            write_bytes(&mut out, &mut offset, package.name.as_bytes())?;
            write_bytes(&mut out, &mut offset, package.version.as_bytes())?;
            write_bytes(&mut out, &mut offset, package.source.as_bytes())?;
            write_bytes(&mut out, &mut offset, package.source_commitment.as_bytes())?;
        }
        for interface in &self.interfaces {
            write_u8(&mut out, &mut offset, interface.direction as u8)?;
            write_u8(&mut out, &mut offset, interface.kind as u8)?;
            write_u16(&mut out, &mut offset, 0)?;
            write_u16(&mut out, &mut offset, usize_u16(interface.name.len())?)?;
            write_u16(&mut out, &mut offset, 0)?;
            write_u32(
                &mut out,
                &mut offset,
                usize_u32(interface.diagnostic_shape.len())?,
            )?;
            write_bytes(&mut out, &mut offset, interface.name.as_bytes())?;
            write_bytes(&mut out, &mut offset, interface.diagnostic_shape.as_bytes())?;
        }
        for module in &self.core_modules {
            write_u32(&mut out, &mut offset, module.byte_len)?;
            write_u32(&mut out, &mut offset, 0)?;
            write_bytes(&mut out, &mut offset, module.commitment.as_bytes())?;
        }
        for adapter in &self.adapters {
            write_u32(&mut out, &mut offset, adapter.ordinal)?;
            write_u16(&mut out, &mut offset, usize_u16(adapter.revision.len())?)?;
            write_u16(&mut out, &mut offset, 0)?;
            write_u32(&mut out, &mut offset, usize_u32(adapter.bytes.len())?)?;
            write_u32(&mut out, &mut offset, 0)?;
            write_bytes(&mut out, &mut offset, adapter.revision.as_bytes())?;
            write_bytes(&mut out, &mut offset, &adapter.bytes)?;
            write_bytes(&mut out, &mut offset, adapter.commitment.as_bytes())?;
        }
        if offset != total {
            return Err(ComponentArtifactError::Length);
        }
        Ok(out)
    }

    fn decode(
        bytes: &[u8],
        expected_wit_count: usize,
        expected_interface_count: usize,
        expected_module_count: usize,
        expected_adapter_count: usize,
    ) -> Result<Self, ComponentArtifactError> {
        if bytes.len() < MANIFEST_HEADER_LEN {
            return Err(ComponentArtifactError::Truncated);
        }
        if bytes.len() > MAX_COMPONENT_ARTIFACT_METADATA_BYTES {
            return Err(ComponentArtifactError::TooLarge);
        }
        if bytes.get(0..8) != Some(MANIFEST_MAGIC.as_slice()) {
            return Err(ComponentArtifactError::Manifest);
        }
        if get_u16(bytes, 8)? != COMPONENT_ARTIFACT_MANIFEST_VERSION
            || usize::from(get_u16(bytes, 10)?) != MANIFEST_HEADER_LEN
        {
            return Err(ComponentArtifactError::Version);
        }
        if get_u32(bytes, 12)? != 0 || get_u16(bytes, 18)? != 0 || get_u32(bytes, 36)? != 0 {
            return Err(ComponentArtifactError::Reserved);
        }

        let world_len = usize::from(get_u16(bytes, 16)?);
        let wit_count = u32_usize(get_u32(bytes, 20)?)?;
        let interface_count = u32_usize(get_u32(bytes, 24)?)?;
        let module_count = u32_usize(get_u32(bytes, 28)?)?;
        let adapter_count = u32_usize(get_u32(bytes, 32)?)?;
        if world_len == 0
            || world_len > MAX_WORLD_BYTES
            || wit_count == 0
            || wit_count > MAX_COMPONENT_ARTIFACT_WIT_PACKAGES
            || interface_count > MAX_COMPONENT_ARTIFACT_INTERFACES
            || module_count > MAX_COMPONENT_ARTIFACT_CORE_MODULES
            || adapter_count > MAX_COMPONENT_ARTIFACT_ADAPTERS
        {
            return Err(ComponentArtifactError::Manifest);
        }
        if (wit_count, interface_count, module_count, adapter_count)
            != (
                expected_wit_count,
                expected_interface_count,
                expected_module_count,
                expected_adapter_count,
            )
        {
            return Err(ComponentArtifactError::Manifest);
        }

        let mut cursor = Cursor::at(bytes, MANIFEST_HEADER_LEN)?;
        let world = text(cursor.take(world_len)?)?;
        validate_token(world, MAX_WORLD_BYTES)?;

        let mut wit_packages = reserved_vec(wit_count)?;
        for _ in 0..wit_count {
            let name_len = usize::from(cursor.read_u16()?);
            let version_len = usize::from(cursor.read_u16()?);
            let source_len = u32_usize(cursor.read_u32()?)?;
            if cursor.read_u32()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            if name_len == 0
                || name_len > MAX_NAME_BYTES
                || version_len == 0
                || version_len > MAX_VERSION_BYTES
                || source_len == 0
                || source_len > MAX_WIT_SOURCE_BYTES
            {
                return Err(ComponentArtifactError::Manifest);
            }
            let name = text(cursor.take(name_len)?)?;
            let version = text(cursor.take(version_len)?)?;
            let source = text(cursor.take(source_len)?)?;
            let stored_hash = cursor.read_hash()?;
            if stored_hash != hash_role(WIT_SOURCE_HASH_DOMAIN, source.as_bytes()) {
                return Err(ComponentArtifactError::WitSourceCommitment);
            }
            wit_packages.push(ComponentArtifactWitPackageV1::new(name, version, source)?);
        }

        let mut interfaces = reserved_vec(interface_count)?;
        for _ in 0..interface_count {
            let direction = ComponentArtifactInterfaceDirection::from_raw(cursor.read_u8()?)
                .ok_or(ComponentArtifactError::Manifest)?;
            let kind = ComponentArtifactEntityKind::from_raw(cursor.read_u8()?)
                .ok_or(ComponentArtifactError::Manifest)?;
            if cursor.read_u16()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            let name_len = usize::from(cursor.read_u16()?);
            if cursor.read_u16()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            let shape_len = u32_usize(cursor.read_u32()?)?;
            if name_len == 0
                || name_len > MAX_NAME_BYTES
                || shape_len == 0
                || shape_len > MAX_SHAPE_BYTES
            {
                return Err(ComponentArtifactError::Manifest);
            }
            let name = text(cursor.take(name_len)?)?;
            let shape = text(cursor.take(shape_len)?)?;
            interfaces.push(ComponentArtifactInterfaceV1::new(
                direction, kind, name, shape,
            )?);
        }

        let mut core_modules = reserved_vec(module_count)?;
        for _ in 0..module_count {
            let byte_len = cursor.read_u32()?;
            if cursor.read_u32()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            let digest = cursor.read_hash()?;
            core_modules.push(ComponentArtifactCoreModuleV1::from_parts(byte_len, digest)?);
        }

        let mut adapters = reserved_vec(adapter_count)?;
        for _ in 0..adapter_count {
            let ordinal = cursor.read_u32()?;
            let revision_len = usize::from(cursor.read_u16()?);
            if cursor.read_u16()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            let adapter_len = u32_usize(cursor.read_u32()?)?;
            if cursor.read_u32()? != 0 {
                return Err(ComponentArtifactError::Reserved);
            }
            if revision_len == 0
                || revision_len > MAX_VERSION_BYTES
                || adapter_len == 0
                || adapter_len > MAX_ADAPTER_BYTES
            {
                return Err(ComponentArtifactError::Manifest);
            }
            let revision = text(cursor.take(revision_len)?)?;
            let adapter_bytes = cursor.take(adapter_len)?;
            let stored_hash = cursor.read_hash()?;
            if stored_hash != hash_role(ADAPTER_HASH_DOMAIN, adapter_bytes) {
                return Err(ComponentArtifactError::AdapterCommitment);
            }
            adapters.push(ComponentArtifactAdapterV1::new(
                ordinal,
                revision,
                adapter_bytes,
            )?);
        }
        cursor.finish()?;

        let manifest = Self::new(world, wit_packages, interfaces, core_modules, adapters)?;
        if manifest.encode()?.as_slice() != bytes {
            return Err(ComponentArtifactError::NonCanonical);
        }
        Ok(manifest)
    }
}
