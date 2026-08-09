//! Canonical persistent-program envelope and durable root-policy composition.
//!
//! M4.5 stores source and an address-independent executable in one immutable
//! object.  Keeping them in one object makes the durable publication boundary
//! the matching root-grant commit: a crash can expose either no program cap or
//! the complete source/binary pair, never one half of it.
//!
//! This module validates the durable outer envelope only. Before execution the
//! compiler-owned `VIBEEXE` decoder must validate `executable()`, then the loader
//! must recompile `source()` and compare the canonical executable bytes exactly.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::durable::{
    DerivationId, DurableRights, ObjectKind, RecoveredGrant, RecoveryError, RecoveryPreflight,
    ResourceKind, RootConstraint, RootPolicy, RootRightsConstraint, SpaceId, MAX_OBJECT_SIZE,
};

pub const PROGRAM_ALIAS: &str = "hello";
pub const PROGRAM_SPACE_ID_RAW: u128 = 0x5052_4f47;
pub const PROGRAM_ROOT_SLOT: u32 = 0;
pub const PROGRAM_ROOT_GENERATION: u64 = 0;
pub const PROGRAM_ARTIFACT_OBJECT_KIND_RAW: u32 = 0x5052_4731;
pub const STORED_OBJECT_RESOURCE_KIND_RAW: u32 = 0x5354_4f52;
pub const PROGRAM_ROOT_RIGHTS: DurableRights = DurableRights::READ;
pub const PROGRAM_CONSOLE_RIGHTS: DurableRights = DurableRights::WRITE;
pub const PROGRAM_MEMORY_RIGHTS: DurableRights = DurableRights::READ.union(DurableRights::WRITE);

pub const PROGRAM_ARTIFACT_MAGIC: [u8; 8] = *b"VIBEPGM\0";
pub const PROGRAM_ARTIFACT_VERSION: u16 = 1;
pub const PROGRAM_ARTIFACT_HEADER_LEN: u16 = 160;
/// Version of the accepted Rust-subset source language.
pub const PROGRAM_SOURCE_ABI_V1: u32 = 1;
/// Version of the compiler-owned canonical `VIBEEXE` envelope.
pub const PROGRAM_EXECUTABLE_ABI_V1: u32 = 1;
/// Version of the runtime imports and entry contract used when linking `VIBEEXE`.
pub const PROGRAM_RUNTIME_ABI_V1: u32 = 1;
pub const PROGRAM_AUTHORITY_ABI_V1: u32 = 1;
pub const PROGRAM_AUTHORITY_COUNT: u16 = 2;
pub const PROGRAM_CONSOLE_AUTHORITY_KIND: u32 = 1;
pub const PROGRAM_MEMORY_AUTHORITY_KIND: u32 = 2;
pub const MAX_PROGRAM_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_PROGRAM_EXECUTABLE_BYTES: usize = 288 * 1024;

const FLAGS_V1: u32 = 0;
const SOURCE_HASH_OFFSET: usize = 32;
const EXECUTABLE_HASH_OFFSET: usize = 64;
const SOURCE_ABI_OFFSET: usize = 108;
const EXECUTABLE_ABI_OFFSET: usize = 112;
const RUNTIME_ABI_OFFSET: usize = 116;
const AUTHORITY_COUNT_OFFSET: usize = 120;
const CONSOLE_KIND_OFFSET: usize = 124;
const MEMORY_KIND_OFFSET: usize = 128;
const ALIAS_LEN_OFFSET: usize = 132;
const ALIAS_OFFSET: usize = 136;
const ALIAS_CAPACITY: usize = 16;
const RESERVED_OFFSET: usize = ALIAS_OFFSET + ALIAS_CAPACITY;

pub const fn program_space_id() -> SpaceId {
    match SpaceId::new(PROGRAM_SPACE_ID_RAW) {
        Some(id) => id,
        None => unreachable!(),
    }
}

pub const fn program_artifact_object_kind() -> ObjectKind {
    match ObjectKind::new(PROGRAM_ARTIFACT_OBJECT_KIND_RAW) {
        Some(kind) => kind,
        None => unreachable!(),
    }
}

pub const fn stored_object_resource_kind() -> ResourceKind {
    match ResourceKind::new(STORED_OBJECT_RESOURCE_KIND_RAW) {
        Some(kind) => kind,
        None => unreachable!(),
    }
}

/// The exact dynamic root admitted for the fixed saved-program CSpace. The
/// decoded artifact is validated separately before supervisor-provided console
/// and memory resources are attenuated to its fixed authority manifest.
pub const fn program_root_constraint() -> RootConstraint {
    RootConstraint {
        space: program_space_id(),
        first_slot: PROGRAM_ROOT_SLOT,
        last_slot_inclusive: PROGRAM_ROOT_SLOT,
        rights: RootRightsConstraint::exact(PROGRAM_ROOT_RIGHTS),
        resource_kind: stored_object_resource_kind(),
        object_kind: program_artifact_object_kind(),
    }
}

/// `RootConstraint` intentionally supports slot ranges and therefore does not
/// carry a generation field. Saved-program recovery must apply this final exact
/// shape check after dynamic selection and before `finish`/installation.
pub fn program_root_policy_is_exact(root: &RootPolicy) -> bool {
    let grant = &root.grant;
    grant.parent_id.is_none()
        && grant.flags.is_root()
        && grant.target.space == program_space_id()
        && grant.target.slot == PROGRAM_ROOT_SLOT
        && grant.target.generation == PROGRAM_ROOT_GENERATION
        && grant.rights == PROGRAM_ROOT_RIGHTS
        && grant.resource_kind == stored_object_resource_kind()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramArtifact {
    source: String,
    executable: Vec<u8>,
}

impl ProgramArtifact {
    pub fn new(source: &str, executable: &[u8]) -> Result<Self, ProgramArtifactError> {
        validate_lengths(source.len(), executable.len())?;
        if source.is_empty() {
            return Err(ProgramArtifactError::EmptySource);
        }
        if executable.is_empty() {
            return Err(ProgramArtifactError::EmptyExecutable);
        }
        Ok(Self {
            source: source.to_string(),
            executable: executable.to_vec(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn executable(&self) -> &[u8] {
        &self.executable
    }

    /// The one canonical little-endian v1 representation.
    pub fn encode(&self) -> Vec<u8> {
        let source = self.source.as_bytes();
        let total = usize::from(PROGRAM_ARTIFACT_HEADER_LEN) + source.len() + self.executable.len();
        let mut out = vec![0u8; total];
        out[0..8].copy_from_slice(&PROGRAM_ARTIFACT_MAGIC);
        put_u16(&mut out, 8, PROGRAM_ARTIFACT_VERSION);
        put_u16(&mut out, 10, PROGRAM_ARTIFACT_HEADER_LEN);
        put_u32(&mut out, 12, FLAGS_V1);
        put_u32(&mut out, 16, PROGRAM_AUTHORITY_ABI_V1);
        put_u32(&mut out, 20, source.len() as u32);
        put_u32(&mut out, 24, self.executable.len() as u32);
        // 28..32 is reserved and remains zero.
        out[SOURCE_HASH_OFFSET..SOURCE_HASH_OFFSET + 32].copy_from_slice(&sha256(source));
        out[EXECUTABLE_HASH_OFFSET..EXECUTABLE_HASH_OFFSET + 32]
            .copy_from_slice(&sha256(&self.executable));
        put_u32(&mut out, 96, PROGRAM_ROOT_RIGHTS.bits());
        put_u32(&mut out, 100, PROGRAM_CONSOLE_RIGHTS.bits());
        put_u32(&mut out, 104, PROGRAM_MEMORY_RIGHTS.bits());
        put_u32(&mut out, SOURCE_ABI_OFFSET, PROGRAM_SOURCE_ABI_V1);
        put_u32(&mut out, EXECUTABLE_ABI_OFFSET, PROGRAM_EXECUTABLE_ABI_V1);
        put_u32(&mut out, RUNTIME_ABI_OFFSET, PROGRAM_RUNTIME_ABI_V1);
        put_u16(&mut out, AUTHORITY_COUNT_OFFSET, PROGRAM_AUTHORITY_COUNT);
        // 122..124 is reserved and remains zero.
        put_u32(
            &mut out,
            CONSOLE_KIND_OFFSET,
            PROGRAM_CONSOLE_AUTHORITY_KIND,
        );
        put_u32(&mut out, MEMORY_KIND_OFFSET, PROGRAM_MEMORY_AUTHORITY_KIND);
        put_u16(&mut out, ALIAS_LEN_OFFSET, PROGRAM_ALIAS.len() as u16);
        // 134..136 is reserved and remains zero.
        out[ALIAS_OFFSET..ALIAS_OFFSET + PROGRAM_ALIAS.len()]
            .copy_from_slice(PROGRAM_ALIAS.as_bytes());
        // The unused alias capacity and 152..160 remain zero.
        let body = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
        out[body..body + source.len()].copy_from_slice(source);
        out[body + source.len()..].copy_from_slice(&self.executable);
        out
    }

    /// Decode only the exact v1 representation. Lengths are checked before
    /// allocation, and hashes bind the two body regions independently. SHA-256
    /// is a content binding here, not authentication or rollback protection.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProgramArtifactError> {
        let header = usize::from(PROGRAM_ARTIFACT_HEADER_LEN);
        if bytes.len() < header {
            return Err(ProgramArtifactError::Truncated);
        }
        if bytes.len() > MAX_OBJECT_SIZE {
            return Err(ProgramArtifactError::TooLarge);
        }
        if bytes[0..8] != PROGRAM_ARTIFACT_MAGIC {
            return Err(ProgramArtifactError::Magic);
        }
        if get_u16(bytes, 8)? != PROGRAM_ARTIFACT_VERSION {
            return Err(ProgramArtifactError::Version);
        }
        if get_u16(bytes, 10)? != PROGRAM_ARTIFACT_HEADER_LEN {
            return Err(ProgramArtifactError::Header);
        }
        if get_u32(bytes, 12)? != FLAGS_V1 || get_u32(bytes, 16)? != PROGRAM_AUTHORITY_ABI_V1 {
            return Err(ProgramArtifactError::Abi);
        }
        if get_u32(bytes, 28)? != 0
            || get_u16(bytes, 122)? != 0
            || get_u16(bytes, 134)? != 0
            || bytes[ALIAS_OFFSET + PROGRAM_ALIAS.len()..RESERVED_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            || bytes[RESERVED_OFFSET..header].iter().any(|byte| *byte != 0)
        {
            return Err(ProgramArtifactError::Reserved);
        }
        if get_u32(bytes, 96)? != PROGRAM_ROOT_RIGHTS.bits()
            || get_u32(bytes, 100)? != PROGRAM_CONSOLE_RIGHTS.bits()
            || get_u32(bytes, 104)? != PROGRAM_MEMORY_RIGHTS.bits()
        {
            return Err(ProgramArtifactError::Authority);
        }
        if get_u32(bytes, SOURCE_ABI_OFFSET)? != PROGRAM_SOURCE_ABI_V1
            || get_u32(bytes, EXECUTABLE_ABI_OFFSET)? != PROGRAM_EXECUTABLE_ABI_V1
            || get_u32(bytes, RUNTIME_ABI_OFFSET)? != PROGRAM_RUNTIME_ABI_V1
        {
            return Err(ProgramArtifactError::Abi);
        }
        if get_u16(bytes, AUTHORITY_COUNT_OFFSET)? != PROGRAM_AUTHORITY_COUNT
            || get_u32(bytes, CONSOLE_KIND_OFFSET)? != PROGRAM_CONSOLE_AUTHORITY_KIND
            || get_u32(bytes, MEMORY_KIND_OFFSET)? != PROGRAM_MEMORY_AUTHORITY_KIND
        {
            return Err(ProgramArtifactError::Authority);
        }
        if usize::from(get_u16(bytes, ALIAS_LEN_OFFSET)?) != PROGRAM_ALIAS.len()
            || &bytes[ALIAS_OFFSET..ALIAS_OFFSET + PROGRAM_ALIAS.len()] != PROGRAM_ALIAS.as_bytes()
        {
            return Err(ProgramArtifactError::Alias);
        }

        let source_len =
            usize::try_from(get_u32(bytes, 20)?).map_err(|_| ProgramArtifactError::Length)?;
        let executable_len =
            usize::try_from(get_u32(bytes, 24)?).map_err(|_| ProgramArtifactError::Length)?;
        validate_lengths(source_len, executable_len)?;
        let total = header
            .checked_add(source_len)
            .and_then(|length| length.checked_add(executable_len))
            .ok_or(ProgramArtifactError::Length)?;
        if total != bytes.len() {
            return Err(ProgramArtifactError::Length);
        }
        if source_len == 0 {
            return Err(ProgramArtifactError::EmptySource);
        }
        if executable_len == 0 {
            return Err(ProgramArtifactError::EmptyExecutable);
        }
        let source_bytes = &bytes[header..header + source_len];
        let executable = &bytes[header + source_len..];
        if bytes[SOURCE_HASH_OFFSET..SOURCE_HASH_OFFSET + 32] != sha256(source_bytes) {
            return Err(ProgramArtifactError::SourceHash);
        }
        if bytes[EXECUTABLE_HASH_OFFSET..EXECUTABLE_HASH_OFFSET + 32] != sha256(executable) {
            return Err(ProgramArtifactError::ExecutableHash);
        }
        let source = core::str::from_utf8(source_bytes)
            .map_err(|_| ProgramArtifactError::Utf8)?
            .to_string();
        let artifact = Self {
            source,
            executable: executable.to_vec(),
        };
        if artifact.encode().as_slice() != bytes {
            return Err(ProgramArtifactError::NonCanonical);
        }
        Ok(artifact)
    }
}

fn validate_lengths(source: usize, executable: usize) -> Result<(), ProgramArtifactError> {
    if source > MAX_PROGRAM_SOURCE_BYTES || executable > MAX_PROGRAM_EXECUTABLE_BYTES {
        return Err(ProgramArtifactError::TooLarge);
    }
    usize::from(PROGRAM_ARTIFACT_HEADER_LEN)
        .checked_add(source)
        .and_then(|length| length.checked_add(executable))
        .filter(|length| *length <= MAX_OBJECT_SIZE)
        .map(|_| ())
        .ok_or(ProgramArtifactError::TooLarge)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramArtifactError {
    Truncated,
    TooLarge,
    Magic,
    Version,
    Header,
    Abi,
    Reserved,
    Authority,
    Alias,
    Length,
    EmptySource,
    EmptyExecutable,
    SourceHash,
    ExecutableHash,
    Utf8,
    NonCanonical,
}

impl core::fmt::Display for ProgramArtifactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated program artifact",
            Self::TooLarge => "program artifact exceeds the v1 size limit",
            Self::Magic => "bad program artifact magic",
            Self::Version => "unsupported program artifact version",
            Self::Header => "non-canonical program artifact header",
            Self::Abi => "unsupported program authority ABI",
            Self::Reserved => "non-zero program artifact reserved field",
            Self::Authority => "program authority manifest does not match the v1 policy",
            Self::Alias => "program artifact alias is not the fixed `hello` slot",
            Self::Length => "program artifact length is inconsistent",
            Self::EmptySource => "program artifact source is empty",
            Self::EmptyExecutable => "program artifact executable is empty",
            Self::SourceHash => "program artifact source hash mismatch",
            Self::ExecutableHash => "program artifact executable hash mismatch",
            Self::Utf8 => "program artifact source is not UTF-8",
            Self::NonCanonical => "program artifact has a non-canonical representation",
        })
    }
}

/// One independently owned SpaceId partition in the global external-root
/// policy. A caller may omit a partition with no live roots; `finish` still
/// rejects every live root not selected by the resulting union.
#[derive(Clone, Copy)]
pub struct RootPolicyPartition<'a> {
    pub space: SpaceId,
    pub constraints: &'a [RootConstraint],
}

pub fn select_root_policy_union(
    preflight: &RecoveryPreflight,
    partitions: &[RootPolicyPartition<'_>],
) -> Result<Vec<RootPolicy>, RecoveryError> {
    let mut constraints = Vec::new();
    for (index, partition) in partitions.iter().enumerate() {
        if partitions[..index]
            .iter()
            .any(|other| other.space == partition.space)
        {
            return Err(RecoveryError::InvalidRootConstraint);
        }
        for (constraint_index, constraint) in partition.constraints.iter().enumerate() {
            if constraint.space != partition.space
                || partition.constraints[..constraint_index]
                    .iter()
                    .any(|other| {
                        other.first_slot <= constraint.last_slot_inclusive
                            && constraint.first_slot <= other.last_slot_inclusive
                    })
            {
                return Err(RecoveryError::InvalidRootConstraint);
            }
            constraints.push(*constraint);
        }
    }
    preflight.select_roots(&constraints)
}

/// Tombstones are global records, but recovered CSpace validators are owned by
/// one `SpaceId` each. This result preserves the caller's partition order while
/// assigning every explicit tombstone to the space of its original committed
/// grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstonePartition {
    pub space: SpaceId,
    pub tombstones: Vec<DerivationId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombstonePartitionError {
    DuplicateSpace,
    ForeignSpace,
    UnknownDerivation,
    CrossSpaceDerivation,
}

/// Partition global tombstones without allowing authority ancestry to cross an
/// independently validated CSpace boundary. `committed` must be the preflight
/// history, not the live-only grant set returned by `finish`, because the grant
/// named by a tombstone is no longer live there.
pub fn partition_tombstones_by_space(
    committed: &[RecoveredGrant],
    tombstones: &[DerivationId],
    spaces: &[SpaceId],
) -> Result<Vec<TombstonePartition>, TombstonePartitionError> {
    let mut partitions = Vec::with_capacity(spaces.len());
    for (index, space) in spaces.iter().copied().enumerate() {
        if spaces[..index].contains(&space) {
            return Err(TombstonePartitionError::DuplicateSpace);
        }
        partitions.push(TombstonePartition {
            space,
            tombstones: Vec::new(),
        });
    }

    // Reject foreign grants even when they are fully tombstoned and therefore
    // absent from the live grant set. Also reject a derived edge whose parent
    // belongs to another policy partition: a tombstone on that parent would
    // otherwise silently revoke authority across validator boundaries.
    for recovered in committed {
        let grant = &recovered.grant;
        if !spaces.contains(&grant.target.space) {
            return Err(TombstonePartitionError::ForeignSpace);
        }
        if let Some(parent_id) = grant.parent_id {
            let parent = committed
                .iter()
                .find(|candidate| candidate.grant.derivation_id == parent_id)
                .ok_or(TombstonePartitionError::UnknownDerivation)?;
            if parent.grant.target.space != grant.target.space {
                return Err(TombstonePartitionError::CrossSpaceDerivation);
            }
        }
    }

    for tombstone in tombstones {
        let grant = committed
            .iter()
            .find(|candidate| candidate.grant.derivation_id == *tombstone)
            .ok_or(TombstonePartitionError::UnknownDerivation)?;
        let partition = partitions
            .iter_mut()
            .find(|partition| partition.space == grant.grant.target.space)
            .ok_or(TombstonePartitionError::ForeignSpace)?;
        partition.tombstones.push(*tombstone);
    }
    Ok(partitions)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, ProgramArtifactError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(ProgramArtifactError::Truncated)?
        .try_into()
        .map_err(|_| ProgramArtifactError::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, ProgramArtifactError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(ProgramArtifactError::Truncated)?
        .try_into()
        .map_err(|_| ProgramArtifactError::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

/// Compact no_std SHA-256 used only to bind the two artifact body regions.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u128).wrapping_mul(8) as u64;
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}
