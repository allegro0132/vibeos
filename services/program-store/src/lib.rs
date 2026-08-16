//! Durable program artifact policy and recovered-resource authorization.

#![no_std]

extern crate alloc;

mod model;

pub use model::*;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate as program;
use vibeos_core::cap::{PersistentCapIdentity, PersistentResourceWitness, Rights};
use vibeos_durable_format::{
    GrantFlags, RecoveredGrant, RecoveredObject, RecoveredSlot, RecoveredStore,
};
use vibeos_object_store::{StoreError, StoredObject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SavedProgramState {
    Cold = 0,
    /// Durable graph installation completed, but the unified boot coordinator
    /// has not yet activated dependent authority.
    Staging = 1,
    ReadyEmpty = 2,
    Ready = 3,
    FailedClosed = 4,
}

impl SavedProgramState {
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Cold,
            1 => Self::Staging,
            2 => Self::ReadyEmpty,
            3 => Self::Ready,
            _ => Self::FailedClosed,
        }
    }

    pub const fn recovery_pending(self) -> bool {
        matches!(self, Self::Cold | Self::Staging)
    }

    pub const fn client_ready(self) -> bool {
        matches!(self, Self::ReadyEmpty | Self::Ready)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SavedProgramError {
    PermissionDenied,
    Busy,
    NotReady,
    AlreadySaved,
    Missing,
    Artifact,
    Compiler(String),
    Store(StoreError),
    OutsideTask,
    IdExhausted,
    Encode,
    Install,
    UnexpectedGraph,
}

impl core::fmt::Display for SavedProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Compiler(error) => {
                write!(f, "saved program compiler rejected the artifact: {error}")
            }
            Self::Store(error) => write!(f, "saved program store failed: {error}"),
            _ => f.write_str(match self {
                Self::PermissionDenied => "saved-program service lacks the required right",
                Self::Busy => "saved program already has an active operation",
                Self::NotReady => "saved-program recovery is not ready",
                Self::AlreadySaved => "the fixed `hello` program slot is already occupied",
                Self::Missing => "no saved `hello` program capability is installed",
                Self::Artifact => "saved program artifact failed canonical validation",
                Self::OutsideTask => "saved-program operations require an executor task",
                Self::IdExhausted => "saved-program stable ID space is exhausted",
                Self::Encode => "saved-program durable record encoding failed",
                Self::Install => "saved-program capability installation failed",
                Self::UnexpectedGraph => "saved-program durable graph has an unexpected shape",
                Self::Compiler(_) | Self::Store(_) => unreachable!(),
            }),
        }
    }
}

impl From<StoreError> for SavedProgramError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedProgramInfo {
    pub state: SavedProgramState,
    pub running: bool,
    pub artifact: Option<PersistentCapIdentity>,
    pub console_rights: Rights,
    pub memory_rights: Rights,
}

pub struct TrustedProgram {
    pub slots: Vec<RecoveredSlot>,
    pub grants: Vec<RecoveredGrant>,
    pub resources: Vec<PersistentResourceWitness>,
    pub live: bool,
}

pub fn authorize_recovered(
    recovered: &RecoveredStore,
) -> Result<TrustedProgram, SavedProgramError> {
    authorize_recovered_with(recovered, |object| Ok(StoredObject::from_recovered(object)))
}

/// Authorize a recovered program while requiring the selected persistence
/// backend to materialize the exact object resource. Storage V2 uses this hook
/// to bind the durable graph identity to an opaque CAS capability; callers
/// cannot substitute a media ObjectId lookup.
/// Identity of a program artifact that already passed
/// [`validate_recovered_object`] this boot. Object ids are unique within a
/// validated stream and the commit sequence pins the exact committing record,
/// so a matching identity names byte-identical, already-proven content; any
/// mismatch (including a compacted rewrite's fresh sequences) revalidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedArtifact {
    object_id: u128,
    commit_sequence: u64,
    byte_len: usize,
}

pub fn authorize_recovered_with(
    recovered: &RecoveredStore,
    resolve: impl FnOnce(&RecoveredObject) -> Result<Arc<StoredObject>, SavedProgramError>,
) -> Result<TrustedProgram, SavedProgramError> {
    authorize_recovered_with_memo(recovered, resolve, None).map(|(program, _)| program)
}

/// Like [`authorize_recovered_with`], but skipping the artifact recompilation
/// proof when `memo` names the exact object this stream commits. Every other
/// graph and slot check still runs in full; only the source-to-executable
/// equivalence proof — a deterministic function of the already-authenticated
/// artifact bytes — is reused.
pub fn authorize_recovered_with_memo(
    recovered: &RecoveredStore,
    resolve: impl FnOnce(&RecoveredObject) -> Result<Arc<StoredObject>, SavedProgramError>,
    memo: Option<ValidatedArtifact>,
) -> Result<(TrustedProgram, Option<ValidatedArtifact>), SavedProgramError> {
    if !recovered.tombstones.is_empty()
        || recovered
            .slots
            .iter()
            .any(|slot| slot.space != program::program_space_id())
        || recovered
            .grants
            .iter()
            .any(|grant| grant.grant.target.space != program::program_space_id())
    {
        return Err(SavedProgramError::UnexpectedGraph);
    }
    let slots: Vec<_> = recovered
        .slots
        .iter()
        .filter(|slot| slot.space == program::program_space_id())
        .copied()
        .collect();
    let grants: Vec<_> = recovered
        .grants
        .iter()
        .filter(|grant| grant.grant.target.space == program::program_space_id())
        .cloned()
        .collect();
    if slots.is_empty() && grants.is_empty() {
        return Ok((
            TrustedProgram {
                slots,
                grants,
                resources: Vec::new(),
                live: false,
            },
            None,
        ));
    }
    if slots.len() != 1 || grants.len() != 1 {
        return Err(SavedProgramError::UnexpectedGraph);
    }
    let slot = slots[0];
    let grant = &grants[0].grant;
    if slot.slot != PROGRAM_ROOT_SLOT
        || slot.max_generation != 0
        || slot.live_derivation != Some(grant.derivation_id)
        || grant.parent_id.is_some()
        || grant.target.slot != PROGRAM_ROOT_SLOT
        || grant.target.generation != 0
        || grant.rights != PROGRAM_ROOT_RIGHTS
        || grant.resource_kind != program::stored_object_resource_kind()
        || grant.flags != GrantFlags::ROOT
    {
        return Err(SavedProgramError::UnexpectedGraph);
    }
    let object_id = grant.object_id;
    let object = recovered
        .objects
        .iter()
        .find(|object| {
            object.object_id == object_id
                && object.object_kind == program::program_artifact_object_kind()
        })
        .ok_or(SavedProgramError::UnexpectedGraph)?;
    let identity = ValidatedArtifact {
        object_id: object.object_id.get(),
        commit_sequence: object.commit_sequence,
        byte_len: object.byte_len() as usize,
    };
    if memo != Some(identity) {
        validate_recovered_object(object)?;
    }
    let resource = resolve(object)?;
    Ok((
        TrustedProgram {
            slots,
            grants,
            resources: alloc::vec![PersistentResourceWitness::new(
                object_id,
                program::stored_object_resource_kind(),
                resource,
            )],
            live: true,
        },
        Some(identity),
    ))
}

fn validate_recovered_object(object: &RecoveredObject) -> Result<(), SavedProgramError> {
    let artifact =
        ProgramArtifact::decode(&object.bytes).map_err(|_| SavedProgramError::Artifact)?;
    let executable = vibeos_rustc::RelocatableImage::decode(artifact.executable())
        .map_err(SavedProgramError::Compiler)?;
    let current = vibeos_rustc::compile_relocatable(artifact.source())
        .map_err(SavedProgramError::Compiler)?;
    if current.encode() != executable.encode() || executable.encode() != artifact.executable() {
        return Err(SavedProgramError::Artifact);
    }
    Ok(())
}
