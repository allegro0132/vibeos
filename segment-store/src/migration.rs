//! Crash-safe, capability-scoped M4-to-Storage-V2 boot-preference protocol.
//!
//! Migration data lives outside both stores. Two independently sealed control
//! slots record a monotonic state transition. Until `V2Active` is durably
//! selected, M4 remains authoritative; an active record is accepted only when
//! it binds an independently scrubbed V2 activation floor and authority root.

use alloc::boxed::Box;
use core::fmt;

use sha2::{Digest, Sha256};
use vibeos_segment_format::{Page, StoreUuid, PAGE_SIZE};
use vibeos_storage_device::MutationFailure;

use crate::maintenance::{
    MaintenanceOperationLease, StoreMaintenance, StoreMaintenanceProvisioner,
};
use crate::{PageDevice, PageDeviceInfo};

pub const M4_FIRST_LOGICAL_BLOCK: u64 = 64;
pub const M4_LOGICAL_BLOCK_COUNT: u64 = 512;
pub const MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK: u64 = 576;
pub const MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT: u64 = 32;
pub const V2_DEFAULT_FIRST_LOGICAL_BLOCK: u64 = 2_048;
pub const V2_DEFAULT_LOGICAL_BLOCK_COUNT: u64 = 65_664;

pub const CONTROL_PAGE_COUNT: u64 = 4;
pub const CONTROL_FORMAT_VERSION: u16 = 1;
pub const CONTROL_BODY_MAGIC: &[u8; 8] = b"VIBEMG2\0";
pub const CONTROL_SEAL_MAGIC: &[u8; 8] = b"VIBEMS2\0";
pub const CONTROL_TERMINAL_MARKER: &[u8; 16] = b"VIBEMG2-COMMIT!!";

const BODY_HEADER_LEN: u16 = 0x100;
const BODY_DIGEST_AT: usize = 0x20;
const SEAL_DIGEST_AT: usize = 0x20;
const SEAL_TERMINAL_AT: usize = PAGE_SIZE - CONTROL_TERMINAL_MARKER.len();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MigrationState {
    FrozenM4 = 1,
    V2Staged = 2,
    V2Active = 3,
    RollbackClosed = 4,
}

impl MigrationState {
    fn decode(raw: u8) -> Result<Self, MigrationControlError> {
        match raw {
            1 => Ok(Self::FrozenM4),
            2 => Ok(Self::V2Staged),
            3 => Ok(Self::V2Active),
            4 => Ok(Self::RollbackClosed),
            _ => Err(MigrationControlError::InvalidState),
        }
    }

    pub const fn prefers_v2(self) -> bool {
        matches!(self, Self::V2Active | Self::RollbackClosed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationControl {
    pub state: MigrationState,
    pub generation: u64,
    pub device_id: [u8; 16],
    pub m4_first_logical_block: u64,
    pub m4_logical_block_count: u64,
    pub v2_first_logical_block: u64,
    pub v2_logical_block_count: u64,
    pub store_uuid: [u8; 16],
    /// Exact staged checkpoint while `V2Staged`; immutable activation floor
    /// after `V2Active`. Later V2-only checkpoints may advance beyond it.
    pub activation_checkpoint_generation: u64,
    /// Exact staged snapshot digest and activation commitment. At the floor it
    /// must match byte-for-byte; later healthy checkpoints are accepted only
    /// after full policy recovery and scrub.
    pub activation_authority_sha256: [u8; 32],
}

impl MigrationControl {
    pub fn frozen(device_id: [u8; 16]) -> Self {
        Self {
            state: MigrationState::FrozenM4,
            generation: 1,
            device_id,
            m4_first_logical_block: M4_FIRST_LOGICAL_BLOCK,
            m4_logical_block_count: M4_LOGICAL_BLOCK_COUNT,
            v2_first_logical_block: V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            v2_logical_block_count: V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            store_uuid: [0; 16],
            activation_checkpoint_generation: 0,
            activation_authority_sha256: [0; 32],
        }
    }

    fn validate(self) -> Result<Self, MigrationControlError> {
        if self.generation == 0
            || self.device_id == [0; 16]
            || self.m4_first_logical_block != M4_FIRST_LOGICAL_BLOCK
            || self.m4_logical_block_count != M4_LOGICAL_BLOCK_COUNT
            || self.v2_first_logical_block != V2_DEFAULT_FIRST_LOGICAL_BLOCK
            || self.v2_logical_block_count != V2_DEFAULT_LOGICAL_BLOCK_COUNT
            || ranges_overlap(
                self.m4_first_logical_block,
                self.m4_logical_block_count,
                self.v2_first_logical_block,
                self.v2_logical_block_count,
            )?
        {
            return Err(MigrationControlError::InvalidBinding);
        }
        let has_any_v2 = self.store_uuid != [0; 16]
            || self.activation_checkpoint_generation != 0
            || self.activation_authority_sha256 != [0; 32];
        let has_complete_v2 = self.store_uuid != [0; 16]
            && self.activation_checkpoint_generation != 0
            && self.activation_authority_sha256 != [0; 32];
        match self.state {
            MigrationState::FrozenM4 if has_any_v2 => Err(MigrationControlError::InvalidBinding),
            MigrationState::FrozenM4 => Ok(self),
            MigrationState::V2Staged
            | MigrationState::V2Active
            | MigrationState::RollbackClosed
                if has_complete_v2 =>
            {
                Ok(self)
            }
            _ => Err(MigrationControlError::InvalidBinding),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColdScrubEvidence {
    pub device_id: [u8; 16],
    pub v2_first_logical_block: u64,
    pub v2_logical_block_count: u64,
    pub store_uuid: StoreUuid,
    pub checkpoint_generation: u64,
    pub authority_sha256: [u8; 32],
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationTransition {
    /// Publish a fully proved native V2 store on media which has never held an
    /// M4 authority journal. The transition is legal only from an absent
    /// control record and therefore cannot bypass or overwrite migration
    /// history.
    InitializeV2(ColdScrubEvidence),
    /// Freeze the legacy writer for this exact V2 store incarnation. The UUID
    /// is checked only against runtime maintenance authority and is never
    /// published in the `FrozenM4` control record.
    FreezeM4(StoreUuid),
    StageV2(ColdScrubEvidence),
    ActivateV2(ColdScrubEvidence),
    RollBackToM4,
    CloseRollback(ColdScrubEvidence),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationWrite {
    ClearSeal { page: u64 },
    Body { page: u64 },
    Seal { page: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationControlError {
    Empty,
    Torn,
    BadMagic,
    UnsupportedVersion,
    InvalidLength,
    InvalidState,
    InvalidBinding,
    NonZeroReserved,
    DigestMismatch,
    AmbiguousGeneration,
}

impl fmt::Display for MigrationControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "migration control is empty",
            Self::Torn => "migration control is torn",
            Self::BadMagic => "migration control magic is invalid",
            Self::UnsupportedVersion => "migration control version is unsupported",
            Self::InvalidLength => "migration control length is invalid",
            Self::InvalidState => "migration control state is invalid",
            Self::InvalidBinding => "migration control binding is invalid",
            Self::NonZeroReserved => "migration control reserved bytes are non-zero",
            Self::DigestMismatch => "migration control digest does not match",
            Self::AmbiguousGeneration => "migration control slots have an ambiguous generation",
        })
    }
}

impl core::error::Error for MigrationControlError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError<E> {
    Device(E),
    Mutation(MutationFailure<E>),
    Control(MigrationControlError),
    Unauthorized,
    InvalidControlDevice,
    InvalidTransition,
    GenerationExhausted,
    ScrubMismatch,
    ReadbackMismatch,
}

impl<E> From<MigrationControlError> for MigrationError<E> {
    fn from(value: MigrationControlError) -> Self {
        Self::Control(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyFormatProbe {
    Absent,
    Valid,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageV2FormatProbe {
    Absent,
    Valid {
        device_id: [u8; 16],
        v2_first_logical_block: u64,
        v2_logical_block_count: u64,
        store_uuid: StoreUuid,
        checkpoint_generation: u64,
        authority_sha256: [u8; 32],
    },
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatProbe {
    Blank,
    M4Only,
    V2Only,
    BothPreferM4,
    BothPreferV2,
    Corrupt,
}

pub fn probe_storage_formats(
    legacy: LegacyFormatProbe,
    v2: StorageV2FormatProbe,
    control: Option<MigrationControl>,
) -> FormatProbe {
    if legacy == LegacyFormatProbe::Corrupt || v2 == StorageV2FormatProbe::Corrupt {
        return FormatProbe::Corrupt;
    }
    if control.is_some_and(|value| value.validate().is_err()) {
        return FormatProbe::Corrupt;
    }
    match (legacy, v2, control) {
        (LegacyFormatProbe::Absent, StorageV2FormatProbe::Absent, None) => FormatProbe::Blank,
        (
            LegacyFormatProbe::Valid,
            StorageV2FormatProbe::Absent | StorageV2FormatProbe::Valid { .. },
            None
            | Some(MigrationControl {
                state: MigrationState::FrozenM4,
                ..
            }),
        ) => {
            if matches!(v2, StorageV2FormatProbe::Valid { .. }) {
                FormatProbe::BothPreferM4
            } else {
                FormatProbe::M4Only
            }
        }
        (LegacyFormatProbe::Absent, StorageV2FormatProbe::Valid { .. }, Some(control))
            if control.state == MigrationState::RollbackClosed
                && control_matches_v2(control, v2) =>
        {
            FormatProbe::V2Only
        }
        (LegacyFormatProbe::Valid, StorageV2FormatProbe::Valid { .. }, Some(control))
            if control_matches_v2(control, v2) =>
        {
            if control.state.prefers_v2() {
                FormatProbe::BothPreferV2
            } else {
                FormatProbe::BothPreferM4
            }
        }
        _ => FormatProbe::Corrupt,
    }
}

fn control_matches_v2(control: MigrationControl, v2: StorageV2FormatProbe) -> bool {
    matches!(v2, StorageV2FormatProbe::Valid {
        device_id,
        v2_first_logical_block,
        v2_logical_block_count,
        store_uuid,
        checkpoint_generation,
        authority_sha256,
    }
    if control.device_id == device_id
        && control.v2_first_logical_block == v2_first_logical_block
        && control.v2_logical_block_count == v2_logical_block_count
        && control.store_uuid == *store_uuid.as_bytes()
        && match control.state {
            MigrationState::V2Staged => {
                control.activation_checkpoint_generation == checkpoint_generation
                    && control.activation_authority_sha256 == authority_sha256
            }
            MigrationState::V2Active | MigrationState::RollbackClosed => {
                checkpoint_generation > control.activation_checkpoint_generation
                    || (checkpoint_generation == control.activation_checkpoint_generation
                        && control.activation_authority_sha256 == authority_sha256)
            }
            MigrationState::FrozenM4 => false,
        })
}

pub fn encode_migration_control(
    value: MigrationControl,
    body: &mut Page,
    seal: &mut Page,
) -> Result<(), MigrationControlError> {
    let value = value.validate()?;
    body.fill(0);
    seal.fill(0);
    body[..8].copy_from_slice(CONTROL_BODY_MAGIC);
    body[0x08..0x0a].copy_from_slice(&CONTROL_FORMAT_VERSION.to_le_bytes());
    body[0x0a..0x0c].copy_from_slice(&BODY_HEADER_LEN.to_le_bytes());
    body[0x0c] = value.state as u8;
    body[0x10..0x18].copy_from_slice(&value.generation.to_le_bytes());
    body[0x40..0x50].copy_from_slice(&value.device_id);
    put_u64(body, 0x50, value.m4_first_logical_block);
    put_u64(body, 0x58, value.m4_logical_block_count);
    put_u64(body, 0x60, value.v2_first_logical_block);
    put_u64(body, 0x68, value.v2_logical_block_count);
    body[0x70..0x80].copy_from_slice(&value.store_uuid);
    put_u64(body, 0x80, value.activation_checkpoint_generation);
    body[0x88..0xa8].copy_from_slice(&value.activation_authority_sha256);
    let digest: [u8; 32] = Sha256::digest(&body[0x40..]).into();
    body[BODY_DIGEST_AT..BODY_DIGEST_AT + 32].copy_from_slice(&digest);

    seal[..8].copy_from_slice(CONTROL_SEAL_MAGIC);
    seal[0x08..0x0a].copy_from_slice(&CONTROL_FORMAT_VERSION.to_le_bytes());
    seal[0x10..0x18].copy_from_slice(&value.generation.to_le_bytes());
    let body_sha256: [u8; 32] = Sha256::digest(body.as_slice()).into();
    seal[SEAL_DIGEST_AT..SEAL_DIGEST_AT + 32].copy_from_slice(&body_sha256);
    seal[SEAL_TERMINAL_AT..].copy_from_slice(CONTROL_TERMINAL_MARKER);
    Ok(())
}

pub fn decode_migration_control(
    body: &Page,
    seal: &Page,
) -> Result<MigrationControl, MigrationControlError> {
    if body.iter().all(|byte| *byte == 0) && seal.iter().all(|byte| *byte == 0) {
        return Err(MigrationControlError::Empty);
    }
    // The only invalid seals recoverable as an unpublished target are exact
    // prefixes of writing the canonical seal or exact prefixes of clearing the
    // previous canonical seal. Random damage is not downgraded to `Torn`.
    let expected_seal = canonical_seal_for_body(body);
    if seal.iter().all(|byte| *byte == 0)
        || is_canonical_write_prefix(seal, &expected_seal)
        || is_canonical_clear_prefix(seal, &expected_seal)
    {
        return Err(MigrationControlError::Torn);
    }
    if &body[..8] != CONTROL_BODY_MAGIC || &seal[..8] != CONTROL_SEAL_MAGIC {
        return Err(MigrationControlError::BadMagic);
    }
    if get_u16(body, 0x08) != CONTROL_FORMAT_VERSION
        || get_u16(seal, 0x08) != CONTROL_FORMAT_VERSION
    {
        return Err(MigrationControlError::UnsupportedVersion);
    }
    if get_u16(body, 0x0a) != BODY_HEADER_LEN {
        return Err(MigrationControlError::InvalidLength);
    }
    if !is_zero(&body[0x0d..0x10])
        || !is_zero(&body[0x18..0x20])
        || !is_zero(&body[0xa8..0x100])
        || !is_zero(&body[0x100..])
        || !is_zero(&seal[0x0a..0x10])
        || !is_zero(&seal[0x18..0x20])
        || !is_zero(&seal[0x40..SEAL_TERMINAL_AT])
        || &seal[SEAL_TERMINAL_AT..] != CONTROL_TERMINAL_MARKER
    {
        return Err(MigrationControlError::NonZeroReserved);
    }
    let expected_payload: [u8; 32] = Sha256::digest(&body[0x40..]).into();
    let expected_body: [u8; 32] = Sha256::digest(body.as_slice()).into();
    if body[BODY_DIGEST_AT..BODY_DIGEST_AT + 32] != expected_payload
        || seal[SEAL_DIGEST_AT..SEAL_DIGEST_AT + 32] != expected_body
    {
        return Err(MigrationControlError::DigestMismatch);
    }
    let generation = get_u64(body, 0x10);
    if generation != get_u64(seal, 0x10) {
        return Err(MigrationControlError::DigestMismatch);
    }
    let control = MigrationControl {
        state: MigrationState::decode(body[0x0c])?,
        generation,
        device_id: body[0x40..0x50].try_into().expect("fixed field"),
        m4_first_logical_block: get_u64(body, 0x50),
        m4_logical_block_count: get_u64(body, 0x58),
        v2_first_logical_block: get_u64(body, 0x60),
        v2_logical_block_count: get_u64(body, 0x68),
        store_uuid: body[0x70..0x80].try_into().expect("fixed field"),
        activation_checkpoint_generation: get_u64(body, 0x80),
        activation_authority_sha256: body[0x88..0xa8].try_into().expect("fixed field"),
    };
    control.validate()
}

fn canonical_seal_for_body(body: &Page) -> Page {
    let mut seal = [0; PAGE_SIZE];
    seal[..8].copy_from_slice(CONTROL_SEAL_MAGIC);
    seal[0x08..0x0a].copy_from_slice(&CONTROL_FORMAT_VERSION.to_le_bytes());
    seal[0x10..0x18].copy_from_slice(&body[0x10..0x18]);
    let body_sha256: [u8; 32] = Sha256::digest(body.as_slice()).into();
    seal[SEAL_DIGEST_AT..SEAL_DIGEST_AT + 32].copy_from_slice(&body_sha256);
    seal[SEAL_TERMINAL_AT..].copy_from_slice(CONTROL_TERMINAL_MARKER);
    seal
}

fn is_canonical_write_prefix(observed: &Page, expected: &Page) -> bool {
    let Some(last_nonzero) = observed.iter().rposition(|byte| *byte != 0) else {
        return true;
    };
    last_nonzero < PAGE_SIZE - 1 && observed[..=last_nonzero] == expected[..=last_nonzero]
}

fn is_canonical_clear_prefix(observed: &Page, expected: &Page) -> bool {
    let Some(first_nonzero) = observed.iter().position(|byte| *byte != 0) else {
        return true;
    };
    first_nonzero > 0 && observed[first_nonzero..] == expected[first_nonzero..]
}

pub fn select_migration_control(
    left: Result<MigrationControl, MigrationControlError>,
    right: Result<MigrationControl, MigrationControlError>,
) -> Result<Option<MigrationControl>, MigrationControlError> {
    let admissible = |result| match result {
        Ok(value) => Ok(Some(value)),
        Err(MigrationControlError::Empty | MigrationControlError::Torn) => Ok(None),
        Err(error) => Err(error),
    };
    match (admissible(left)?, admissible(right)?) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => Ok(Some(value)),
        (Some(left), Some(right)) if left.generation == right.generation => {
            if left == right {
                Ok(Some(left))
            } else {
                Err(MigrationControlError::AmbiguousGeneration)
            }
        }
        (Some(left), Some(right)) => {
            let (older, newer) = if left.generation < right.generation {
                (left, right)
            } else {
                (right, left)
            };
            if newer.generation != older.generation.saturating_add(1)
                || !valid_successor(older, newer)
            {
                return Err(MigrationControlError::AmbiguousGeneration);
            }
            Ok(Some(newer))
        }
    }
}

fn valid_successor(older: MigrationControl, newer: MigrationControl) -> bool {
    let stable_binding = older.device_id == newer.device_id
        && older.m4_first_logical_block == newer.m4_first_logical_block
        && older.m4_logical_block_count == newer.m4_logical_block_count
        && older.v2_first_logical_block == newer.v2_first_logical_block
        && older.v2_logical_block_count == newer.v2_logical_block_count;
    if !stable_binding {
        return false;
    }
    match (older.state, newer.state) {
        (MigrationState::FrozenM4, MigrationState::V2Staged) => {
            older.store_uuid == [0; 16]
                && newer.store_uuid != [0; 16]
                && newer.activation_checkpoint_generation != 0
                && newer.activation_authority_sha256 != [0; 32]
        }
        (MigrationState::V2Staged, MigrationState::V2Active)
        | (MigrationState::V2Active, MigrationState::RollbackClosed) => {
            same_v2_binding(older, newer)
        }
        (MigrationState::V2Staged, MigrationState::FrozenM4) => {
            newer.store_uuid == [0; 16]
                && newer.activation_checkpoint_generation == 0
                && newer.activation_authority_sha256 == [0; 32]
        }
        _ => false,
    }
}

fn same_v2_binding(left: MigrationControl, right: MigrationControl) -> bool {
    left.store_uuid == right.store_uuid
        && left.activation_checkpoint_generation == right.activation_checkpoint_generation
        && left.activation_authority_sha256 == right.activation_authority_sha256
}

pub struct MigrationController<D> {
    device: D,
}

impl<D: PageDevice> MigrationController<D> {
    pub fn new(device: D) -> Result<Self, MigrationError<D::Error>> {
        validate_control_device(device.info())?;
        Ok(Self { device })
    }

    pub fn into_device(self) -> D {
        self.device
    }

    pub async fn recover(&self) -> Result<Option<MigrationControl>, MigrationError<D::Error>> {
        let left = read_pair(&self.device, 0).await?;
        let right = read_pair(&self.device, 2).await?;
        let left = require_slot_parity(decode_migration_control(&left[0], &left[1]), 0);
        let right = require_slot_parity(decode_migration_control(&right[0], &right[1]), 1);
        let selected = select_migration_control(left, right)?;
        if selected.is_some_and(|value| value.device_id != self.device.info().device_id) {
            return Err(MigrationControlError::InvalidBinding.into());
        }
        Ok(selected)
    }

    pub async fn transition(
        &self,
        maintenance: &StoreMaintenance,
        provisioner: &StoreMaintenanceProvisioner,
        current: Option<MigrationControl>,
        transition: MigrationTransition,
    ) -> Result<MigrationControl, MigrationError<D::Error>> {
        // Authority is checked before the first media read. Ordinary online
        // maintenance (grow/scrub) tokens and tokens for a different V2 slice
        // therefore cannot even use the controller as a format oracle.
        let expected_store_uuid = transition_store_uuid(current, transition)?;
        let _maintenance_lease: MaintenanceOperationLease = maintenance
            .acquire_explicit_migration(
                provisioner,
                expected_store_uuid,
                self.device.info().device_id,
                V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            )
            .ok_or(MigrationError::Unauthorized)?;
        // Keep the controller's recovery state off the kernel task stack. The
        // control path is rare, privileged work, while a large embedded
        // recovery future would tax every task merely for owning this future.
        let recovered = Box::pin(self.recover()).await?;
        if recovered != current {
            return Err(MigrationError::InvalidTransition);
        }
        let next = next_control(self.device.info(), current, transition)?;
        let slot = (next.generation - 1) & 1;
        let body_page = slot * 2;
        let seal_page = body_page + 1;
        let zero = Box::new([0; PAGE_SIZE]);
        self.device
            .write_page(seal_page, zero.as_ref())
            .await
            .map_err(MigrationError::Mutation)?;
        self.device
            .flush()
            .await
            .map_err(|failure| MigrationError::Mutation(failure.force_ambiguous()))?;
        let mut observed = Box::new([0; PAGE_SIZE]);
        self.device
            .read_page(seal_page, observed.as_mut())
            .await
            .map_err(MigrationError::Device)?;
        if observed.as_ref() != zero.as_ref() {
            return Err(MigrationError::ReadbackMismatch);
        }
        drop(observed);
        drop(zero);
        let mut pair = Box::new([[0; PAGE_SIZE]; 2]);
        let [body, seal] = pair.as_mut();
        encode_migration_control(next, body, seal)?;
        self.device
            .write_page(body_page, body)
            .await
            .map_err(|failure| MigrationError::Mutation(failure.force_ambiguous()))?;
        self.device
            .flush()
            .await
            .map_err(|failure| MigrationError::Mutation(failure.force_ambiguous()))?;
        self.device
            .write_page(seal_page, seal)
            .await
            .map_err(|failure| MigrationError::Mutation(failure.force_ambiguous()))?;
        self.device
            .flush()
            .await
            .map_err(|failure| MigrationError::Mutation(failure.force_ambiguous()))?;
        let recovered = Box::pin(self.recover()).await?;
        if recovered == Some(next) {
            Ok(next)
        } else {
            Err(MigrationError::ReadbackMismatch)
        }
    }
}

fn transition_store_uuid<E>(
    current: Option<MigrationControl>,
    transition: MigrationTransition,
) -> Result<StoreUuid, MigrationError<E>> {
    match (current, transition) {
        (None, MigrationTransition::InitializeV2(evidence)) => Ok(evidence.store_uuid),
        (None, MigrationTransition::FreezeM4(store_uuid)) => Ok(store_uuid),
        (Some(control), MigrationTransition::StageV2(evidence))
            if control.state == MigrationState::FrozenM4 =>
        {
            Ok(evidence.store_uuid)
        }
        (Some(control), MigrationTransition::ActivateV2(_))
            if control.state == MigrationState::V2Staged =>
        {
            StoreUuid::new(control.store_uuid).map_err(|_| MigrationError::InvalidTransition)
        }
        (Some(control), MigrationTransition::RollBackToM4)
            if control.state == MigrationState::V2Staged =>
        {
            StoreUuid::new(control.store_uuid).map_err(|_| MigrationError::InvalidTransition)
        }
        (Some(control), MigrationTransition::CloseRollback(_))
            if control.state == MigrationState::V2Active =>
        {
            StoreUuid::new(control.store_uuid).map_err(|_| MigrationError::InvalidTransition)
        }
        _ => Err(MigrationError::InvalidTransition),
    }
}

fn require_slot_parity(
    value: Result<MigrationControl, MigrationControlError>,
    slot: u64,
) -> Result<MigrationControl, MigrationControlError> {
    match value {
        Ok(value) if (value.generation - 1) & 1 == slot => Ok(value),
        Ok(_) => Err(MigrationControlError::InvalidBinding),
        Err(error) => Err(error),
    }
}

fn next_control<E>(
    info: PageDeviceInfo,
    current: Option<MigrationControl>,
    transition: MigrationTransition,
) -> Result<MigrationControl, MigrationError<E>> {
    let next_generation = current.map_or(1, |value| value.generation.checked_add(1).unwrap_or(0));
    if next_generation == 0 {
        return Err(MigrationError::GenerationExhausted);
    }
    let base = current.unwrap_or_else(|| MigrationControl::frozen(info.device_id));
    let mut next = base;
    next.generation = next_generation;
    match transition {
        MigrationTransition::InitializeV2(evidence) if current.is_none() => {
            apply_evidence(&mut next, evidence)?;
            // A native store has no frozen M4 source and therefore no rollback
            // window. Reuse the existing terminal V2-preferring state rather
            // than inventing a second selector state.
            next.state = MigrationState::RollbackClosed;
        }
        MigrationTransition::FreezeM4(_) if current.is_none() => {
            next.state = MigrationState::FrozenM4
        }
        MigrationTransition::StageV2(evidence)
            if current.is_some_and(|value| value.state == MigrationState::FrozenM4) =>
        {
            apply_evidence(&mut next, evidence)?;
            next.state = MigrationState::V2Staged;
        }
        MigrationTransition::ActivateV2(evidence)
            if current.is_some_and(|value| value.state == MigrationState::V2Staged) =>
        {
            require_same_evidence(base, evidence)?;
            next.state = MigrationState::V2Active;
        }
        MigrationTransition::RollBackToM4
            if current.is_some_and(|value| value.state == MigrationState::V2Staged) =>
        {
            next = MigrationControl::frozen(info.device_id);
            next.generation = next_generation;
        }
        MigrationTransition::CloseRollback(evidence)
            if current.is_some_and(|value| value.state == MigrationState::V2Active) =>
        {
            require_active_evidence(base, evidence)?;
            next.state = MigrationState::RollbackClosed;
        }
        _ => return Err(MigrationError::InvalidTransition),
    }
    next.validate().map_err(MigrationError::Control)
}

fn apply_evidence<E>(
    control: &mut MigrationControl,
    evidence: ColdScrubEvidence,
) -> Result<(), MigrationError<E>> {
    if !evidence.complete
        || evidence.device_id != control.device_id
        || evidence.v2_first_logical_block != control.v2_first_logical_block
        || evidence.v2_logical_block_count != control.v2_logical_block_count
        || evidence.store_uuid.as_bytes() == &[0; 16]
        || evidence.checkpoint_generation == 0
        || evidence.authority_sha256 == [0; 32]
    {
        return Err(MigrationError::ScrubMismatch);
    }
    control.store_uuid = *evidence.store_uuid.as_bytes();
    control.activation_checkpoint_generation = evidence.checkpoint_generation;
    control.activation_authority_sha256 = evidence.authority_sha256;
    Ok(())
}

fn require_same_evidence<E>(
    control: MigrationControl,
    evidence: ColdScrubEvidence,
) -> Result<(), MigrationError<E>> {
    let mut observed = control;
    apply_evidence(&mut observed, evidence)?;
    if observed.store_uuid != control.store_uuid
        || observed.activation_checkpoint_generation != control.activation_checkpoint_generation
        || observed.activation_authority_sha256 != control.activation_authority_sha256
    {
        Err(MigrationError::ScrubMismatch)
    } else {
        Ok(())
    }
}

fn require_active_evidence<E>(
    control: MigrationControl,
    evidence: ColdScrubEvidence,
) -> Result<(), MigrationError<E>> {
    if !evidence.complete
        || evidence.device_id != control.device_id
        || evidence.v2_first_logical_block != control.v2_first_logical_block
        || evidence.v2_logical_block_count != control.v2_logical_block_count
        || evidence.store_uuid.as_bytes() != &control.store_uuid
        || evidence.checkpoint_generation < control.activation_checkpoint_generation
        || evidence.authority_sha256 == [0; 32]
        || (evidence.checkpoint_generation == control.activation_checkpoint_generation
            && evidence.authority_sha256 != control.activation_authority_sha256)
    {
        Err(MigrationError::ScrubMismatch)
    } else {
        Ok(())
    }
}

fn validate_control_device<E>(info: PageDeviceInfo) -> Result<(), MigrationError<E>> {
    if info.range_first_logical_block != MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK
        || info.logical_block_count != MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT
        || info.logical_block_size != 512
        || info.page_count != CONTROL_PAGE_COUNT
        || info.device_id == [0; 16]
    {
        Err(MigrationError::InvalidControlDevice)
    } else {
        Ok(())
    }
}

async fn read_pair<D: PageDevice>(
    device: &D,
    first: u64,
) -> Result<Box<[Page; 2]>, MigrationError<D::Error>> {
    let mut pair = Box::new([[0; PAGE_SIZE]; 2]);
    device
        .read_page(first, &mut pair[0])
        .await
        .map_err(MigrationError::Device)?;
    device
        .read_page(first + 1, &mut pair[1])
        .await
        .map_err(MigrationError::Device)?;
    Ok(pair)
}

fn ranges_overlap(
    a_first: u64,
    a_count: u64,
    b_first: u64,
    b_count: u64,
) -> Result<bool, MigrationControlError> {
    let a_end = a_first
        .checked_add(a_count)
        .ok_or(MigrationControlError::InvalidBinding)?;
    let b_end = b_first
        .checked_add(b_count)
        .ok_or(MigrationControlError::InvalidBinding)?;
    Ok(a_first < b_end && b_first < a_end)
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed field"))
}
fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}
fn is_zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::{
        MaintenanceDomain, MaintenanceOperation, StoreMaintenanceProvisioner,
    };
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use std::sync::Mutex;
    use vibeos_storage_device::MutationFailure;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        loop {
            match poll_once(future.as_mut()) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Injected,
        OutsideRange,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FaultEffect {
        NotSubmitted,
        AmbiguousVolatile,
        AmbiguousDurable,
        PendingNoEffect,
        PendingVolatile,
        PendingDurable,
    }

    struct TestMedia {
        visible: [Page; CONTROL_PAGE_COUNT as usize],
        durable: [Page; CONTROL_PAGE_COUNT as usize],
        reads: usize,
        mutations: usize,
        fault: Option<(usize, FaultEffect)>,
    }

    #[derive(Clone)]
    struct MemoryControlDevice(Arc<Mutex<TestMedia>>);

    impl MemoryControlDevice {
        fn blank() -> Self {
            Self(Arc::new(Mutex::new(TestMedia {
                visible: [[0; PAGE_SIZE]; CONTROL_PAGE_COUNT as usize],
                durable: [[0; PAGE_SIZE]; CONTROL_PAGE_COUNT as usize],
                reads: 0,
                mutations: 0,
                fault: None,
            })))
        }

        fn seed(&self, page: u64, bytes: Page) {
            let mut media = self.0.lock().unwrap();
            media.visible[page as usize] = bytes;
            media.durable[page as usize] = bytes;
        }

        fn inject(&self, mutation: usize, effect: FaultEffect) {
            let mut media = self.0.lock().unwrap();
            media.reads = 0;
            media.mutations = 0;
            media.fault = Some((mutation, effect));
        }

        fn crash(&self) {
            let mut media = self.0.lock().unwrap();
            media.visible = media.durable;
            media.fault = None;
        }

        fn io_counts(&self) -> (usize, usize) {
            let media = self.0.lock().unwrap();
            (media.reads, media.mutations)
        }

        fn begin_mutation(&self) -> Option<FaultEffect> {
            let mut media = self.0.lock().unwrap();
            media.mutations += 1;
            media
                .fault
                .filter(|(mutation, _)| *mutation == media.mutations)
                .map(|(_, effect)| effect)
        }
    }

    impl PageDevice for MemoryControlDevice {
        type Error = TestError;

        fn info(&self) -> PageDeviceInfo {
            PageDeviceInfo {
                device_id: [7; 16],
                range_first_logical_block: MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK,
                logical_block_count: MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT,
                logical_block_size: 512,
                page_count: CONTROL_PAGE_COUNT,
            }
        }

        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            let mut media = self.0.lock().unwrap();
            media.reads += 1;
            let Some(bytes) = media.visible.get(page as usize) else {
                return Err(TestError::OutsideRange);
            };
            *output = *bytes;
            Ok(())
        }

        async fn write_page(
            &self,
            page: u64,
            input: &Page,
        ) -> Result<(), MutationFailure<Self::Error>> {
            if page >= CONTROL_PAGE_COUNT {
                return Err(MutationFailure::not_submitted(TestError::OutsideRange));
            }
            let effect = self.begin_mutation();
            match effect {
                Some(FaultEffect::NotSubmitted) => {
                    return Err(MutationFailure::not_submitted(TestError::Injected));
                }
                Some(FaultEffect::PendingNoEffect) => {
                    core::future::pending::<()>().await;
                    unreachable!();
                }
                _ => {}
            }
            {
                let mut media = self.0.lock().unwrap();
                media.visible[page as usize] = *input;
                if matches!(
                    effect,
                    Some(FaultEffect::AmbiguousDurable | FaultEffect::PendingDurable)
                ) {
                    media.durable[page as usize] = *input;
                }
            }
            match effect {
                Some(FaultEffect::AmbiguousVolatile | FaultEffect::AmbiguousDurable) => {
                    Err(MutationFailure::ambiguous(TestError::Injected))
                }
                Some(FaultEffect::PendingVolatile | FaultEffect::PendingDurable) => {
                    core::future::pending::<()>().await;
                    unreachable!();
                }
                None => Ok(()),
                Some(FaultEffect::NotSubmitted | FaultEffect::PendingNoEffect) => unreachable!(),
            }
        }

        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            match self.begin_mutation() {
                Some(FaultEffect::NotSubmitted) => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                Some(FaultEffect::AmbiguousVolatile) => {
                    Err(MutationFailure::ambiguous(TestError::Injected))
                }
                Some(FaultEffect::AmbiguousDurable) => {
                    let mut media = self.0.lock().unwrap();
                    media.durable = media.visible;
                    Err(MutationFailure::ambiguous(TestError::Injected))
                }
                Some(FaultEffect::PendingNoEffect | FaultEffect::PendingVolatile) => {
                    core::future::pending::<()>().await;
                    unreachable!();
                }
                Some(FaultEffect::PendingDurable) => {
                    {
                        let mut media = self.0.lock().unwrap();
                        media.durable = media.visible;
                    }
                    core::future::pending::<()>().await;
                    unreachable!();
                }
                None => {
                    let mut media = self.0.lock().unwrap();
                    media.durable = media.visible;
                    Ok(())
                }
            }
        }
    }

    fn uuid(byte: u8) -> StoreUuid {
        StoreUuid::new([byte; 16]).unwrap()
    }
    fn active() -> MigrationControl {
        MigrationControl {
            state: MigrationState::V2Active,
            generation: 3,
            device_id: [7; 16],
            m4_first_logical_block: M4_FIRST_LOGICAL_BLOCK,
            m4_logical_block_count: M4_LOGICAL_BLOCK_COUNT,
            v2_first_logical_block: V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            v2_logical_block_count: V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            store_uuid: [8; 16],
            activation_checkpoint_generation: 11,
            activation_authority_sha256: [9; 32],
        }
    }

    fn staged_evidence() -> ColdScrubEvidence {
        ColdScrubEvidence {
            device_id: [7; 16],
            v2_first_logical_block: V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            v2_logical_block_count: V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            store_uuid: uuid(8),
            checkpoint_generation: 11,
            authority_sha256: [9; 32],
            complete: true,
        }
    }

    fn staged() -> MigrationControl {
        let mut value = active();
        value.state = MigrationState::V2Staged;
        value.generation = 2;
        value
    }

    fn close_evidence() -> ColdScrubEvidence {
        let mut evidence = staged_evidence();
        evidence.checkpoint_generation += 1;
        evidence.authority_sha256 = [10; 32];
        evidence
    }

    fn maintenance(
        store_uuid: StoreUuid,
        device_id: [u8; 16],
        first: u64,
        count: u64,
        operations: &[MaintenanceOperation],
    ) -> (StoreMaintenance, StoreMaintenanceProvisioner) {
        let domain = Arc::new(MaintenanceDomain::new());
        let provisioner = StoreMaintenanceProvisioner::new(domain.clone());
        let maintenance = StoreMaintenance::mint_root(domain, store_uuid, device_id, first, count)
            .attenuate(operations)
            .unwrap();
        (maintenance, provisioner)
    }

    fn seed_frozen(device: &MemoryControlDevice) -> MigrationControl {
        let value = MigrationControl::frozen(device.info().device_id);
        seed_control(device, value);
        value
    }

    fn seed_control(device: &MemoryControlDevice, value: MigrationControl) {
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        encode_migration_control(value, &mut body, &mut seal).unwrap();
        let slot = (value.generation - 1) & 1;
        device.seed(slot * 2, body);
        device.seed(slot * 2 + 1, seal);
    }

    #[derive(Clone, Copy, Debug)]
    enum ControlTransitionCase {
        Freeze,
        Stage,
        Activate,
        Rollback,
        Close,
    }

    impl ControlTransitionCase {
        const ALL: [Self; 5] = [
            Self::Freeze,
            Self::Stage,
            Self::Activate,
            Self::Rollback,
            Self::Close,
        ];

        fn fixture(self) -> ControlTransitionFixture {
            let device = MemoryControlDevice::blank();
            match self {
                Self::Freeze => ControlTransitionFixture {
                    device,
                    current: None,
                    transition: MigrationTransition::FreezeM4(uuid(8)),
                },
                Self::Stage => {
                    let frozen = seed_frozen(&device);
                    ControlTransitionFixture {
                        device,
                        current: Some(frozen),
                        transition: MigrationTransition::StageV2(staged_evidence()),
                    }
                }
                Self::Activate | Self::Rollback => {
                    seed_frozen(&device);
                    let staged = staged();
                    seed_control(&device, staged);
                    ControlTransitionFixture {
                        device,
                        current: Some(staged),
                        transition: if matches!(self, Self::Activate) {
                            MigrationTransition::ActivateV2(staged_evidence())
                        } else {
                            MigrationTransition::RollBackToM4
                        },
                    }
                }
                Self::Close => {
                    seed_control(&device, staged());
                    let active = active();
                    seed_control(&device, active);
                    ControlTransitionFixture {
                        device,
                        current: Some(active),
                        transition: MigrationTransition::CloseRollback(close_evidence()),
                    }
                }
            }
        }
    }

    struct ControlTransitionFixture {
        device: MemoryControlDevice,
        current: Option<MigrationControl>,
        transition: MigrationTransition,
    }

    #[test]
    fn exact_control_round_trip_and_every_single_byte_body_corruption_fail_closed() {
        let value = active();
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        encode_migration_control(value, &mut body, &mut seal).unwrap();
        assert_eq!(decode_migration_control(&body, &seal), Ok(value));
        for offset in 0..PAGE_SIZE {
            let mut corrupt = body;
            corrupt[offset] ^= 1;
            assert!(
                decode_migration_control(&corrupt, &seal).is_err(),
                "offset {offset}"
            );
        }
        for offset in 0..PAGE_SIZE {
            let mut corrupt = seal;
            corrupt[offset] ^= 1;
            assert!(
                decode_migration_control(&body, &corrupt).is_err(),
                "seal offset {offset}"
            );
        }

        let expected = canonical_seal_for_body(&body);
        for written in 1..PAGE_SIZE {
            let mut prefix = [0; PAGE_SIZE];
            prefix[..written].copy_from_slice(&expected[..written]);
            assert_eq!(
                decode_migration_control(&body, &prefix),
                Err(MigrationControlError::Torn),
                "seal write prefix {written}"
            );

            let mut cleared = expected;
            cleared[..written].fill(0);
            assert_eq!(
                decode_migration_control(&body, &cleared),
                Err(MigrationControlError::Torn),
                "seal clear prefix {written}"
            );
        }

        let frozen = MigrationControl::frozen([7; 16]);
        let mut frozen_body = [0; PAGE_SIZE];
        let mut frozen_seal = [0; PAGE_SIZE];
        encode_migration_control(frozen, &mut frozen_body, &mut frozen_seal).unwrap();
        frozen_body[0x70] = 1;
        let payload_digest: [u8; 32] = Sha256::digest(&frozen_body[0x40..]).into();
        frozen_body[BODY_DIGEST_AT..BODY_DIGEST_AT + 32].copy_from_slice(&payload_digest);
        frozen_seal = canonical_seal_for_body(&frozen_body);
        assert_eq!(
            decode_migration_control(&frozen_body, &frozen_seal),
            Err(MigrationControlError::InvalidBinding)
        );
    }

    #[test]
    fn selector_ignores_torn_slot_but_rejects_same_generation_disagreement() {
        let value = active();
        assert_eq!(
            select_migration_control(Ok(value), Err(MigrationControlError::Torn)),
            Ok(Some(value))
        );
        let mut other = value;
        other.state = MigrationState::RollbackClosed;
        assert_eq!(
            select_migration_control(Ok(value), Ok(other)),
            Err(MigrationControlError::AmbiguousGeneration)
        );

        let mut skipped = value;
        skipped.generation += 2;
        assert_eq!(
            select_migration_control(Ok(value), Ok(skipped)),
            Err(MigrationControlError::AmbiguousGeneration)
        );
    }

    #[test]
    fn selector_requires_a_legal_successor_with_stable_bindings() {
        let mut staged = active();
        staged.state = MigrationState::V2Staged;
        staged.generation = 2;
        let active = active();
        assert_eq!(
            select_migration_control(Ok(staged), Ok(active)),
            Ok(Some(active))
        );
        let mut rebound = active;
        rebound.device_id = [6; 16];
        assert_eq!(
            select_migration_control(Ok(staged), Ok(rebound)),
            Err(MigrationControlError::AmbiguousGeneration)
        );
    }

    #[test]
    fn boot_preference_requires_exact_v2_evidence() {
        let value = active();
        let v2 = StorageV2FormatProbe::Valid {
            device_id: value.device_id,
            v2_first_logical_block: value.v2_first_logical_block,
            v2_logical_block_count: value.v2_logical_block_count,
            store_uuid: uuid(8),
            checkpoint_generation: value.activation_checkpoint_generation,
            authority_sha256: value.activation_authority_sha256,
        };
        assert_eq!(
            probe_storage_formats(LegacyFormatProbe::Valid, v2, Some(value)),
            FormatProbe::BothPreferV2
        );
        assert_eq!(
            probe_storage_formats(
                LegacyFormatProbe::Valid,
                StorageV2FormatProbe::Valid {
                    device_id: value.device_id,
                    v2_first_logical_block: value.v2_first_logical_block,
                    v2_logical_block_count: value.v2_logical_block_count,
                    store_uuid: uuid(8),
                    checkpoint_generation: value.activation_checkpoint_generation,
                    authority_sha256: [1; 32]
                },
                Some(value)
            ),
            FormatProbe::Corrupt
        );
        assert_eq!(
            probe_storage_formats(LegacyFormatProbe::Valid, v2, None),
            FormatProbe::BothPreferM4
        );
        let frozen = MigrationControl::frozen(value.device_id);
        assert_eq!(
            probe_storage_formats(LegacyFormatProbe::Valid, v2, Some(frozen)),
            FormatProbe::BothPreferM4
        );
        assert_eq!(
            probe_storage_formats(
                LegacyFormatProbe::Valid,
                StorageV2FormatProbe::Valid {
                    device_id: value.device_id,
                    v2_first_logical_block: value.v2_first_logical_block,
                    v2_logical_block_count: value.v2_logical_block_count,
                    store_uuid: uuid(8),
                    checkpoint_generation: value.activation_checkpoint_generation + 1,
                    authority_sha256: [1; 32],
                },
                Some(value),
            ),
            FormatProbe::BothPreferV2
        );
        assert_eq!(
            probe_storage_formats(LegacyFormatProbe::Absent, v2, None),
            FormatProbe::Corrupt
        );

        for mismatched in [
            StorageV2FormatProbe::Valid {
                device_id: [6; 16],
                v2_first_logical_block: value.v2_first_logical_block,
                v2_logical_block_count: value.v2_logical_block_count,
                store_uuid: uuid(8),
                checkpoint_generation: value.activation_checkpoint_generation,
                authority_sha256: value.activation_authority_sha256,
            },
            StorageV2FormatProbe::Valid {
                device_id: value.device_id,
                v2_first_logical_block: value.v2_first_logical_block + 8,
                v2_logical_block_count: value.v2_logical_block_count,
                store_uuid: uuid(8),
                checkpoint_generation: value.activation_checkpoint_generation,
                authority_sha256: value.activation_authority_sha256,
            },
            StorageV2FormatProbe::Valid {
                device_id: value.device_id,
                v2_first_logical_block: value.v2_first_logical_block,
                v2_logical_block_count: value.v2_logical_block_count - 8,
                store_uuid: uuid(8),
                checkpoint_generation: value.activation_checkpoint_generation,
                authority_sha256: value.activation_authority_sha256,
            },
        ] {
            assert_eq!(
                probe_storage_formats(LegacyFormatProbe::Valid, mismatched, Some(value)),
                FormatProbe::Corrupt
            );
        }
    }

    #[test]
    fn controller_requires_explicit_store_bound_maintenance_before_io() {
        let candidates = [
            maintenance(
                uuid(8),
                [7; 16],
                V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT,
                &[MaintenanceOperation::Grow, MaintenanceOperation::Scrub],
            ),
            maintenance(
                uuid(8),
                [6; 16],
                V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT,
                &[MaintenanceOperation::ExplicitMaintenance],
            ),
            maintenance(
                uuid(8),
                [7; 16],
                V2_DEFAULT_FIRST_LOGICAL_BLOCK + 8,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT,
                &[MaintenanceOperation::ExplicitMaintenance],
            ),
            maintenance(
                uuid(8),
                [7; 16],
                V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT - 8,
                &[MaintenanceOperation::ExplicitMaintenance],
            ),
            maintenance(
                uuid(6),
                [7; 16],
                V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                V2_DEFAULT_LOGICAL_BLOCK_COUNT,
                &[MaintenanceOperation::ExplicitMaintenance],
            ),
        ];
        for (candidate, provisioner) in &candidates {
            let device = MemoryControlDevice::blank();
            let frozen = seed_frozen(&device);
            let result = block_on(
                MigrationController::new(device.clone())
                    .unwrap()
                    .transition(
                        candidate,
                        provisioner,
                        Some(frozen),
                        MigrationTransition::StageV2(staged_evidence()),
                    ),
            );
            assert_eq!(result, Err(MigrationError::Unauthorized));
            assert_eq!(device.io_counts(), (0, 0));
        }

        let (same_binding, _same_binding_provisioner) = maintenance(
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );
        let foreign_domain = Arc::new(MaintenanceDomain::new());
        let foreign_domain_provisioner = StoreMaintenanceProvisioner::new(foreign_domain);
        let device = MemoryControlDevice::blank();
        let frozen = seed_frozen(&device);
        assert_eq!(
            block_on(
                MigrationController::new(device.clone())
                    .unwrap()
                    .transition(
                        &same_binding,
                        &foreign_domain_provisioner,
                        Some(frozen),
                        MigrationTransition::StageV2(staged_evidence()),
                    )
            ),
            Err(MigrationError::Unauthorized)
        );
        assert_eq!(device.io_counts(), (0, 0));

        let domain = Arc::new(MaintenanceDomain::new());
        let provisioner = StoreMaintenanceProvisioner::new(domain.clone());
        let revoked = StoreMaintenance::mint_root(
            domain,
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
        )
        .attenuate(&[MaintenanceOperation::ExplicitMaintenance])
        .unwrap();
        provisioner.revoke_all().unwrap();
        let device = MemoryControlDevice::blank();
        let frozen = seed_frozen(&device);
        assert_eq!(
            block_on(
                MigrationController::new(device.clone())
                    .unwrap()
                    .transition(
                        &revoked,
                        &provisioner,
                        Some(frozen),
                        MigrationTransition::StageV2(staged_evidence()),
                    )
            ),
            Err(MigrationError::Unauthorized)
        );
        assert_eq!(device.io_counts(), (0, 0));

        let device = MemoryControlDevice::blank();
        let (foreign_store, foreign_provisioner) = maintenance(
            uuid(6),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );
        assert_eq!(
            block_on(
                MigrationController::new(device.clone())
                    .unwrap()
                    .transition(
                        &foreign_store,
                        &foreign_provisioner,
                        None,
                        MigrationTransition::FreezeM4(uuid(8)),
                    )
            ),
            Err(MigrationError::Unauthorized)
        );
        assert_eq!(device.io_counts(), (0, 0));
    }

    #[test]
    fn every_control_transition_mutation_and_cancel_recovers_old_or_exact_new() {
        const MUTATION_BOUNDARIES: usize = 6;
        const FAILURE_EFFECTS: [FaultEffect; 3] = [
            FaultEffect::NotSubmitted,
            FaultEffect::AmbiguousVolatile,
            FaultEffect::AmbiguousDurable,
        ];
        const CANCELLATION_EFFECTS: [FaultEffect; 3] = [
            FaultEffect::PendingNoEffect,
            FaultEffect::PendingVolatile,
            FaultEffect::PendingDurable,
        ];

        let (explicit, provisioner) = maintenance(
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );

        for case in ControlTransitionCase::ALL {
            let probe = case.fixture();
            let expected =
                next_control::<TestError>(probe.device.info(), probe.current, probe.transition)
                    .unwrap();
            assert_eq!(
                block_on(
                    MigrationController::new(probe.device.clone())
                        .unwrap()
                        .transition(&explicit, &provisioner, probe.current, probe.transition),
                ),
                Ok(expected),
                "{case:?}: successful transition"
            );
            assert_eq!(
                probe.device.io_counts().1,
                MUTATION_BOUNDARIES,
                "{case:?}: mutation surface"
            );

            for mutation in 1..=MUTATION_BOUNDARIES {
                for effect in FAILURE_EFFECTS {
                    let fixture = case.fixture();
                    let expected = next_control::<TestError>(
                        fixture.device.info(),
                        fixture.current,
                        fixture.transition,
                    )
                    .unwrap();
                    fixture.device.inject(mutation, effect);
                    let result = block_on(
                        MigrationController::new(fixture.device.clone())
                            .unwrap()
                            .transition(
                                &explicit,
                                &provisioner,
                                fixture.current,
                                fixture.transition,
                            ),
                    );
                    assert!(
                        matches!(result, Err(MigrationError::Mutation(_))),
                        "{case:?}, mutation {mutation}, effect {effect:?}: {result:?}"
                    );
                    assert_eq!(
                        fixture.device.io_counts().1,
                        mutation,
                        "{case:?}, mutation {mutation}, effect {effect:?}"
                    );
                    fixture.device.crash();
                    let recovered = block_on(
                        MigrationController::new(fixture.device.clone())
                            .unwrap()
                            .recover(),
                    )
                    .unwrap();
                    let expected_recovery =
                        if effect == FaultEffect::AmbiguousDurable && mutation >= 5 {
                            Some(expected)
                        } else {
                            fixture.current
                        };
                    assert_eq!(
                        recovered, expected_recovery,
                        "{case:?}, mutation {mutation}, effect {effect:?}"
                    );
                }

                for effect in CANCELLATION_EFFECTS {
                    let fixture = case.fixture();
                    let expected = next_control::<TestError>(
                        fixture.device.info(),
                        fixture.current,
                        fixture.transition,
                    )
                    .unwrap();
                    fixture.device.inject(mutation, effect);
                    let controller = MigrationController::new(fixture.device.clone()).unwrap();
                    let mut operation = Box::pin(controller.transition(
                        &explicit,
                        &provisioner,
                        fixture.current,
                        fixture.transition,
                    ));
                    assert!(
                        matches!(poll_once(operation.as_mut()), Poll::Pending),
                        "{case:?}, mutation {mutation}, cancellation {effect:?}"
                    );
                    assert_eq!(
                        fixture.device.io_counts().1,
                        mutation,
                        "{case:?}, mutation {mutation}, cancellation {effect:?}"
                    );
                    drop(operation);
                    fixture.device.crash();
                    let recovered = block_on(
                        MigrationController::new(fixture.device.clone())
                            .unwrap()
                            .recover(),
                    )
                    .unwrap();
                    let expected_recovery =
                        if effect == FaultEffect::PendingDurable && mutation >= 5 {
                            Some(expected)
                        } else {
                            fixture.current
                        };
                    assert_eq!(
                        recovered, expected_recovery,
                        "{case:?}, mutation {mutation}, cancellation {effect:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn explicitly_authorized_controller_transition_publishes_exact_successor() {
        let device = MemoryControlDevice::blank();
        let frozen = seed_frozen(&device);
        let evidence = staged_evidence();
        let (explicit, provisioner) = maintenance(
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );
        let staged = block_on(
            MigrationController::new(device.clone())
                .unwrap()
                .transition(
                    &explicit,
                    &provisioner,
                    Some(frozen),
                    MigrationTransition::StageV2(evidence),
                ),
        )
        .unwrap();
        assert_eq!(staged.state, MigrationState::V2Staged);
        assert_eq!(staged.generation, frozen.generation + 1);
        assert_eq!(
            block_on(MigrationController::new(device).unwrap().recover()),
            Ok(Some(staged))
        );
    }

    #[test]
    fn native_v2_initialization_publishes_generation_one_closed_control() {
        let device = MemoryControlDevice::blank();
        let evidence = staged_evidence();
        let (explicit, provisioner) = maintenance(
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );
        let active = block_on(
            MigrationController::new(device.clone())
                .unwrap()
                .transition(
                    &explicit,
                    &provisioner,
                    None,
                    MigrationTransition::InitializeV2(evidence),
                ),
        )
        .unwrap();
        assert_eq!(active.state, MigrationState::RollbackClosed);
        assert_eq!(active.generation, 1);
        assert_eq!(active.store_uuid, *evidence.store_uuid.as_bytes());
        assert_eq!(
            active.activation_checkpoint_generation,
            evidence.checkpoint_generation
        );
        assert_eq!(
            active.activation_authority_sha256,
            evidence.authority_sha256
        );
        assert_eq!(
            block_on(MigrationController::new(device).unwrap().recover()),
            Ok(Some(active))
        );
    }

    #[test]
    fn every_native_control_boundary_recovers_none_or_exact_closed() {
        let effects = [
            FaultEffect::NotSubmitted,
            FaultEffect::AmbiguousVolatile,
            FaultEffect::AmbiguousDurable,
        ];
        for mutation in 1..=6 {
            for effect in effects {
                let device = MemoryControlDevice::blank();
                let evidence = staged_evidence();
                let (explicit, provisioner) = maintenance(
                    uuid(8),
                    [7; 16],
                    V2_DEFAULT_FIRST_LOGICAL_BLOCK,
                    V2_DEFAULT_LOGICAL_BLOCK_COUNT,
                    &[MaintenanceOperation::ExplicitMaintenance],
                );
                let expected = next_control::<TestError>(
                    device.info(),
                    None,
                    MigrationTransition::InitializeV2(evidence),
                )
                .unwrap();
                device.inject(mutation, effect);
                let result = block_on(
                    MigrationController::new(device.clone())
                        .unwrap()
                        .transition(
                            &explicit,
                            &provisioner,
                            None,
                            MigrationTransition::InitializeV2(evidence),
                        ),
                );
                assert!(
                    matches!(result, Err(MigrationError::Mutation(_))),
                    "mutation {mutation}, effect {effect:?}: {result:?}"
                );
                device.crash();
                let recovered =
                    block_on(MigrationController::new(device).unwrap().recover()).unwrap();
                let exact = if effect == FaultEffect::AmbiguousDurable && mutation >= 5 {
                    Some(expected)
                } else {
                    None
                };
                assert_eq!(recovered, exact, "mutation {mutation}, effect {effect:?}");
            }
        }
    }

    #[test]
    fn controller_rollback_and_close_publish_only_legal_successors() {
        let (explicit, provisioner) = maintenance(
            uuid(8),
            [7; 16],
            V2_DEFAULT_FIRST_LOGICAL_BLOCK,
            V2_DEFAULT_LOGICAL_BLOCK_COUNT,
            &[MaintenanceOperation::ExplicitMaintenance],
        );

        let rollback_device = MemoryControlDevice::blank();
        let frozen = seed_frozen(&rollback_device);
        let mut staged = active();
        staged.state = MigrationState::V2Staged;
        staged.generation = frozen.generation + 1;
        seed_control(&rollback_device, staged);
        let rolled_back = block_on(
            MigrationController::new(rollback_device.clone())
                .unwrap()
                .transition(
                    &explicit,
                    &provisioner,
                    Some(staged),
                    MigrationTransition::RollBackToM4,
                ),
        )
        .unwrap();
        assert_eq!(rolled_back.state, MigrationState::FrozenM4);
        assert_eq!(rolled_back.generation, staged.generation + 1);
        assert_eq!(rolled_back.store_uuid, [0; 16]);
        assert_eq!(
            block_on(MigrationController::new(rollback_device).unwrap().recover()),
            Ok(Some(rolled_back))
        );

        let close_device = MemoryControlDevice::blank();
        seed_control(&close_device, staged);
        let active = active();
        seed_control(&close_device, active);
        let mut newer_evidence = staged_evidence();
        newer_evidence.checkpoint_generation += 1;
        newer_evidence.authority_sha256 = [10; 32];
        let closed = block_on(
            MigrationController::new(close_device.clone())
                .unwrap()
                .transition(
                    &explicit,
                    &provisioner,
                    Some(active),
                    MigrationTransition::CloseRollback(newer_evidence),
                ),
        )
        .unwrap();
        assert_eq!(closed.state, MigrationState::RollbackClosed);
        assert_eq!(closed.generation, active.generation + 1);
        assert!(same_v2_binding(active, closed));
        assert_eq!(
            block_on(MigrationController::new(close_device).unwrap().recover()),
            Ok(Some(closed))
        );
    }

    #[test]
    fn close_rejects_stale_or_floor_mismatched_scrub_evidence() {
        let value = active();
        let mut stale = staged_evidence();
        stale.checkpoint_generation = value.activation_checkpoint_generation - 1;
        assert_eq!(
            next_control::<TestError>(
                PageDeviceInfo {
                    device_id: [7; 16],
                    range_first_logical_block: MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK,
                    logical_block_count: MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT,
                    logical_block_size: 512,
                    page_count: CONTROL_PAGE_COUNT,
                },
                Some(value),
                MigrationTransition::CloseRollback(stale),
            ),
            Err(MigrationError::ScrubMismatch)
        );
        let mut wrong_floor = staged_evidence();
        wrong_floor.authority_sha256 = [10; 32];
        assert_eq!(
            next_control::<TestError>(
                PageDeviceInfo {
                    device_id: [7; 16],
                    range_first_logical_block: MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK,
                    logical_block_count: MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT,
                    logical_block_size: 512,
                    page_count: CONTROL_PAGE_COUNT,
                },
                Some(value),
                MigrationTransition::CloseRollback(wrong_floor),
            ),
            Err(MigrationError::ScrubMismatch)
        );
    }

    #[test]
    fn controller_rejects_a_valid_record_in_the_wrong_slot() {
        let device = MemoryControlDevice::blank();
        let value = MigrationControl::frozen(device.info().device_id);
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        encode_migration_control(value, &mut body, &mut seal).unwrap();
        device.seed(2, body);
        device.seed(3, seal);
        assert_eq!(
            block_on(MigrationController::new(device).unwrap().recover()),
            Err(MigrationError::Control(
                MigrationControlError::InvalidBinding
            ))
        );
    }
}
