//! Durable authority-store policy and public service contract.

#![no_std]

use vibeos_core::durable::{DurableRights, ObjectKind, ResourceKind, SpaceId};
use vibeos_object_store::StoreError;

pub const PERSISTENT_SPACE_ID_RAW: u128 = 0x5053;
pub const STORED_OBJECT_RESOURCE_KIND_RAW: u32 = 0x5354_4f52;
pub const PERSISTENT_OBJECT_KIND_RAW: u32 = 0x4353_5043;
pub const ROOT_SLOT: u32 = 0;
pub const CHILD_SLOT: u32 = 1;
pub const GRANDCHILD_SLOT: u32 = 2;
pub const ROOT_RIGHTS: DurableRights = DurableRights::READ
    .union(DurableRights::GRANT)
    .union(DurableRights::REVOKE);
pub const CHILD_RIGHTS: DurableRights = DurableRights::READ.union(DurableRights::GRANT);
pub const GRANDCHILD_RIGHTS: DurableRights = DurableRights::READ;
pub const MARKER: &[u8] = b"VIBEOS-PERSISTENT-CSPACE-v1";

pub const fn persistent_space_id() -> SpaceId {
    match SpaceId::new(PERSISTENT_SPACE_ID_RAW) {
        Some(id) => id,
        None => unreachable!(),
    }
}

pub fn stored_object_resource_kind() -> ResourceKind {
    ResourceKind::new(STORED_OBJECT_RESOURCE_KIND_RAW)
        .expect("the StoredObject durable resource kind is non-zero")
}

pub fn persistent_object_kind() -> ObjectKind {
    ObjectKind::new(PERSISTENT_OBJECT_KIND_RAW)
        .expect("the persistent-test object kind is non-zero")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DurableCSpaceState {
    Cold = 0,
    WaitingBlock = 1,
    Recovering = 2,
    Ready = 3,
    FailedClosed = 4,
}

impl DurableCSpaceState {
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Cold,
            1 => Self::WaitingBlock,
            2 => Self::Recovering,
            3 => Self::Ready,
            _ => Self::FailedClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentTestPhase {
    Boot1Created,
    Boot2Revoked,
    Boot3Reused,
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentTestReport {
    pub phase: PersistentTestPhase,
    pub root_slot: u32,
    pub root_generation: u64,
    pub child_slot: u32,
    pub old_child_generation: u64,
    pub child_generation: u64,
    pub read_ok: bool,
    pub old_child_absent: bool,
    pub descendant_absent: bool,
    pub no_store_write: bool,
    pub dependent_started: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableCSpaceInfo {
    pub state: DurableCSpaceState,
    pub live_grants: usize,
    pub tombstones: usize,
    pub dependent_started: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableCSpaceError {
    PermissionDenied,
    Busy,
    OutsideTask,
    FailedClosed,
    Store(StoreError),
    IdExhausted,
    Encode,
    RootPolicy,
    Install,
    UnexpectedGraph,
}

impl core::fmt::Display for DurableCSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "durable CSpace journal failed: {error}"),
            _ => f.write_str(match self {
                Self::PermissionDenied => "durable CSpace service lacks WRITE",
                Self::Busy => "durable CSpace operation already active",
                Self::OutsideTask => "durable CSpace operations require an executor task",
                Self::FailedClosed => "durable CSpace recovery failed closed",
                Self::IdExhausted => "durable stable ID space exhausted",
                Self::Encode => "durable authority record encoding failed",
                Self::RootPolicy => "durable root policy did not match exactly",
                Self::Install => "durable CSpace publication revalidation failed",
                Self::UnexpectedGraph => "durable CSpace graph has an unexpected shape",
                Self::Store(_) => unreachable!(),
            }),
        }
    }
}

impl From<StoreError> for DurableCSpaceError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
