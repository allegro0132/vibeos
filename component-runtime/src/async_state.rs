//! Bounded state for Vibe's resource-free native async Component profile.
//!
//! This module deliberately owns no Core Wasm stack and retains no linear-
//! memory slice. A copy records only an opaque buffer lease; the executor must
//! perform the actual transfer and later reclaim that exact lease through the
//! two-phase tickets below. Endpoints and waitable sets share one guest handle
//! arena; tasks use a separate runtime-only table because this profile has no
//! guest-visible subtask handles.
//!
//! Constructing this state is not execution authority. The executor must own
//! the sealed proof that its decoded plan is the versioned resource-free
//! profile before it can expose any of these transitions to component code.

use crate::{
    async_abi::{pack_stream_copy_result, CopyResult, EventCode, BLOCKED},
    value::{
        validate_readable_future_endpoint, validate_readable_stream_endpoint, AsyncValueTypeId,
        CanonicalValue, EndpointDirection, EndpointGeneration, EndpointOwner,
        ReadableFutureEndpointToken, ReadableStreamEndpointToken,
    },
};
use alloc::vec::Vec;
use core::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
    sync::atomic::{AtomicU64, Ordering},
};
use vibeos_component_format::PROFILE_1_LIMITS;

const CANONICAL_HANDLE_MAX: u32 = (1_u32 << 28) - 1;
static NEXT_ASYNC_STATE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncStateLimits {
    pub handles: u32,
    pub pairs: u32,
    pub tasks: u32,
    pub waitables_per_set: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AsyncStateError {
    AllocationFailed = 1,
    InvalidLimits = 2,
    HandleTableFull = 3,
    PairTableFull = 4,
    InvalidHandle = 5,
    StaleHandle = 6,
    WrongState = 7,
    WrongHandleKind = 8,
    WrongEndpointKind = 9,
    WrongDirection = 10,
    WrongType = 11,
    EndpointBusy = 12,
    EndpointDone = 13,
    OperationNotCopying = 14,
    StaleOperation = 15,
    PairBusy = 16,
    PairInvariant = 17,
    ProgressLimit = 18,
    InvalidCopyResult = 19,
    NoPendingEvent = 20,
    EventAlreadyDelivered = 21,
    StaleEvent = 22,
    DropWhileCopying = 23,
    FutureWritableNotDone = 24,
    AuthorityConsumed = 25,
    GenerationExhausted = 26,
    DuplicateHandle = 27,
    WaitableSetFull = 28,
    WaitableNotJoined = 29,
    WaitableSetNotEmpty = 30,
    WaitableSetWaiting = 31,
    WaitableSetNotWaiting = 32,
    AlreadyWaiting = 33,
    StaleWait = 34,
    TaskTableFull = 35,
    TaskAlreadyResolved = 36,
    TaskNotResolved = 37,
    TaskAlreadyExited = 38,
    TaskIncomplete = 39,
    TaskCancelState = 40,
    TransferWhileJoined = 41,
    CancelWhileJoined = 42,
}

impl AsyncStateError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    Stream,
    Future,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyState {
    Idle,
    Copying,
    Cancelling,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Seal {
    index: u32,
    generation: EndpointGeneration,
}

impl Seal {
    fn new(index: u32, generation: u32) -> Result<Self, AsyncStateError> {
        let generation =
            EndpointGeneration::new(generation).ok_or(AsyncStateError::GenerationExhausted)?;
        if index == 0 || index > CANONICAL_HANDLE_MAX {
            return Err(AsyncStateError::InvalidHandle);
        }
        Ok(Self { index, generation })
    }
}

/// A sealed resolution of one guest-visible raw handle.
///
/// The guest sees only [`Self::raw`]. Runtime code retains this seal across a
/// suspension so a recycled slot cannot be mistaken for the original end.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsyncHandle {
    state_id: NonZeroU64,
    seal: Seal,
}

impl AsyncHandle {
    pub const fn raw(self) -> u32 {
        self.seal.index
    }

    pub const fn generation(self) -> EndpointGeneration {
        self.seal.generation
    }
}

impl fmt::Debug for AsyncHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncHandle")
            .field("raw", &self.raw())
            .field("generation", &self.generation())
            .field("state", &"<sealed>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointPair {
    pub readable: AsyncHandle,
    pub writable: AsyncHandle,
}

/// One guest-readable endpoint and the exact host authority for its writer.
pub struct HostReadableBinding {
    pub guest: AsyncHandle,
    pub host: HostEndpointAuthority,
}

/// Fixed aggregate used to install a byte stream and close future atomically.
pub struct HostReadableBindingsPair {
    pub first: HostReadableBinding,
    pub second: HostReadableBinding,
    first_pair: Seal,
    second_pair: Seal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadableTransferRequest {
    pub handle: AsyncHandle,
    pub kind: EndpointKind,
    pub value_type: AsyncValueTypeId,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransferredReadableEndpoint {
    Stream(ReadableStreamEndpointToken),
    Future(ReadableFutureEndpointToken),
}

impl TransferredReadableEndpoint {
    pub const fn kind(&self) -> EndpointKind {
        match self {
            Self::Stream(_) => EndpointKind::Stream,
            Self::Future(_) => EndpointKind::Future,
        }
    }

    pub const fn value_type(&self) -> AsyncValueTypeId {
        match self {
            Self::Stream(token) => token.value_type(),
            Self::Future(token) => token.value_type(),
        }
    }

    pub fn into_canonical_value(self) -> CanonicalValue {
        match self {
            Self::Stream(token) => CanonicalValue::Stream(token),
            Self::Future(token) => CanonicalValue::Future(token),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointInfo {
    pub kind: EndpointKind,
    pub direction: EndpointDirection,
    pub value_type: AsyncValueTypeId,
    pub copy_state: CopyState,
    pub has_pending_event: bool,
    pub event_delivered: bool,
    pub joined_set: Option<u32>,
}

/// Opaque executor-owned buffer registration.
///
/// It contains no pointer and is intentionally neither `Clone` nor `Copy`.
/// The registry fields are exposed only inside the crate so the future
/// executor can resolve them after rechecking memory identity and range.
#[derive(Debug, PartialEq, Eq)]
pub struct BufferLease {
    registry: NonZeroU64,
    slot: NonZeroU32,
    generation: NonZeroU64,
    elements: u32,
}

// These authorities remain crate-private until the async executor owns the
// buffer registry in the next slice; exposing a public constructor would let
// an embedding forge a lease.
#[allow(dead_code)]
impl BufferLease {
    pub(crate) fn issue(
        registry: u64,
        slot: u32,
        generation: u64,
        elements: u32,
    ) -> Result<Self, AsyncStateError> {
        if elements >= (1_u32 << 28) {
            return Err(AsyncStateError::ProgressLimit);
        }
        Ok(Self {
            registry: NonZeroU64::new(registry).ok_or(AsyncStateError::StaleOperation)?,
            slot: NonZeroU32::new(slot).ok_or(AsyncStateError::StaleOperation)?,
            generation: NonZeroU64::new(generation).ok_or(AsyncStateError::StaleOperation)?,
            elements,
        })
    }

    pub const fn elements(&self) -> u32 {
        self.elements
    }

    pub(crate) const fn registry(&self) -> u64 {
        self.registry.get()
    }

    pub(crate) const fn slot(&self) -> u32 {
        self.slot.get()
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub code: EventCode,
    pub p1: u32,
    pub p2: u32,
}

#[derive(PartialEq, Eq)]
pub struct CopyOpToken {
    state_id: NonZeroU64,
    endpoint: Seal,
    pair: Seal,
    operation: NonZeroU64,
}

impl fmt::Debug for CopyOpToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CopyOpToken(<opaque>)")
    }
}

pub enum CopyBegin {
    Blocked { abi: u32, operation: CopyOpToken },
    Ready(EventToken),
    Local(LocalCopyTicket),
}

#[must_use = "the exact buffer lease must be recovered"]
pub struct BeginCopyFailure {
    error: AsyncStateError,
    lease: BufferLease,
}

impl BeginCopyFailure {
    pub const fn error(&self) -> AsyncStateError {
        self.error
    }

    pub fn into_parts(self) -> (AsyncStateError, BufferLease) {
        (self.error, self.lease)
    }
}

impl fmt::Debug for BeginCopyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BeginCopyFailure")
            .field("error", &self.error)
            .field("lease", &"<linear>")
            .finish()
    }
}

impl fmt::Debug for CopyBegin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked { abi, .. } => formatter
                .debug_struct("Blocked")
                .field("abi", abi)
                .finish_non_exhaustive(),
            Self::Ready(_) => formatter.write_str("Ready(<event>)"),
            Self::Local(_) => formatter.write_str("Local(<ticket>)"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct OpRef {
    endpoint: Seal,
    operation: NonZeroU64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PairPhase {
    Idle,
    Waiting(OpRef),
    Matching {
        nonce: NonZeroU64,
        read: OpRef,
        write: OpRef,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Holder {
    Guest(Seal),
    Host,
    Dropped,
}

struct SharedPair {
    kind: EndpointKind,
    value_type: AsyncValueTypeId,
    readable: Holder,
    writable: Holder,
    peer_dropped: bool,
    phase: PairPhase,
    next_match: u64,
    host_writable_done: bool,
}

struct ActiveCopy {
    operation: NonZeroU64,
    lease: BufferLease,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EventPhase {
    Pending,
    Delivered,
}

struct PendingEvent {
    operation: NonZeroU64,
    result: CopyResult,
    progress: u32,
    generation: NonZeroU64,
    phase: EventPhase,
}

struct Endpoint {
    pair: Seal,
    kind: EndpointKind,
    direction: EndpointDirection,
    value_type: AsyncValueTypeId,
    copy_state: CopyState,
    next_operation: u64,
    next_event: u64,
    active: Option<ActiveCopy>,
    event: Option<PendingEvent>,
    joined_set: Option<Seal>,
}

struct WaitableSet {
    members: Vec<Seal>,
    waiter: Option<WaitRegistration>,
    next_wait: u64,
}

enum HandleEntry {
    Endpoint(Endpoint),
    WaitableSet(WaitableSet),
}

impl HandleEntry {
    fn endpoint(&self) -> Result<&Endpoint, AsyncStateError> {
        match self {
            Self::Endpoint(endpoint) => Ok(endpoint),
            Self::WaitableSet(_) => Err(AsyncStateError::WrongHandleKind),
        }
    }

    fn endpoint_mut(&mut self) -> Result<&mut Endpoint, AsyncStateError> {
        match self {
            Self::Endpoint(endpoint) => Ok(endpoint),
            Self::WaitableSet(_) => Err(AsyncStateError::WrongHandleKind),
        }
    }

    fn waitable_set(&self) -> Result<&WaitableSet, AsyncStateError> {
        match self {
            Self::WaitableSet(set) => Ok(set),
            Self::Endpoint(_) => Err(AsyncStateError::WrongHandleKind),
        }
    }

    fn waitable_set_mut(&mut self) -> Result<&mut WaitableSet, AsyncStateError> {
        match self {
            Self::WaitableSet(set) => Ok(set),
            Self::Endpoint(_) => Err(AsyncStateError::WrongHandleKind),
        }
    }
}

impl From<Endpoint> for HandleEntry {
    fn from(endpoint: Endpoint) -> Self {
        Self::Endpoint(endpoint)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct WaitRegistration {
    task: Seal,
    epoch: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskResultState {
    Pending,
    Resolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCallbackState {
    Running,
    Exited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskCancelState {
    None,
    Requested,
    Delivered,
    Acknowledged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskInfo {
    pub result: TaskResultState,
    pub callback: TaskCallbackState,
    pub cancel: TaskCancelState,
    pub waiting: bool,
}

struct Task {
    result: TaskResultState,
    callback: TaskCallbackState,
    cancel: TaskCancelState,
    waiting: Option<(Seal, NonZeroU64)>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskHandle {
    state_id: NonZeroU64,
    seal: Seal,
}

impl fmt::Debug for TaskHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TaskHandle(<opaque>)")
    }
}

#[must_use = "a live wait registration must be resumed or cancelled"]
pub struct WaitTicket {
    state_id: NonZeroU64,
    task: Seal,
    set: Seal,
    epoch: NonZeroU64,
    active: bool,
}

impl fmt::Debug for WaitTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WaitTicket(<opaque>)")
    }
}

pub enum WaitBegin {
    Ready(EventLease),
    Blocked { ticket: WaitTicket },
}

pub enum WaitResume {
    Pending,
    Ready(EventLease),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventLeaseState {
    TaskCancelled,
    EndpointPending,
    EndpointDelivered,
    Consumed,
}

#[must_use = "an event lease must be consumed or retained for retry"]
pub struct EventLease {
    phase: EventLeasePhase,
}

enum EventLeasePhase {
    TaskCancelled(Event),
    EndpointPending(EventToken),
    EndpointDelivered { event: Event, reclaim: ReclaimToken },
    Consumed,
}

impl fmt::Debug for EventLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventLease")
            .field("state", &self.state())
            .finish()
    }
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
    retired: bool,
}

struct Table<T> {
    slots: Vec<Slot<T>>,
    live: u32,
    maximum: u32,
    full_error: AsyncStateError,
}

impl<T> Table<T> {
    fn new(maximum: u32, full_error: AsyncStateError) -> Result<Self, AsyncStateError> {
        if maximum == 0 || maximum > CANONICAL_HANDLE_MAX {
            return Err(AsyncStateError::InvalidLimits);
        }
        Ok(Self {
            slots: Vec::new(),
            live: 0,
            maximum,
            full_error,
        })
    }

    fn prepare_insert(&mut self, count: u32) -> Result<(), AsyncStateError> {
        let target = self.live.checked_add(count).ok_or(self.full_error)?;
        if target > self.maximum {
            return Err(self.full_error);
        }
        let reusable = self
            .slots
            .iter()
            .filter(|slot| slot.value.is_none() && !slot.retired)
            .count();
        let additional = usize::try_from(count)
            .map_err(|_| self.full_error)?
            .saturating_sub(reusable);
        if self.slots.len().saturating_add(additional)
            > usize::try_from(self.maximum).map_err(|_| self.full_error)?
        {
            return Err(self.full_error);
        }
        self.slots
            .try_reserve(additional)
            .map_err(|_| AsyncStateError::AllocationFailed)
    }

    fn insert_prepared(&mut self, value: T) -> Result<Seal, AsyncStateError> {
        if self.live >= self.maximum {
            return Err(self.full_error);
        }
        let slot = if let Some(slot) = self
            .slots
            .iter()
            .position(|slot| slot.value.is_none() && !slot.retired)
        {
            slot
        } else {
            if self.slots.len() >= self.slots.capacity() {
                return Err(AsyncStateError::PairInvariant);
            }
            self.slots.push(Slot {
                generation: 1,
                value: None,
                retired: false,
            });
            self.slots.len() - 1
        };
        let index = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(self.full_error)?;
        let seal = Seal::new(index, self.slots[slot].generation)?;
        self.slots[slot].value = Some(value);
        self.live = self.live.checked_add(1).ok_or(self.full_error)?;
        Ok(seal)
    }

    fn get(&self, seal: Seal) -> Result<&T, AsyncStateError> {
        let slot = self.slot(seal)?;
        slot.value.as_ref().ok_or(AsyncStateError::StaleHandle)
    }

    fn get_mut(&mut self, seal: Seal) -> Result<&mut T, AsyncStateError> {
        let slot = self.slot_mut(seal)?;
        slot.value.as_mut().ok_or(AsyncStateError::StaleHandle)
    }

    fn get_two_mut(
        &mut self,
        first: Seal,
        second: Seal,
    ) -> Result<(&mut T, &mut T), AsyncStateError> {
        let (first_slot, second_slot) = self.get_two_slots_mut(first, second)?;
        let first = first_slot
            .value
            .as_mut()
            .ok_or(AsyncStateError::StaleHandle)?;
        let second = second_slot
            .value
            .as_mut()
            .ok_or(AsyncStateError::StaleHandle)?;
        Ok((first, second))
    }

    fn seal_for_raw(&self, raw: u32) -> Result<Seal, AsyncStateError> {
        if raw == 0 {
            return Err(AsyncStateError::InvalidHandle);
        }
        let slot = usize::try_from(raw - 1).map_err(|_| AsyncStateError::InvalidHandle)?;
        let slot = self.slots.get(slot).ok_or(AsyncStateError::InvalidHandle)?;
        if slot.value.is_none() {
            return Err(AsyncStateError::StaleHandle);
        }
        Seal::new(raw, slot.generation)
    }

    fn remove(&mut self, seal: Seal) -> Result<T, AsyncStateError> {
        let slot = self.slot_mut(seal)?;
        let value = slot.value.take().ok_or(AsyncStateError::StaleHandle)?;
        retire_removed_slot(slot);
        self.live = self
            .live
            .checked_sub(1)
            .ok_or(AsyncStateError::PairInvariant)?;
        Ok(value)
    }

    /// Removes two distinct, already-live entries without exposing a partial
    /// commit. Both slots and the live count are checked before either value
    /// moves; the second `take` has an exact rollback for a corrupted table.
    fn remove_two(&mut self, first: Seal, second: Seal) -> Result<(T, T), AsyncStateError> {
        if self.live < 2 {
            return Err(AsyncStateError::PairInvariant);
        }
        let (first_slot, second_slot) = self.get_two_slots_mut(first, second)?;
        let first_value = first_slot
            .value
            .take()
            .ok_or(AsyncStateError::StaleHandle)?;
        let second_value = match second_slot.value.take() {
            Some(value) => value,
            None => {
                first_slot.value = Some(first_value);
                return Err(AsyncStateError::StaleHandle);
            }
        };
        retire_removed_slot(first_slot);
        retire_removed_slot(second_slot);
        self.live -= 2;
        Ok((first_value, second_value))
    }

    fn get_two_slots_mut(
        &mut self,
        first: Seal,
        second: Seal,
    ) -> Result<(&mut Slot<T>, &mut Slot<T>), AsyncStateError> {
        let first_index = usize::try_from(
            first
                .index
                .checked_sub(1)
                .ok_or(AsyncStateError::InvalidHandle)?,
        )
        .map_err(|_| AsyncStateError::InvalidHandle)?;
        let second_index = usize::try_from(
            second
                .index
                .checked_sub(1)
                .ok_or(AsyncStateError::InvalidHandle)?,
        )
        .map_err(|_| AsyncStateError::InvalidHandle)?;
        if first_index == second_index {
            return Err(AsyncStateError::PairInvariant);
        }

        let (first_slot, second_slot) = if first_index < second_index {
            let (lower, upper) = self.slots.split_at_mut(second_index);
            (
                lower
                    .get_mut(first_index)
                    .ok_or(AsyncStateError::InvalidHandle)?,
                upper.first_mut().ok_or(AsyncStateError::InvalidHandle)?,
            )
        } else {
            let (lower, upper) = self.slots.split_at_mut(first_index);
            (
                upper.first_mut().ok_or(AsyncStateError::InvalidHandle)?,
                lower
                    .get_mut(second_index)
                    .ok_or(AsyncStateError::InvalidHandle)?,
            )
        };
        validate_live_slot(first_slot, first)?;
        validate_live_slot(second_slot, second)?;
        Ok((first_slot, second_slot))
    }

    fn slot(&self, seal: Seal) -> Result<&Slot<T>, AsyncStateError> {
        let slot = usize::try_from(seal.index - 1)
            .ok()
            .and_then(|slot| self.slots.get(slot))
            .ok_or(AsyncStateError::InvalidHandle)?;
        if slot.generation != seal.generation.get() || slot.retired {
            return Err(AsyncStateError::StaleHandle);
        }
        Ok(slot)
    }

    fn slot_mut(&mut self, seal: Seal) -> Result<&mut Slot<T>, AsyncStateError> {
        let slot = usize::try_from(seal.index - 1)
            .ok()
            .and_then(|slot| self.slots.get_mut(slot))
            .ok_or(AsyncStateError::InvalidHandle)?;
        if slot.generation != seal.generation.get() || slot.retired {
            return Err(AsyncStateError::StaleHandle);
        }
        Ok(slot)
    }
}

fn validate_live_slot<T>(slot: &Slot<T>, seal: Seal) -> Result<(), AsyncStateError> {
    if slot.generation != seal.generation.get() || slot.retired || slot.value.is_none() {
        return Err(AsyncStateError::StaleHandle);
    }
    Ok(())
}

fn retire_removed_slot<T>(slot: &mut Slot<T>) {
    match slot.generation.checked_add(1) {
        Some(next) if next != 0 => slot.generation = next,
        _ => slot.retired = true,
    }
}

/// Persistent embedding authority for the host side of one exact pair.
///
/// It is non-cloneable. The readable form is created by lifting a guest end;
/// the writable form creates a host-backed component input.
#[derive(PartialEq, Eq)]
pub struct HostEndpointAuthority {
    state_id: NonZeroU64,
    pair: Seal,
    kind: EndpointKind,
    direction: EndpointDirection,
    value_type: AsyncValueTypeId,
    active: bool,
}

impl HostEndpointAuthority {
    pub const fn kind(&self) -> EndpointKind {
        self.kind
    }

    pub const fn direction(&self) -> EndpointDirection {
        self.direction
    }

    pub const fn value_type(&self) -> AsyncValueTypeId {
        self.value_type
    }
}

impl fmt::Debug for HostEndpointAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostEndpointAuthority(<opaque>)")
    }
}

pub struct LocalCopyTicket {
    state_id: NonZeroU64,
    pair: Seal,
    nonce: NonZeroU64,
    read: OpRef,
    write: OpRef,
    current: OpRef,
    committed: bool,
}

pub struct LocalCopyAbort {
    pub cancelled: EventToken,
    pub peer: CopyOpToken,
}

impl fmt::Debug for LocalCopyTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalCopyTicket(<opaque>)")
    }
}

pub struct HostCopyTicket {
    state_id: NonZeroU64,
    pair: Seal,
    operation: OpRef,
    authority_direction: EndpointDirection,
    committed: bool,
}

impl fmt::Debug for HostCopyTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostCopyTicket(<opaque>)")
    }
}

#[derive(PartialEq, Eq)]
pub struct EventToken {
    state_id: NonZeroU64,
    endpoint: Seal,
    operation: NonZeroU64,
    generation: NonZeroU64,
}

impl fmt::Debug for EventToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventToken(<opaque>)")
    }
}

pub struct ReclaimToken {
    state_id: NonZeroU64,
    endpoint: Seal,
    operation: NonZeroU64,
    generation: NonZeroU64,
    reclaimed: bool,
}

impl fmt::Debug for ReclaimToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReclaimToken(<opaque>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommitError<E> {
    State(AsyncStateError),
    Operation(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReclaimError<E> {
    State(AsyncStateError),
    Operation(E),
}

impl EventLease {
    fn task_cancelled(event: Event) -> Self {
        Self {
            phase: EventLeasePhase::TaskCancelled(event),
        }
    }

    fn endpoint_pending(event: EventToken) -> Self {
        Self {
            phase: EventLeasePhase::EndpointPending(event),
        }
    }

    pub const fn state(&self) -> EventLeaseState {
        match &self.phase {
            EventLeasePhase::TaskCancelled(_) => EventLeaseState::TaskCancelled,
            EventLeasePhase::EndpointPending(_) => EventLeaseState::EndpointPending,
            EventLeasePhase::EndpointDelivered { .. } => EventLeaseState::EndpointDelivered,
            EventLeasePhase::Consumed => EventLeaseState::Consumed,
        }
    }

    /// Consumes an exact task-cancellation event. Other lease phases are left
    /// unchanged so an endpoint lease can never be mistaken for cancellation.
    pub fn take_task_cancelled(&mut self) -> Option<Event> {
        let event = match &self.phase {
            EventLeasePhase::TaskCancelled(event) => Some(*event),
            _ => None,
        };
        if event.is_some() {
            self.phase = EventLeasePhase::Consumed;
        }
        event
    }

    /// Delivers the exact pending endpoint event and retains its reclaim
    /// authority inside this lease. A failed delivery leaves the original
    /// pending token available for an exact retry.
    pub fn prepare_endpoint(&mut self, state: &mut AsyncState) -> Result<(), AsyncStateError> {
        let (event, reclaim) = match &self.phase {
            EventLeasePhase::EndpointPending(token) => state.deliver_event(token)?,
            EventLeasePhase::Consumed => return Err(AsyncStateError::AuthorityConsumed),
            EventLeasePhase::TaskCancelled(_) | EventLeasePhase::EndpointDelivered { .. } => {
                return Err(AsyncStateError::StaleEvent);
            }
        };
        self.phase = EventLeasePhase::EndpointDelivered { event, reclaim };
        Ok(())
    }

    /// Reclaims the exact endpoint buffer before releasing its event. A
    /// reclaim failure keeps both the delivered event and the same retryable
    /// reclaim token in this lease.
    pub fn finish_endpoint<E>(
        &mut self,
        state: &mut AsyncState,
        reclaim_buffer: impl FnOnce(&BufferLease) -> Result<(), E>,
    ) -> Result<Event, ReclaimError<E>> {
        let event = match &mut self.phase {
            EventLeasePhase::EndpointDelivered { event, reclaim } => {
                state.reclaim_event(reclaim, reclaim_buffer)?;
                *event
            }
            EventLeasePhase::Consumed => {
                return Err(ReclaimError::State(AsyncStateError::AuthorityConsumed));
            }
            EventLeasePhase::TaskCancelled(_) | EventLeasePhase::EndpointPending(_) => {
                return Err(ReclaimError::State(AsyncStateError::StaleEvent));
            }
        };
        self.phase = EventLeasePhase::Consumed;
        Ok(event)
    }
}

pub struct AsyncState {
    id: NonZeroU64,
    handles: Table<HandleEntry>,
    pairs: Table<SharedPair>,
    tasks: Table<Task>,
    waitables_per_set: u32,
}

impl AsyncState {
    pub fn new(limits: AsyncStateLimits) -> Result<Self, AsyncStateError> {
        if limits.handles == 0
            || limits.pairs == 0
            || limits.tasks == 0
            || limits.waitables_per_set == 0
            || limits.handles > PROFILE_1_LIMITS.max_resources
            || limits.pairs > PROFILE_1_LIMITS.max_resources
            || limits.tasks > PROFILE_1_LIMITS.max_resources
            || limits.waitables_per_set > PROFILE_1_LIMITS.max_resources
            || limits.handles > CANONICAL_HANDLE_MAX
            || limits.pairs > CANONICAL_HANDLE_MAX
        {
            return Err(AsyncStateError::InvalidLimits);
        }
        let raw = NEXT_ASYNC_STATE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| AsyncStateError::GenerationExhausted)?;
        let id = NonZeroU64::new(raw).ok_or(AsyncStateError::GenerationExhausted)?;
        Ok(Self {
            id,
            handles: Table::new(limits.handles, AsyncStateError::HandleTableFull)?,
            pairs: Table::new(limits.pairs, AsyncStateError::PairTableFull)?,
            tasks: Table::new(limits.tasks, AsyncStateError::TaskTableFull)?,
            waitables_per_set: limits.waitables_per_set,
        })
    }

    pub fn resolve_guest_handle(&self, raw: u32) -> Result<AsyncHandle, AsyncStateError> {
        Ok(self.public_handle(self.handles.seal_for_raw(raw)?))
    }

    /// Resolves and exactly types one live guest endpoint without changing it.
    ///
    /// Native executors use this seal before charging for or registering a
    /// buffer, so malformed raw handles and endpoint-type mismatches cannot
    /// start a copy transition.
    pub(crate) fn resolve_guest_endpoint(
        &self,
        raw: u32,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<AsyncHandle, AsyncStateError> {
        let seal = self.handles.seal_for_raw(raw)?;
        validate_endpoint(self.endpoint_by_seal(seal)?, kind, direction, value_type)?;
        Ok(self.public_handle(seal))
    }

    /// Resolves a raw guest handle only when it names a live waitable set.
    /// Executors use this read-only seal before charging the `WAIT` state
    /// transition, so a wrong-kind handle cannot consume callback fuel.
    pub fn resolve_guest_waitable_set(&self, raw: u32) -> Result<AsyncHandle, AsyncStateError> {
        let seal = self.handles.seal_for_raw(raw)?;
        self.waitable_set_by_seal(seal)?;
        Ok(self.public_handle(seal))
    }

    pub fn endpoint_info(&self, handle: AsyncHandle) -> Result<EndpointInfo, AsyncStateError> {
        let endpoint = self.endpoint(handle)?;
        Ok(EndpointInfo {
            kind: endpoint.kind,
            direction: endpoint.direction,
            value_type: endpoint.value_type,
            copy_state: endpoint.copy_state,
            has_pending_event: endpoint.event.is_some(),
            event_delivered: endpoint
                .event
                .as_ref()
                .is_some_and(|event| event.phase == EventPhase::Delivered),
            joined_set: endpoint.joined_set.map(|set| set.index),
        })
    }

    pub fn create_waitable_set(&mut self) -> Result<AsyncHandle, AsyncStateError> {
        self.handles.prepare_insert(1)?;
        let set = self
            .handles
            .insert_prepared(HandleEntry::WaitableSet(WaitableSet {
                members: Vec::new(),
                waiter: None,
                next_wait: 1,
            }))?;
        Ok(self.public_handle(set))
    }

    /// Atomically moves an endpoint waitable to `set_raw`, or unjoins it when
    /// `set_raw == 0`. A pending event remains attached to the endpoint.
    pub fn join_waitable(
        &mut self,
        waitable: AsyncHandle,
        set_raw: u32,
    ) -> Result<(), AsyncStateError> {
        let endpoint_seal = self.handle_seal(waitable)?;
        let old_set = self.endpoint_by_seal(endpoint_seal)?.joined_set;
        let new_set = if set_raw == 0 {
            None
        } else {
            let seal = self.handles.seal_for_raw(set_raw)?;
            self.waitable_set_by_seal(seal)?;
            Some(seal)
        };
        if old_set == new_set {
            return Ok(());
        }
        let old_position = if let Some(old) = old_set {
            Some(
                self.waitable_set_by_seal(old)?
                    .members
                    .iter()
                    .position(|member| *member == endpoint_seal)
                    .ok_or(AsyncStateError::WaitableNotJoined)?,
            )
        } else {
            None
        };
        if let Some(new) = new_set {
            let maximum = usize::try_from(self.waitables_per_set)
                .map_err(|_| AsyncStateError::WaitableSetFull)?;
            let target = self.waitable_set_by_seal(new)?;
            if target.members.len() >= maximum {
                return Err(AsyncStateError::WaitableSetFull);
            }
            if target.members.contains(&endpoint_seal) {
                return Err(AsyncStateError::PairInvariant);
            }
            self.waitable_set_by_seal_mut(new)?
                .members
                .try_reserve(1)
                .map_err(|_| AsyncStateError::AllocationFailed)?;
        }
        if let (Some(old), Some(position)) = (old_set, old_position) {
            self.waitable_set_by_seal_mut(old)?.members.remove(position);
        }
        if let Some(new) = new_set {
            self.waitable_set_by_seal_mut(new)?
                .members
                .push(endpoint_seal);
        }
        self.endpoint_by_seal_mut(endpoint_seal)?.joined_set = new_set;
        Ok(())
    }

    pub fn drop_waitable_set(&mut self, set: AsyncHandle) -> Result<(), AsyncStateError> {
        let seal = self.handle_seal(set)?;
        let set = self.waitable_set_by_seal(seal)?;
        if !set.members.is_empty() {
            return Err(AsyncStateError::WaitableSetNotEmpty);
        }
        if set.waiter.is_some() {
            return Err(AsyncStateError::WaitableSetWaiting);
        }
        match self.handles.remove(seal)? {
            HandleEntry::WaitableSet(_) => Ok(()),
            HandleEntry::Endpoint(_) => Err(AsyncStateError::PairInvariant),
        }
    }

    pub fn create_stream_pair(
        &mut self,
        value_type: AsyncValueTypeId,
    ) -> Result<EndpointPair, AsyncStateError> {
        self.create_local_pair(EndpointKind::Stream, value_type)
    }

    pub fn create_future_pair(
        &mut self,
        value_type: AsyncValueTypeId,
    ) -> Result<EndpointPair, AsyncStateError> {
        self.create_local_pair(EndpointKind::Future, value_type)
    }

    fn create_local_pair(
        &mut self,
        kind: EndpointKind,
        value_type: AsyncValueTypeId,
    ) -> Result<EndpointPair, AsyncStateError> {
        self.pairs.prepare_insert(1)?;
        self.handles.prepare_insert(2)?;
        let pair = self.pairs.insert_prepared(SharedPair {
            kind,
            value_type,
            readable: Holder::Dropped,
            writable: Holder::Dropped,
            peer_dropped: false,
            phase: PairPhase::Idle,
            next_match: 1,
            host_writable_done: false,
        })?;
        let readable = match self.insert_endpoint(pair, kind, EndpointDirection::Read, value_type) {
            Ok(readable) => readable,
            Err(error) => {
                let _ = self.pairs.remove(pair);
                return Err(error);
            }
        };
        let writable = match self.insert_endpoint(pair, kind, EndpointDirection::Write, value_type)
        {
            Ok(writable) => writable,
            Err(error) => {
                let _ = self.handles.remove(readable);
                let _ = self.pairs.remove(pair);
                return Err(error);
            }
        };
        let shared = self.pairs.get_mut(pair)?;
        shared.readable = Holder::Guest(readable);
        shared.writable = Holder::Guest(writable);
        Ok(EndpointPair {
            readable: self.public_handle(readable),
            writable: self.public_handle(writable),
        })
    }

    /// Creates a guest-readable end backed by a reactive host writer.
    ///
    /// The host authority cannot park a buffer. It may only complete a guest
    /// operation returned by [`Self::begin_copy`].
    pub fn insert_host_readable(
        &mut self,
        kind: EndpointKind,
        value_type: AsyncValueTypeId,
    ) -> Result<(AsyncHandle, HostEndpointAuthority), AsyncStateError> {
        self.pairs.prepare_insert(1)?;
        self.handles.prepare_insert(1)?;
        self.insert_host_readable_prepared(kind, value_type)
    }

    /// Atomically creates two guest-readable ends backed by reactive host
    /// writers.
    ///
    /// This is the bounded input-side constructor used for a byte stream and
    /// its close-reason future. Both pair and handle tables reserve their full
    /// capacity before the first entry becomes live. A commit-time invariant
    /// failure while creating the second end precisely removes the first, so a
    /// caller never observes or loses logical capacity to a partial aggregate.
    pub fn insert_host_readables_pair(
        &mut self,
        first: (EndpointKind, AsyncValueTypeId),
        second: (EndpointKind, AsyncValueTypeId),
    ) -> Result<HostReadableBindingsPair, AsyncStateError> {
        self.pairs.prepare_insert(2)?;
        self.handles.prepare_insert(2)?;

        let first = self.insert_host_readable_prepared(first.0, first.1)?;
        match self.insert_host_readable_prepared(second.0, second.1) {
            Ok(second) => {
                let first_pair = first.1.pair;
                let second_pair = second.1.pair;
                Ok(HostReadableBindingsPair {
                    first: HostReadableBinding {
                        guest: first.0,
                        host: first.1,
                    },
                    second: HostReadableBinding {
                        guest: second.0,
                        host: second.1,
                    },
                    first_pair,
                    second_pair,
                })
            }
            Err(error) => {
                self.rollback_host_readable(first.0, &first.1)?;
                Err(error)
            }
        }
    }

    /// Discards an exact, still-unused pair returned by
    /// [`Self::insert_host_readables_pair`].
    ///
    /// Native instantiation uses this only when Core startup fails before the
    /// aggregate becomes guest-observable. Both origin seals, guest ends, host
    /// authorities, and idle pair states are validated before any table entry
    /// moves. Success consumes both host authorities and removes both pairs;
    /// every rejection leaves the complete aggregate unchanged.
    pub(crate) fn discard_host_readables_pair(
        &mut self,
        bindings: &mut HostReadableBindingsPair,
    ) -> Result<(), AsyncStateError> {
        let (first_handle, first_pair) =
            self.prepare_host_readable_discard(&bindings.first, bindings.first_pair)?;
        let (second_handle, second_pair) =
            self.prepare_host_readable_discard(&bindings.second, bindings.second_pair)?;
        if first_handle == second_handle || first_pair == second_pair {
            return Err(AsyncStateError::PairInvariant);
        }
        if self.handles.live < 2 || self.pairs.live < 2 {
            return Err(AsyncStateError::PairInvariant);
        }

        let ((first_entry, second_entry), (first_shared, second_shared)) = {
            let (first_handle_slot, second_handle_slot) = self
                .handles
                .get_two_slots_mut(first_handle, second_handle)?;
            let (first_pair_slot, second_pair_slot) =
                self.pairs.get_two_slots_mut(first_pair, second_pair)?;

            let first_entry = first_handle_slot
                .value
                .take()
                .ok_or(AsyncStateError::PairInvariant)?;
            let second_entry = match second_handle_slot.value.take() {
                Some(entry) => entry,
                None => {
                    first_handle_slot.value = Some(first_entry);
                    return Err(AsyncStateError::PairInvariant);
                }
            };
            let first_shared = match first_pair_slot.value.take() {
                Some(shared) => shared,
                None => {
                    first_handle_slot.value = Some(first_entry);
                    second_handle_slot.value = Some(second_entry);
                    return Err(AsyncStateError::PairInvariant);
                }
            };
            let second_shared = match second_pair_slot.value.take() {
                Some(shared) => shared,
                None => {
                    first_pair_slot.value = Some(first_shared);
                    first_handle_slot.value = Some(first_entry);
                    second_handle_slot.value = Some(second_entry);
                    return Err(AsyncStateError::PairInvariant);
                }
            };

            // All four values are now owned by this transaction. Advancing
            // generations and live counts is infallible because both tables'
            // exact slots and minimum live counts were prevalidated.
            retire_removed_slot(first_handle_slot);
            retire_removed_slot(second_handle_slot);
            retire_removed_slot(first_pair_slot);
            retire_removed_slot(second_pair_slot);
            ((first_entry, second_entry), (first_shared, second_shared))
        };
        self.handles.live -= 2;
        self.pairs.live -= 2;

        debug_assert!(matches!(first_entry, HandleEntry::Endpoint(_)));
        debug_assert!(matches!(second_entry, HandleEntry::Endpoint(_)));
        debug_assert!(first_shared.readable == Holder::Guest(first_handle));
        debug_assert!(second_shared.readable == Holder::Guest(second_handle));
        bindings.first.host.active = false;
        bindings.second.host.active = false;
        Ok(())
    }

    fn prepare_host_readable_discard(
        &self,
        binding: &HostReadableBinding,
        expected_pair: Seal,
    ) -> Result<(Seal, Seal), AsyncStateError> {
        let authority = &binding.host;
        if authority.state_id != self.id {
            return Err(AsyncStateError::WrongState);
        }
        if !authority.active {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        if authority.pair != expected_pair || authority.direction != EndpointDirection::Write {
            return Err(AsyncStateError::PairInvariant);
        }

        let handle = self.handle_seal(binding.guest)?;
        let endpoint = self.endpoint_by_seal(handle)?;
        validate_endpoint(
            endpoint,
            authority.kind,
            EndpointDirection::Read,
            authority.value_type,
        )?;
        if endpoint.pair != expected_pair {
            return Err(AsyncStateError::PairInvariant);
        }
        if endpoint.copy_state != CopyState::Idle
            || endpoint.active.is_some()
            || endpoint.event.is_some()
        {
            return Err(AsyncStateError::EndpointBusy);
        }
        if endpoint.joined_set.is_some() {
            return Err(AsyncStateError::TransferWhileJoined);
        }

        let shared = self.pairs.get(expected_pair)?;
        if shared.kind != authority.kind
            || shared.value_type != authority.value_type
            || shared.readable != Holder::Guest(handle)
            || shared.writable != Holder::Host
            || shared.peer_dropped
        {
            return Err(AsyncStateError::PairInvariant);
        }
        if shared.phase != PairPhase::Idle || shared.host_writable_done {
            return Err(AsyncStateError::EndpointBusy);
        }
        Ok((handle, expected_pair))
    }

    fn insert_host_readable_prepared(
        &mut self,
        kind: EndpointKind,
        value_type: AsyncValueTypeId,
    ) -> Result<(AsyncHandle, HostEndpointAuthority), AsyncStateError> {
        let pair = self.pairs.insert_prepared(SharedPair {
            kind,
            value_type,
            readable: Holder::Dropped,
            writable: Holder::Host,
            peer_dropped: false,
            phase: PairPhase::Idle,
            next_match: 1,
            host_writable_done: false,
        })?;
        let readable = match self.insert_endpoint(pair, kind, EndpointDirection::Read, value_type) {
            Ok(readable) => readable,
            Err(error) => {
                return match self.pairs.remove(pair) {
                    Ok(_) => Err(error),
                    Err(_) => Err(AsyncStateError::PairInvariant),
                };
            }
        };
        if let Err(error) = self
            .pairs
            .get_mut(pair)
            .map(|shared| shared.readable = Holder::Guest(readable))
        {
            let handle_removed =
                matches!(self.handles.remove(readable), Ok(HandleEntry::Endpoint(_)));
            let pair_removed = self.pairs.remove(pair).is_ok();
            return if handle_removed && pair_removed {
                Err(error)
            } else {
                Err(AsyncStateError::PairInvariant)
            };
        }
        Ok((
            self.public_handle(readable),
            HostEndpointAuthority {
                state_id: self.id,
                pair,
                kind,
                direction: EndpointDirection::Write,
                value_type,
                active: true,
            },
        ))
    }

    fn rollback_host_readable(
        &mut self,
        readable: AsyncHandle,
        authority: &HostEndpointAuthority,
    ) -> Result<(), AsyncStateError> {
        if readable.state_id != self.id
            || authority.state_id != self.id
            || authority.direction != EndpointDirection::Write
            || !authority.active
        {
            return Err(AsyncStateError::PairInvariant);
        }
        let endpoint = self.endpoint_by_seal(readable.seal)?;
        let shared = self.pairs.get(authority.pair)?;
        if endpoint.pair != authority.pair
            || endpoint.kind != authority.kind
            || endpoint.kind != shared.kind
            || endpoint.direction != EndpointDirection::Read
            || endpoint.value_type != authority.value_type
            || endpoint.value_type != shared.value_type
            || shared.readable != Holder::Guest(readable.seal)
            || shared.writable != Holder::Host
            || shared.phase != PairPhase::Idle
        {
            return Err(AsyncStateError::PairInvariant);
        }
        match self.handles.remove(readable.seal)? {
            HandleEntry::Endpoint(_) => {}
            HandleEntry::WaitableSet(_) => return Err(AsyncStateError::PairInvariant),
        }
        self.pairs.remove(authority.pair)?;
        Ok(())
    }

    fn insert_endpoint(
        &mut self,
        pair: Seal,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<Seal, AsyncStateError> {
        self.handles.insert_prepared(
            Endpoint {
                pair,
                kind,
                direction,
                value_type,
                copy_state: CopyState::Idle,
                next_operation: 1,
                next_event: 1,
                active: None,
                event: None,
                joined_set: None,
            }
            .into(),
        )
    }

    /// Checks the complete state-side preparation for [`Self::begin_copy`]
    /// without consuming a buffer lease or changing endpoint state.
    ///
    /// Executors use this before registering guest memory or charging work.
    /// `begin_copy` repeats the same sealed preparation immediately before its
    /// commit, so this is an early rejection boundary rather than authority to
    /// skip the transition's exact revalidation.
    pub(crate) fn preflight_begin_copy(
        &self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        elements: u32,
    ) -> Result<(), AsyncStateError> {
        self.prepare_begin_copy(handle, kind, direction, value_type, elements)
            .map(|_| ())
    }

    fn prepare_begin_copy(
        &self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        elements: u32,
    ) -> Result<PreparedBeginCopy, AsyncStateError> {
        let endpoint_seal = self.handle_seal(handle)?;
        let (pair_seal, operation, next_operation) = {
            let endpoint = self.endpoint_by_seal(endpoint_seal)?;
            validate_endpoint(endpoint, kind, direction, value_type)?;
            if endpoint.copy_state == CopyState::Done {
                return Err(AsyncStateError::EndpointDone);
            }
            if endpoint.copy_state != CopyState::Idle
                || endpoint.active.is_some()
                || endpoint.event.is_some()
            {
                return Err(AsyncStateError::EndpointBusy);
            }
            if kind == EndpointKind::Future && elements != 1 {
                return Err(AsyncStateError::ProgressLimit);
            }
            let operation = NonZeroU64::new(endpoint.next_operation)
                .ok_or(AsyncStateError::GenerationExhausted)?;
            let next_operation = endpoint
                .next_operation
                .checked_add(1)
                .ok_or(AsyncStateError::GenerationExhausted)?;
            (endpoint.pair, operation, next_operation)
        };
        let original_phase = self.pairs.get(pair_seal)?.phase;
        let action = self.plan_begin(pair_seal, endpoint_seal, direction, elements)?;
        match action {
            BeginAction::Dropped => self.preflight_new_event(
                endpoint_seal,
                kind,
                direction,
                CopyResult::Dropped,
                0,
                elements,
            )?,
            BeginAction::CompleteCurrentKeepPeer => self.preflight_new_event(
                endpoint_seal,
                kind,
                direction,
                CopyResult::Completed,
                0,
                elements,
            )?,
            BeginAction::CompletePeerWaitCurrent(peer) => {
                self.prepare_event(peer, CopyResult::Completed, 0)?
            }
            BeginAction::Match(_) => {
                let shared = self.pairs.get(pair_seal)?;
                if shared.next_match == 0 || shared.next_match == u64::MAX {
                    return Err(AsyncStateError::GenerationExhausted);
                }
            }
            BeginAction::Wait => {}
        }
        Ok(PreparedBeginCopy {
            endpoint: endpoint_seal,
            pair: pair_seal,
            operation,
            next_operation,
            action,
            original_phase,
        })
    }

    pub fn begin_copy(
        &mut self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        lease: BufferLease,
    ) -> Result<CopyBegin, BeginCopyFailure> {
        let prepared =
            match self.prepare_begin_copy(handle, kind, direction, value_type, lease.elements) {
                Ok(prepared) => prepared,
                Err(error) => return Err(BeginCopyFailure { error, lease }),
            };
        let PreparedBeginCopy {
            endpoint: endpoint_seal,
            pair: pair_seal,
            operation,
            next_operation,
            action,
            original_phase,
        } = prepared;
        let current = OpRef {
            endpoint: endpoint_seal,
            operation,
        };

        match action {
            BeginAction::Dropped => {
                let endpoint = match self.endpoint_by_seal_mut(endpoint_seal) {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let generation = match NonZeroU64::new(endpoint.next_event) {
                    Some(generation) => generation,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                let next_event = match endpoint.next_event.checked_add(1) {
                    Some(next_event) => next_event,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                endpoint.next_operation = next_operation;
                endpoint.copy_state = CopyState::Copying;
                endpoint.active = Some(ActiveCopy { operation, lease });
                endpoint.next_event = next_event;
                endpoint.event = Some(PendingEvent {
                    operation,
                    result: CopyResult::Dropped,
                    progress: 0,
                    generation,
                    phase: EventPhase::Pending,
                });
                Ok(CopyBegin::Ready(EventToken {
                    state_id: self.id,
                    endpoint: endpoint_seal,
                    operation,
                    generation,
                }))
            }
            BeginAction::Wait => {
                let shared = match self.pairs.get_mut(pair_seal) {
                    Ok(shared) => shared,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                if shared.phase != original_phase {
                    return Err(BeginCopyFailure {
                        error: AsyncStateError::PairInvariant,
                        lease,
                    });
                }
                let entry = match self.handles.get_mut(endpoint_seal) {
                    Ok(entry) => entry,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let endpoint = match entry.endpoint_mut() {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                endpoint.next_operation = next_operation;
                endpoint.copy_state = CopyState::Copying;
                endpoint.active = Some(ActiveCopy { operation, lease });
                shared.phase = PairPhase::Waiting(current);
                Ok(CopyBegin::Blocked {
                    abi: BLOCKED,
                    operation: self.operation_token(pair_seal, current),
                })
            }
            BeginAction::CompleteCurrentKeepPeer => {
                let endpoint = match self.endpoint_by_seal_mut(endpoint_seal) {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let generation = match NonZeroU64::new(endpoint.next_event) {
                    Some(generation) => generation,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                let next_event = match endpoint.next_event.checked_add(1) {
                    Some(next_event) => next_event,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                endpoint.next_operation = next_operation;
                endpoint.copy_state = CopyState::Copying;
                endpoint.active = Some(ActiveCopy { operation, lease });
                endpoint.next_event = next_event;
                endpoint.event = Some(PendingEvent {
                    operation,
                    result: CopyResult::Completed,
                    progress: 0,
                    generation,
                    phase: EventPhase::Pending,
                });
                Ok(CopyBegin::Ready(EventToken {
                    state_id: self.id,
                    endpoint: endpoint_seal,
                    operation,
                    generation,
                }))
            }
            BeginAction::CompletePeerWaitCurrent(peer) => {
                let shared = match self.pairs.get_mut(pair_seal) {
                    Ok(shared) => shared,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                if shared.phase != original_phase {
                    return Err(BeginCopyFailure {
                        error: AsyncStateError::PairInvariant,
                        lease,
                    });
                }
                let (current_entry, peer_entry) =
                    match self.handles.get_two_mut(endpoint_seal, peer.endpoint) {
                        Ok(entries) => entries,
                        Err(error) => return Err(BeginCopyFailure { error, lease }),
                    };
                let current_endpoint = match current_entry.endpoint_mut() {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let peer_endpoint = match peer_entry.endpoint_mut() {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let generation = match NonZeroU64::new(peer_endpoint.next_event) {
                    Some(generation) => generation,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                let next_event = match peer_endpoint.next_event.checked_add(1) {
                    Some(next_event) => next_event,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                current_endpoint.next_operation = next_operation;
                current_endpoint.copy_state = CopyState::Copying;
                current_endpoint.active = Some(ActiveCopy { operation, lease });
                peer_endpoint.next_event = next_event;
                peer_endpoint.event = Some(PendingEvent {
                    operation: peer.operation,
                    result: CopyResult::Completed,
                    progress: 0,
                    generation,
                    phase: EventPhase::Pending,
                });
                shared.phase = PairPhase::Waiting(current);
                Ok(CopyBegin::Blocked {
                    abi: BLOCKED,
                    operation: self.operation_token(pair_seal, current),
                })
            }
            BeginAction::Match(peer) => {
                let (read, write) = match direction {
                    EndpointDirection::Read => (current, peer),
                    EndpointDirection::Write => (peer, current),
                };
                let shared = match self.pairs.get_mut(pair_seal) {
                    Ok(shared) => shared,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                if shared.phase != original_phase {
                    return Err(BeginCopyFailure {
                        error: AsyncStateError::PairInvariant,
                        lease,
                    });
                }
                let nonce = match NonZeroU64::new(shared.next_match) {
                    Some(nonce) => nonce,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                let next_match = match shared.next_match.checked_add(1) {
                    Some(next_match) => next_match,
                    None => {
                        return Err(BeginCopyFailure {
                            error: AsyncStateError::GenerationExhausted,
                            lease,
                        })
                    }
                };
                let entry = match self.handles.get_mut(endpoint_seal) {
                    Ok(entry) => entry,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                let endpoint = match entry.endpoint_mut() {
                    Ok(endpoint) => endpoint,
                    Err(error) => return Err(BeginCopyFailure { error, lease }),
                };
                endpoint.next_operation = next_operation;
                endpoint.copy_state = CopyState::Copying;
                endpoint.active = Some(ActiveCopy { operation, lease });
                shared.next_match = next_match;
                shared.phase = PairPhase::Matching { nonce, read, write };
                Ok(CopyBegin::Local(LocalCopyTicket {
                    state_id: self.id,
                    pair: pair_seal,
                    nonce,
                    read,
                    write,
                    current,
                    committed: false,
                }))
            }
        }
    }

    fn plan_begin(
        &self,
        pair: Seal,
        current: Seal,
        direction: EndpointDirection,
        elements: u32,
    ) -> Result<BeginAction, AsyncStateError> {
        let shared = self.pairs.get(pair)?;
        let expected_holder = match direction {
            EndpointDirection::Read => shared.readable,
            EndpointDirection::Write => shared.writable,
        };
        if expected_holder != Holder::Guest(current) {
            return Err(AsyncStateError::PairInvariant);
        }
        if shared.peer_dropped {
            return Ok(BeginAction::Dropped);
        }
        match shared.phase {
            PairPhase::Idle => Ok(BeginAction::Wait),
            PairPhase::Matching { .. } => Err(AsyncStateError::PairBusy),
            PairPhase::Waiting(peer) => {
                let peer_endpoint = self.endpoint_by_seal(peer.endpoint)?;
                let peer_active = peer_endpoint
                    .active
                    .as_ref()
                    .filter(|active| active.operation == peer.operation)
                    .ok_or(AsyncStateError::PairInvariant)?;
                if peer_endpoint.pair != pair || peer_endpoint.direction == direction {
                    return Err(AsyncStateError::PairInvariant);
                }
                if shared.kind == EndpointKind::Future {
                    if elements != 1 || peer_active.lease.elements != 1 {
                        return Err(AsyncStateError::ProgressLimit);
                    }
                    return Ok(BeginAction::Match(peer));
                }
                let peer_elements = peer_active.lease.elements;
                Ok(match direction {
                    EndpointDirection::Read => {
                        if peer_elements > 0 && elements > 0 {
                            BeginAction::Match(peer)
                        } else if peer_elements > 0 {
                            BeginAction::CompleteCurrentKeepPeer
                        } else {
                            BeginAction::CompletePeerWaitCurrent(peer)
                        }
                    }
                    EndpointDirection::Write => {
                        if peer_elements > 0 && elements > 0 {
                            BeginAction::Match(peer)
                        } else if elements == 0 {
                            BeginAction::CompleteCurrentKeepPeer
                        } else {
                            BeginAction::CompletePeerWaitCurrent(peer)
                        }
                    }
                })
            }
        }
    }

    fn operation_token(&self, pair: Seal, operation: OpRef) -> CopyOpToken {
        CopyOpToken {
            state_id: self.id,
            endpoint: operation.endpoint,
            pair,
            operation: operation.operation,
        }
    }

    fn public_handle(&self, seal: Seal) -> AsyncHandle {
        AsyncHandle {
            state_id: self.id,
            seal,
        }
    }

    fn handle_seal(&self, handle: AsyncHandle) -> Result<Seal, AsyncStateError> {
        if handle.state_id != self.id {
            return Err(AsyncStateError::WrongState);
        }
        self.handles.get(handle.seal)?;
        Ok(handle.seal)
    }

    fn endpoint(&self, handle: AsyncHandle) -> Result<&Endpoint, AsyncStateError> {
        self.endpoint_by_seal(self.handle_seal(handle)?)
    }

    fn endpoint_by_seal(&self, seal: Seal) -> Result<&Endpoint, AsyncStateError> {
        self.handles.get(seal)?.endpoint()
    }

    fn endpoint_by_seal_mut(&mut self, seal: Seal) -> Result<&mut Endpoint, AsyncStateError> {
        self.handles.get_mut(seal)?.endpoint_mut()
    }

    fn waitable_set_by_seal(&self, seal: Seal) -> Result<&WaitableSet, AsyncStateError> {
        self.handles.get(seal)?.waitable_set()
    }

    fn waitable_set_by_seal_mut(
        &mut self,
        seal: Seal,
    ) -> Result<&mut WaitableSet, AsyncStateError> {
        self.handles.get_mut(seal)?.waitable_set_mut()
    }
}

impl AsyncState {
    /// Revalidates a local rendezvous ticket and returns its exact progress.
    ///
    /// The returned minimum is sealed by the pair nonce, both operations, the
    /// endpoint metadata, and the two still-owned leases. The executor can use
    /// it to charge and bounds-check a copy before mutating guest memory.
    pub(crate) fn local_copy_progress(
        &self,
        ticket: &LocalCopyTicket,
    ) -> Result<u32, AsyncStateError> {
        if ticket.state_id != self.id || ticket.committed {
            return Err(AsyncStateError::StaleOperation);
        }
        if ticket.current != ticket.read && ticket.current != ticket.write {
            return Err(AsyncStateError::PairInvariant);
        }

        let shared = self.pairs.get(ticket.pair)?;
        if shared.phase
            != (PairPhase::Matching {
                nonce: ticket.nonce,
                read: ticket.read,
                write: ticket.write,
            })
        {
            return Err(AsyncStateError::StaleOperation);
        }
        if shared.peer_dropped
            || shared.readable != Holder::Guest(ticket.read.endpoint)
            || shared.writable != Holder::Guest(ticket.write.endpoint)
        {
            return Err(AsyncStateError::PairInvariant);
        }

        let read_endpoint = self.endpoint_by_seal(ticket.read.endpoint)?;
        let write_endpoint = self.endpoint_by_seal(ticket.write.endpoint)?;
        if ticket.read.endpoint == ticket.write.endpoint
            || read_endpoint.pair != ticket.pair
            || write_endpoint.pair != ticket.pair
            || read_endpoint.kind != shared.kind
            || write_endpoint.kind != shared.kind
            || read_endpoint.direction != EndpointDirection::Read
            || write_endpoint.direction != EndpointDirection::Write
            || read_endpoint.value_type != shared.value_type
            || write_endpoint.value_type != shared.value_type
            || read_endpoint.copy_state != CopyState::Copying
            || write_endpoint.copy_state != CopyState::Copying
            || read_endpoint.event.is_some()
            || write_endpoint.event.is_some()
        {
            return Err(AsyncStateError::PairInvariant);
        }

        let read = self.active_for(ticket.read)?;
        let write = self.active_for(ticket.write)?;
        let progress = read.lease.elements.min(write.lease.elements);
        match shared.kind {
            EndpointKind::Stream => {
                if progress == 0
                    || read.lease.elements >= (1_u32 << 28)
                    || write.lease.elements >= (1_u32 << 28)
                {
                    return Err(AsyncStateError::ProgressLimit);
                }
            }
            EndpointKind::Future => {
                if read.lease.elements != 1 || write.lease.elements != 1 {
                    return Err(AsyncStateError::ProgressLimit);
                }
            }
        }
        Ok(progress)
    }

    pub fn commit_local_copy<E>(
        &mut self,
        ticket: &mut LocalCopyTicket,
        progress: u32,
        copy: impl FnOnce(&BufferLease, &BufferLease, u32) -> Result<(), E>,
    ) -> Result<EventToken, CommitError<E>> {
        let exact_progress = self
            .local_copy_progress(ticket)
            .map_err(CommitError::State)?;
        if progress != exact_progress {
            return Err(CommitError::State(AsyncStateError::ProgressLimit));
        }
        let event_progress = match self
            .pairs
            .get(ticket.pair)
            .map_err(CommitError::State)?
            .kind
        {
            EndpointKind::Stream => progress,
            EndpointKind::Future => 0,
        };
        self.prepare_event(ticket.read, CopyResult::Completed, event_progress)
            .map_err(CommitError::State)?;
        self.prepare_event(ticket.write, CopyResult::Completed, event_progress)
            .map_err(CommitError::State)?;
        {
            let read = self.active_for(ticket.read).map_err(CommitError::State)?;
            let write = self.active_for(ticket.write).map_err(CommitError::State)?;
            copy(&write.lease, &read.lease, progress).map_err(CommitError::Operation)?;
        }
        self.queue_event(ticket.read, CopyResult::Completed, event_progress)
            .map_err(CommitError::State)?;
        self.queue_event(ticket.write, CopyResult::Completed, event_progress)
            .map_err(CommitError::State)?;
        self.pairs
            .get_mut(ticket.pair)
            .map_err(CommitError::State)?
            .phase = PairPhase::Idle;
        ticket.committed = true;
        self.event_token(ticket.current).map_err(CommitError::State)
    }

    /// Cancels the operation which triggered a local match and restores the
    /// earlier peer as the exact pending operation. Executors use this during
    /// checked-copy failure or task teardown; dropping a ticket is never the
    /// recovery protocol.
    pub fn abort_local_copy(
        &mut self,
        ticket: &mut LocalCopyTicket,
    ) -> Result<LocalCopyAbort, AsyncStateError> {
        self.validate_local_ticket(ticket)?;
        let peer = if ticket.current == ticket.read {
            ticket.write
        } else if ticket.current == ticket.write {
            ticket.read
        } else {
            return Err(AsyncStateError::PairInvariant);
        };
        self.prepare_event(ticket.current, CopyResult::Cancelled, 0)?;
        self.queue_event(ticket.current, CopyResult::Cancelled, 0)?;
        self.pairs.get_mut(ticket.pair)?.phase = PairPhase::Waiting(peer);
        ticket.committed = true;
        Ok(LocalCopyAbort {
            cancelled: self.event_token(ticket.current)?,
            peer: self.operation_token(ticket.pair, peer),
        })
    }

    fn validate_local_ticket(&self, ticket: &LocalCopyTicket) -> Result<(), AsyncStateError> {
        self.local_copy_progress(ticket).map(|_| ())
    }

    /// Resolves an exact guest operation for a reactive host authority.
    /// Calling this before the guest has parked an operation fails without
    /// changing either side.
    pub fn prepare_host_copy(
        &self,
        authority: &HostEndpointAuthority,
        operation: &CopyOpToken,
    ) -> Result<HostCopyTicket, AsyncStateError> {
        self.validate_authority(authority)?;
        if operation.state_id != self.id || operation.pair != authority.pair {
            return Err(AsyncStateError::StaleOperation);
        }
        let shared = self.pairs.get(authority.pair)?;
        let expected_holder = match authority.direction {
            EndpointDirection::Read => shared.readable,
            EndpointDirection::Write => shared.writable,
        };
        if expected_holder != Holder::Host {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        let op = OpRef {
            endpoint: operation.endpoint,
            operation: operation.operation,
        };
        if shared.phase != PairPhase::Waiting(op) {
            return Err(AsyncStateError::StaleOperation);
        }
        let endpoint = self.endpoint_by_seal(op.endpoint)?;
        if endpoint.pair != authority.pair
            || endpoint.kind != authority.kind
            || endpoint.value_type != authority.value_type
            || endpoint.direction == authority.direction
        {
            return Err(AsyncStateError::PairInvariant);
        }
        self.active_for(op)?;
        Ok(HostCopyTicket {
            state_id: self.id,
            pair: authority.pair,
            operation: op,
            authority_direction: authority.direction,
            committed: false,
        })
    }

    /// Returns the exact active buffer's maximum host completion progress.
    ///
    /// The ticket is fully revalidated on every call. Only the scalar element
    /// count crosses this boundary; the linear buffer lease and its registry
    /// identity remain owned by the async state.
    pub fn host_copy_progress_limit(
        &self,
        ticket: &HostCopyTicket,
    ) -> Result<u32, AsyncStateError> {
        self.validate_host_ticket(ticket)?;
        Ok(self.active_for(ticket.operation)?.lease.elements())
    }

    pub fn commit_host_copy<E>(
        &mut self,
        ticket: &mut HostCopyTicket,
        result: CopyResult,
        progress: u32,
        copy: impl FnOnce(&BufferLease, u32) -> Result<(), E>,
    ) -> Result<EventToken, CommitError<E>> {
        self.validate_host_ticket(ticket)
            .map_err(CommitError::State)?;
        if result != CopyResult::Completed {
            return Err(CommitError::State(AsyncStateError::InvalidCopyResult));
        }
        let (kind, direction, elements) = {
            let endpoint = self
                .endpoint_by_seal(ticket.operation.endpoint)
                .map_err(CommitError::State)?;
            let active = endpoint
                .active
                .as_ref()
                .filter(|active| active.operation == ticket.operation.operation)
                .ok_or(CommitError::State(AsyncStateError::StaleOperation))?;
            (endpoint.kind, endpoint.direction, active.lease.elements)
        };
        let event_progress = validate_host_result(kind, direction, result, progress, elements)
            .map_err(CommitError::State)?;
        self.prepare_event(ticket.operation, result, event_progress)
            .map_err(CommitError::State)?;
        if result == CopyResult::Completed {
            let active = self
                .active_for(ticket.operation)
                .map_err(CommitError::State)?;
            copy(&active.lease, progress).map_err(CommitError::Operation)?;
        }
        self.queue_event(ticket.operation, result, event_progress)
            .map_err(CommitError::State)?;
        {
            let shared = self
                .pairs
                .get_mut(ticket.pair)
                .map_err(CommitError::State)?;
            shared.phase = PairPhase::Idle;
            if shared.kind == EndpointKind::Future
                && ticket.authority_direction == EndpointDirection::Write
            {
                shared.host_writable_done = true;
            }
        }
        ticket.committed = true;
        self.event_token(ticket.operation)
            .map_err(CommitError::State)
    }

    fn validate_host_ticket(&self, ticket: &HostCopyTicket) -> Result<(), AsyncStateError> {
        if ticket.state_id != self.id || ticket.committed {
            return Err(AsyncStateError::StaleOperation);
        }
        let shared = self.pairs.get(ticket.pair)?;
        if shared.phase != PairPhase::Waiting(ticket.operation) {
            return Err(AsyncStateError::StaleOperation);
        }
        let host_holder = match ticket.authority_direction {
            EndpointDirection::Read => shared.readable,
            EndpointDirection::Write => shared.writable,
        };
        if host_holder != Holder::Host {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        self.active_for(ticket.operation)?;
        Ok(())
    }

    /// Checks the complete state-side preparation for [`Self::cancel_copy`]
    /// without changing the operation, pair, or pending event.
    pub(crate) fn preflight_cancel_copy(
        &self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<(), AsyncStateError> {
        self.prepare_cancel_copy(handle, kind, direction, value_type)
            .map(|_| ())
    }

    fn prepare_cancel_copy(
        &self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<PreparedCancelCopy, AsyncStateError> {
        let seal = self.handle_seal(handle)?;
        let (pair, operation, existing_event) = {
            let endpoint = self.endpoint_by_seal(seal)?;
            validate_endpoint(endpoint, kind, direction, value_type)?;
            if !matches!(
                endpoint.copy_state,
                CopyState::Copying | CopyState::Cancelling
            ) {
                return Err(AsyncStateError::OperationNotCopying);
            }
            let active = endpoint
                .active
                .as_ref()
                .ok_or(AsyncStateError::OperationNotCopying)?;
            if endpoint.joined_set.is_some() {
                return Err(AsyncStateError::CancelWhileJoined);
            }
            (
                endpoint.pair,
                OpRef {
                    endpoint: seal,
                    operation: active.operation,
                },
                endpoint.event.is_some(),
            )
        };
        if existing_event {
            let endpoint = self.endpoint_by_seal(seal)?;
            if endpoint
                .event
                .as_ref()
                .is_some_and(|event| event.phase == EventPhase::Delivered)
            {
                return Err(AsyncStateError::EventAlreadyDelivered);
            }
            let event = self.event_token(operation)?;
            return Ok(PreparedCancelCopy {
                endpoint: seal,
                operation,
                action: CancelAction::Existing(event),
            });
        }

        let original_phase = self.pairs.get(pair)?.phase;
        let next_phase = match original_phase {
            PairPhase::Waiting(pending) if pending == operation => PairPhase::Idle,
            PairPhase::Matching { read, write, .. } => {
                let peer = if operation == read {
                    write
                } else if operation == write {
                    read
                } else {
                    return Err(AsyncStateError::StaleOperation);
                };
                let peer_endpoint = self.endpoint_by_seal(peer.endpoint)?;
                if peer_endpoint.pair != pair
                    || peer_endpoint.direction == direction
                    || peer_endpoint.event.is_some()
                    || peer_endpoint
                        .active
                        .as_ref()
                        .is_none_or(|active| active.operation != peer.operation)
                {
                    return Err(AsyncStateError::PairInvariant);
                }
                PairPhase::Waiting(peer)
            }
            _ => return Err(AsyncStateError::StaleOperation),
        };
        self.prepare_event(operation, CopyResult::Cancelled, 0)?;
        let (generation, next_event) = {
            let endpoint = self.endpoint_by_seal(seal)?;
            let generation =
                NonZeroU64::new(endpoint.next_event).ok_or(AsyncStateError::GenerationExhausted)?;
            let next_event = endpoint
                .next_event
                .checked_add(1)
                .ok_or(AsyncStateError::GenerationExhausted)?;
            (generation, next_event)
        };

        Ok(PreparedCancelCopy {
            endpoint: seal,
            operation,
            action: CancelAction::New {
                pair,
                original_phase,
                next_phase,
                generation,
                next_event,
            },
        })
    }

    /// Synchronously requests cancellation of the current exact copy.
    ///
    /// The selected profile does not enable the async cancel builtins, so a
    /// parked local or reactive-host operation is removed immediately and a
    /// `Cancelled` event is made available to the caller.
    pub fn cancel_copy(
        &mut self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<EventToken, AsyncStateError> {
        let PreparedCancelCopy {
            endpoint: seal,
            operation,
            action,
        } = self.prepare_cancel_copy(handle, kind, direction, value_type)?;
        let (pair, original_phase, next_phase, generation, next_event) = match action {
            CancelAction::Existing(event) => {
                self.endpoint_by_seal_mut(seal)?.copy_state = CopyState::Cancelling;
                return Ok(event);
            }
            CancelAction::New {
                pair,
                original_phase,
                next_phase,
                generation,
                next_event,
            } => (pair, original_phase, next_phase, generation, next_event),
        };

        // Every fallible lookup and counter check precedes this commit. The
        // endpoint retains its active lease until the returned event is
        // delivered and reclaimed; the exact peer becomes pending again.
        let shared = self.pairs.get_mut(pair)?;
        if shared.phase != original_phase {
            return Err(AsyncStateError::PairInvariant);
        }
        let entry = self.handles.get_mut(seal)?;
        let endpoint = entry.endpoint_mut()?;
        if endpoint.event.is_some()
            || endpoint.next_event != generation.get()
            || endpoint
                .active
                .as_ref()
                .is_none_or(|active| active.operation != operation.operation)
        {
            return Err(AsyncStateError::StaleOperation);
        }
        endpoint.copy_state = CopyState::Cancelling;
        endpoint.next_event = next_event;
        endpoint.event = Some(PendingEvent {
            operation: operation.operation,
            result: CopyResult::Cancelled,
            progress: 0,
            generation,
            phase: EventPhase::Pending,
        });
        shared.phase = next_phase;
        Ok(EventToken {
            state_id: self.id,
            endpoint: seal,
            operation: operation.operation,
            generation,
        })
    }

    pub fn deliver_event(
        &mut self,
        token: &EventToken,
    ) -> Result<(Event, ReclaimToken), AsyncStateError> {
        if token.state_id != self.id {
            return Err(AsyncStateError::WrongState);
        }
        let endpoint = self.endpoint_by_seal_mut(token.endpoint)?;
        let event = endpoint
            .event
            .as_mut()
            .ok_or(AsyncStateError::NoPendingEvent)?;
        if event.operation != token.operation || event.generation != token.generation {
            return Err(AsyncStateError::StaleEvent);
        }
        if event.phase != EventPhase::Pending {
            return Err(AsyncStateError::EventAlreadyDelivered);
        }
        let p2 = match endpoint.kind {
            EndpointKind::Stream => pack_stream_copy_result(event.result, event.progress)
                .map_err(|_| AsyncStateError::ProgressLimit)?,
            EndpointKind::Future => event.result as u32,
        };
        let code = match (endpoint.kind, endpoint.direction) {
            (EndpointKind::Stream, EndpointDirection::Read) => EventCode::StreamRead,
            (EndpointKind::Stream, EndpointDirection::Write) => EventCode::StreamWrite,
            (EndpointKind::Future, EndpointDirection::Read) => EventCode::FutureRead,
            (EndpointKind::Future, EndpointDirection::Write) => EventCode::FutureWrite,
        };
        event.phase = EventPhase::Delivered;
        Ok((
            Event {
                code,
                p1: token.endpoint.index,
                p2,
            },
            ReclaimToken {
                state_id: self.id,
                endpoint: token.endpoint,
                operation: token.operation,
                generation: token.generation,
                reclaimed: false,
            },
        ))
    }

    /// Obtains the exact pending event authority for a known endpoint. This is
    /// used by the callback executor when a peer completed the operation.
    pub fn pending_event(
        &self,
        handle: AsyncHandle,
    ) -> Result<Option<EventToken>, AsyncStateError> {
        let seal = self.handle_seal(handle)?;
        let endpoint = self.endpoint_by_seal(seal)?;
        let Some(event) = endpoint.event.as_ref() else {
            return Ok(None);
        };
        Ok(Some(EventToken {
            state_id: self.id,
            endpoint: seal,
            operation: event.operation,
            generation: event.generation,
        }))
    }

    /// Reclaims the exact buffer and only then releases the endpoint for reuse.
    /// A failing closure leaves both the delivered event and endpoint state
    /// unchanged, and the caller retains the same usable token.
    pub fn reclaim_event<E>(
        &mut self,
        token: &mut ReclaimToken,
        reclaim: impl FnOnce(&BufferLease) -> Result<(), E>,
    ) -> Result<(), ReclaimError<E>> {
        if token.state_id != self.id || token.reclaimed {
            return Err(ReclaimError::State(AsyncStateError::StaleEvent));
        }
        let (kind, result) = {
            let endpoint = self
                .endpoint_by_seal(token.endpoint)
                .map_err(ReclaimError::State)?;
            let active = endpoint
                .active
                .as_ref()
                .filter(|active| active.operation == token.operation)
                .ok_or(ReclaimError::State(AsyncStateError::StaleEvent))?;
            let event = endpoint
                .event
                .as_ref()
                .filter(|event| {
                    event.operation == token.operation
                        && event.generation == token.generation
                        && event.phase == EventPhase::Delivered
                })
                .ok_or(ReclaimError::State(AsyncStateError::StaleEvent))?;
            reclaim(&active.lease).map_err(ReclaimError::Operation)?;
            (endpoint.kind, event.result)
        };
        let endpoint = self
            .endpoint_by_seal_mut(token.endpoint)
            .map_err(ReclaimError::State)?;
        endpoint.active = None;
        endpoint.event = None;
        endpoint.copy_state = settled_copy_state(kind, result);
        token.reclaimed = true;
        Ok(())
    }

    /// Drains every live copy during fail-stop executor teardown.
    ///
    /// This walk does not allocate. Pair and endpoint authority is invalidated
    /// before each owned lease is handed to `release`, which must be
    /// infallible. If it nevertheless unwinds, calling this method again drains
    /// only the leases which were not already handed off.
    pub(crate) fn abort_all_copies(&mut self, mut release: impl FnMut(BufferLease)) {
        // Invalidate local and host tickets globally before the first external
        // cleanup call. Monotonic counters are deliberately retained so later
        // operations cannot resurrect an old operation or event authority.
        for slot in &mut self.pairs.slots {
            if let Some(pair) = slot.value.as_mut() {
                pair.phase = PairPhase::Idle;
            }
        }

        for slot in &mut self.handles.slots {
            let lease = match slot.value.as_mut() {
                Some(HandleEntry::Endpoint(endpoint)) => {
                    let settled = endpoint
                        .event
                        .as_ref()
                        .map(|event| settled_copy_state(endpoint.kind, event.result));
                    let active = endpoint.active.take();
                    endpoint.event = None;
                    if let Some(settled) = settled {
                        endpoint.copy_state = settled;
                    } else if active.is_some()
                        || matches!(
                            endpoint.copy_state,
                            CopyState::Copying | CopyState::Cancelling
                        )
                    {
                        endpoint.copy_state = CopyState::Idle;
                    }
                    active.map(|active| active.lease)
                }
                Some(HandleEntry::WaitableSet(_)) | None => None,
            };
            if let Some(lease) = lease {
                release(lease);
            }
        }
    }

    pub fn detach_readable(
        &mut self,
        handle: AsyncHandle,
        kind: EndpointKind,
        value_type: AsyncValueTypeId,
    ) -> Result<HostEndpointAuthority, AsyncStateError> {
        let seal = self.handle_seal(handle)?;
        let pair = {
            let endpoint = self.endpoint_by_seal(seal)?;
            validate_endpoint(endpoint, kind, EndpointDirection::Read, value_type)?;
            if endpoint.copy_state != CopyState::Idle
                || endpoint.active.is_some()
                || endpoint.event.is_some()
            {
                return Err(AsyncStateError::EndpointBusy);
            }
            if endpoint.joined_set.is_some() {
                return Err(AsyncStateError::TransferWhileJoined);
            }
            endpoint.pair
        };
        if self.pairs.get(pair)?.readable != Holder::Guest(seal) {
            return Err(AsyncStateError::PairInvariant);
        }
        self.pairs.get_mut(pair)?.readable = Holder::Host;
        self.handles.remove(seal)?;
        Ok(HostEndpointAuthority {
            state_id: self.id,
            pair,
            kind,
            direction: EndpointDirection::Read,
            value_type,
            active: true,
        })
    }

    /// Atomically lifts the two readable endpoints in the native filter's
    /// `(stream<u8>, future<close-reason>)` result aggregate.
    ///
    /// Unlike [`Self::detach_readables_batch`], this fixed-shape path does not
    /// allocate. Both requests, their pair holders, and both output tokens are
    /// completely validated before the first handle moves.
    pub fn detach_readables_pair(
        &mut self,
        first: ReadableTransferRequest,
        second: ReadableTransferRequest,
    ) -> Result<(TransferredReadableEndpoint, TransferredReadableEndpoint), AsyncStateError> {
        let (first_seal, first_pair, first_token) = self.prepare_readable_transfer(first)?;
        if first.handle == second.handle {
            return Err(AsyncStateError::DuplicateHandle);
        }
        let (second_seal, second_pair, second_token) = self.prepare_readable_transfer(second)?;

        // These mutable resolutions are the last fallible pair-side step. The
        // holders are rechecked before either guest handle is removed.
        let (first_shared, second_shared) = self.pairs.get_two_mut(first_pair, second_pair)?;
        if first_shared.readable != Holder::Guest(first_seal)
            || first_shared.kind != first.kind
            || first_shared.value_type != first.value_type
            || second_shared.readable != Holder::Guest(second_seal)
            || second_shared.kind != second.kind
            || second_shared.value_type != second.value_type
        {
            return Err(AsyncStateError::PairInvariant);
        }

        // `remove_two` validates both exact slots before taking either one and
        // rolls the first value back if a corrupted second slot disappears.
        // Once it succeeds, changing these already-borrowed holders cannot
        // fail, so the aggregate cannot be left half transferred.
        let (first_entry, second_entry) = self.handles.remove_two(first_seal, second_seal)?;
        debug_assert!(matches!(first_entry, HandleEntry::Endpoint(_)));
        debug_assert!(matches!(second_entry, HandleEntry::Endpoint(_)));
        first_shared.readable = Holder::Host;
        second_shared.readable = Holder::Host;
        Ok((first_token, second_token))
    }

    /// Atomically lifts every readable endpoint in one aggregate.
    /// Allocation and validation finish before the first guest handle moves.
    pub fn detach_readables_batch(
        &mut self,
        requests: &[ReadableTransferRequest],
    ) -> Result<Vec<TransferredReadableEndpoint>, AsyncStateError> {
        if requests.len() > PROFILE_1_LIMITS.max_canonical_values as usize {
            return Err(AsyncStateError::HandleTableFull);
        }
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(requests.len())
            .map_err(|_| AsyncStateError::AllocationFailed)?;
        for (index, request) in requests.iter().enumerate() {
            let seal = self.handle_seal(request.handle)?;
            if requests[..index]
                .iter()
                .any(|previous| previous.handle == request.handle)
            {
                return Err(AsyncStateError::DuplicateHandle);
            }
            let endpoint = self.endpoint_by_seal(seal)?;
            validate_endpoint(
                endpoint,
                request.kind,
                EndpointDirection::Read,
                request.value_type,
            )?;
            if endpoint.copy_state != CopyState::Idle
                || endpoint.active.is_some()
                || endpoint.event.is_some()
            {
                return Err(AsyncStateError::EndpointBusy);
            }
            if endpoint.joined_set.is_some() {
                return Err(AsyncStateError::TransferWhileJoined);
            }
            let pair = endpoint.pair;
            let shared = self.pairs.get(pair)?;
            if shared.readable != Holder::Guest(seal)
                || shared.kind != request.kind
                || shared.value_type != request.value_type
            {
                return Err(AsyncStateError::PairInvariant);
            }
            let token = match request.kind {
                EndpointKind::Stream => TransferredReadableEndpoint::Stream(
                    ReadableStreamEndpointToken::issue(
                        self.id.get(),
                        pair.index,
                        pair.generation,
                        request.value_type,
                        EndpointOwner::Host,
                    )
                    .map_err(|_| AsyncStateError::PairInvariant)?,
                ),
                EndpointKind::Future => TransferredReadableEndpoint::Future(
                    ReadableFutureEndpointToken::issue(
                        self.id.get(),
                        pair.index,
                        pair.generation,
                        request.value_type,
                        EndpointOwner::Host,
                    )
                    .map_err(|_| AsyncStateError::PairInvariant)?,
                ),
            };
            prepared.push((seal, pair, token));
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(prepared.len())
            .map_err(|_| AsyncStateError::AllocationFailed)?;
        for (seal, pair, token) in prepared {
            self.pairs.get_mut(pair)?.readable = Holder::Host;
            match self.handles.remove(seal)? {
                HandleEntry::Endpoint(_) => {}
                HandleEntry::WaitableSet(_) => return Err(AsyncStateError::PairInvariant),
            }
            output.push(token);
        }
        Ok(output)
    }

    fn prepare_readable_transfer(
        &self,
        request: ReadableTransferRequest,
    ) -> Result<(Seal, Seal, TransferredReadableEndpoint), AsyncStateError> {
        let seal = self.handle_seal(request.handle)?;
        let endpoint = self.endpoint_by_seal(seal)?;
        validate_endpoint(
            endpoint,
            request.kind,
            EndpointDirection::Read,
            request.value_type,
        )?;
        if endpoint.copy_state != CopyState::Idle
            || endpoint.active.is_some()
            || endpoint.event.is_some()
        {
            return Err(AsyncStateError::EndpointBusy);
        }
        if endpoint.joined_set.is_some() {
            return Err(AsyncStateError::TransferWhileJoined);
        }
        let pair = endpoint.pair;
        let shared = self.pairs.get(pair)?;
        if shared.readable != Holder::Guest(seal)
            || shared.kind != request.kind
            || shared.value_type != request.value_type
        {
            return Err(AsyncStateError::PairInvariant);
        }
        let token = match request.kind {
            EndpointKind::Stream => TransferredReadableEndpoint::Stream(
                ReadableStreamEndpointToken::issue(
                    self.id.get(),
                    pair.index,
                    pair.generation,
                    request.value_type,
                    EndpointOwner::Host,
                )
                .map_err(|_| AsyncStateError::PairInvariant)?,
            ),
            EndpointKind::Future => TransferredReadableEndpoint::Future(
                ReadableFutureEndpointToken::issue(
                    self.id.get(),
                    pair.index,
                    pair.generation,
                    request.value_type,
                    EndpointOwner::Host,
                )
                .map_err(|_| AsyncStateError::PairInvariant)?,
            ),
        };
        Ok((seal, pair, token))
    }

    pub fn prepare_stream_host_copy(
        &self,
        token: &ReadableStreamEndpointToken,
        operation: &CopyOpToken,
    ) -> Result<HostCopyTicket, AsyncStateError> {
        let pair = self.find_stream_token(token)?;
        let authority =
            self.transferred_authority(pair, EndpointKind::Stream, token.value_type())?;
        self.prepare_host_copy(&authority, operation)
    }

    pub fn prepare_future_host_copy(
        &self,
        token: &ReadableFutureEndpointToken,
        operation: &CopyOpToken,
    ) -> Result<HostCopyTicket, AsyncStateError> {
        let pair = self.find_future_token(token)?;
        let authority =
            self.transferred_authority(pair, EndpointKind::Future, token.value_type())?;
        self.prepare_host_copy(&authority, operation)
    }

    pub fn drop_stream_host_readable(
        &mut self,
        token: &ReadableStreamEndpointToken,
    ) -> Result<(), AsyncStateError> {
        let pair = self.find_stream_token(token)?;
        let mut authority =
            self.transferred_authority(pair, EndpointKind::Stream, token.value_type())?;
        self.drop_host_endpoint(&mut authority)
    }

    pub fn drop_future_host_readable(
        &mut self,
        token: &ReadableFutureEndpointToken,
    ) -> Result<(), AsyncStateError> {
        let pair = self.find_future_token(token)?;
        let mut authority =
            self.transferred_authority(pair, EndpointKind::Future, token.value_type())?;
        self.drop_host_endpoint(&mut authority)
    }

    pub fn drop_host_endpoint(
        &mut self,
        authority: &mut HostEndpointAuthority,
    ) -> Result<(), AsyncStateError> {
        self.validate_authority(authority)?;
        let pair = authority.pair;
        let (holder, pending) = {
            let shared = self.pairs.get(pair)?;
            let holder = match authority.direction {
                EndpointDirection::Read => shared.readable,
                EndpointDirection::Write => shared.writable,
            };
            let pending = match shared.phase {
                PairPhase::Idle => None,
                PairPhase::Waiting(operation) => Some(operation),
                PairPhase::Matching { .. } => return Err(AsyncStateError::PairBusy),
            };
            (holder, pending)
        };
        if holder != Holder::Host {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        if authority.kind == EndpointKind::Future
            && authority.direction == EndpointDirection::Write
            && !self.pairs.get(pair)?.host_writable_done
        {
            return Err(AsyncStateError::FutureWritableNotDone);
        }
        if let Some(operation) = pending {
            let endpoint = self.endpoint_by_seal(operation.endpoint)?;
            if endpoint.direction == authority.direction {
                return Err(AsyncStateError::PairInvariant);
            }
            self.prepare_event(operation, CopyResult::Dropped, 0)?;
            self.queue_event(operation, CopyResult::Dropped, 0)?;
        }
        {
            let shared = self.pairs.get_mut(pair)?;
            shared.peer_dropped = true;
            shared.phase = PairPhase::Idle;
            match authority.direction {
                EndpointDirection::Read => shared.readable = Holder::Dropped,
                EndpointDirection::Write => shared.writable = Holder::Dropped,
            }
        }
        authority.active = false;
        self.maybe_remove_pair(pair)
    }

    pub fn drop_endpoint(
        &mut self,
        handle: AsyncHandle,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    ) -> Result<(), AsyncStateError> {
        let seal = self.handle_seal(handle)?;
        let (pair, copy_state, joined_set) = {
            let endpoint = self.endpoint_by_seal(seal)?;
            validate_endpoint(endpoint, kind, direction, value_type)?;
            if endpoint.active.is_some() || endpoint.event.is_some() {
                return Err(AsyncStateError::DropWhileCopying);
            }
            if matches!(
                endpoint.copy_state,
                CopyState::Copying | CopyState::Cancelling
            ) {
                return Err(AsyncStateError::DropWhileCopying);
            }
            if kind == EndpointKind::Future
                && direction == EndpointDirection::Write
                && endpoint.copy_state != CopyState::Done
            {
                return Err(AsyncStateError::FutureWritableNotDone);
            }
            (endpoint.pair, endpoint.copy_state, endpoint.joined_set)
        };
        let _ = copy_state;
        let (holder, pending) = {
            let shared = self.pairs.get(pair)?;
            let holder = match direction {
                EndpointDirection::Read => shared.readable,
                EndpointDirection::Write => shared.writable,
            };
            let pending = match shared.phase {
                PairPhase::Idle => None,
                PairPhase::Waiting(operation) => Some(operation),
                PairPhase::Matching { .. } => return Err(AsyncStateError::PairBusy),
            };
            (holder, pending)
        };
        if holder != Holder::Guest(seal) {
            return Err(AsyncStateError::PairInvariant);
        }
        if let Some(operation) = pending {
            if operation.endpoint == seal {
                return Err(AsyncStateError::PairInvariant);
            }
            self.prepare_event(operation, CopyResult::Dropped, 0)?;
            self.queue_event(operation, CopyResult::Dropped, 0)?;
        }
        let joined_position = if let Some(set) = joined_set {
            Some(
                self.waitable_set_by_seal(set)?
                    .members
                    .iter()
                    .position(|member| *member == seal)
                    .ok_or(AsyncStateError::WaitableNotJoined)?,
            )
        } else {
            None
        };
        {
            let shared = self.pairs.get_mut(pair)?;
            shared.peer_dropped = true;
            shared.phase = PairPhase::Idle;
            match direction {
                EndpointDirection::Read => shared.readable = Holder::Dropped,
                EndpointDirection::Write => shared.writable = Holder::Dropped,
            }
        }
        if let (Some(set), Some(position)) = (joined_set, joined_position) {
            self.waitable_set_by_seal_mut(set)?.members.remove(position);
        }
        self.handles.remove(seal)?;
        self.maybe_remove_pair(pair)
    }

    fn validate_authority(&self, authority: &HostEndpointAuthority) -> Result<(), AsyncStateError> {
        if authority.state_id != self.id {
            return Err(AsyncStateError::WrongState);
        }
        if !authority.active {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        let shared = self.pairs.get(authority.pair)?;
        if shared.kind != authority.kind || shared.value_type != authority.value_type {
            return Err(AsyncStateError::PairInvariant);
        }
        Ok(())
    }

    fn transferred_authority(
        &self,
        pair: Seal,
        kind: EndpointKind,
        value_type: AsyncValueTypeId,
    ) -> Result<HostEndpointAuthority, AsyncStateError> {
        let shared = self.pairs.get(pair)?;
        if shared.readable != Holder::Host || shared.kind != kind || shared.value_type != value_type
        {
            return Err(AsyncStateError::AuthorityConsumed);
        }
        Ok(HostEndpointAuthority {
            state_id: self.id,
            pair,
            kind,
            direction: EndpointDirection::Read,
            value_type,
            active: true,
        })
    }

    fn find_stream_token(
        &self,
        token: &ReadableStreamEndpointToken,
    ) -> Result<Seal, AsyncStateError> {
        self.find_transferred_pair(|pair, shared| {
            shared.kind == EndpointKind::Stream
                && validate_readable_stream_endpoint(
                    token,
                    self.id.get(),
                    pair.index,
                    pair.generation,
                    shared.value_type,
                    EndpointOwner::Host,
                )
                .is_ok()
        })
    }

    fn find_future_token(
        &self,
        token: &ReadableFutureEndpointToken,
    ) -> Result<Seal, AsyncStateError> {
        self.find_transferred_pair(|pair, shared| {
            shared.kind == EndpointKind::Future
                && validate_readable_future_endpoint(
                    token,
                    self.id.get(),
                    pair.index,
                    pair.generation,
                    shared.value_type,
                    EndpointOwner::Host,
                )
                .is_ok()
        })
    }

    fn find_transferred_pair(
        &self,
        mut matches: impl FnMut(Seal, &SharedPair) -> bool,
    ) -> Result<Seal, AsyncStateError> {
        for (slot_index, slot) in self.pairs.slots.iter().enumerate() {
            let Some(shared) = slot.value.as_ref() else {
                continue;
            };
            if slot.retired {
                continue;
            }
            let index = u32::try_from(slot_index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(AsyncStateError::InvalidHandle)?;
            let pair = Seal::new(index, slot.generation)?;
            if matches(pair, shared) {
                return Ok(pair);
            }
        }
        Err(AsyncStateError::AuthorityConsumed)
    }

    fn active_for(&self, operation: OpRef) -> Result<&ActiveCopy, AsyncStateError> {
        self.endpoint_by_seal(operation.endpoint)?
            .active
            .as_ref()
            .filter(|active| active.operation == operation.operation)
            .ok_or(AsyncStateError::StaleOperation)
    }

    fn preflight_new_event(
        &self,
        endpoint: Seal,
        kind: EndpointKind,
        direction: EndpointDirection,
        result: CopyResult,
        progress: u32,
        elements: u32,
    ) -> Result<(), AsyncStateError> {
        let endpoint = self.endpoint_by_seal(endpoint)?;
        if endpoint.event.is_some() || endpoint.next_event == 0 || endpoint.next_event == u64::MAX {
            return Err(AsyncStateError::GenerationExhausted);
        }
        validate_event_result(kind, direction, result, progress, elements)
    }

    fn prepare_event(
        &self,
        operation: OpRef,
        result: CopyResult,
        progress: u32,
    ) -> Result<(), AsyncStateError> {
        let endpoint = self.endpoint_by_seal(operation.endpoint)?;
        let active = endpoint
            .active
            .as_ref()
            .filter(|active| active.operation == operation.operation)
            .ok_or(AsyncStateError::StaleOperation)?;
        if endpoint.event.is_some() {
            return Err(AsyncStateError::PairInvariant);
        }
        if endpoint.next_event == 0 || endpoint.next_event == u64::MAX {
            return Err(AsyncStateError::GenerationExhausted);
        }
        validate_event_result(
            endpoint.kind,
            endpoint.direction,
            result,
            progress,
            active.lease.elements,
        )
    }

    fn queue_event(
        &mut self,
        operation: OpRef,
        result: CopyResult,
        progress: u32,
    ) -> Result<(), AsyncStateError> {
        self.prepare_event(operation, result, progress)?;
        let endpoint = self.endpoint_by_seal_mut(operation.endpoint)?;
        let generation =
            NonZeroU64::new(endpoint.next_event).ok_or(AsyncStateError::GenerationExhausted)?;
        endpoint.next_event = endpoint
            .next_event
            .checked_add(1)
            .ok_or(AsyncStateError::GenerationExhausted)?;
        endpoint.event = Some(PendingEvent {
            operation: operation.operation,
            result,
            progress,
            generation,
            phase: EventPhase::Pending,
        });
        Ok(())
    }

    fn event_token(&self, operation: OpRef) -> Result<EventToken, AsyncStateError> {
        let endpoint = self.endpoint_by_seal(operation.endpoint)?;
        let event = endpoint
            .event
            .as_ref()
            .filter(|event| event.operation == operation.operation)
            .ok_or(AsyncStateError::NoPendingEvent)?;
        Ok(EventToken {
            state_id: self.id,
            endpoint: operation.endpoint,
            operation: operation.operation,
            generation: event.generation,
        })
    }

    fn maybe_remove_pair(&mut self, pair: Seal) -> Result<(), AsyncStateError> {
        let removable = {
            let shared = self.pairs.get(pair)?;
            shared.readable == Holder::Dropped
                && shared.writable == Holder::Dropped
                && shared.phase == PairPhase::Idle
        };
        if removable {
            self.pairs.remove(pair)?;
        }
        Ok(())
    }
}

impl AsyncState {
    pub fn create_task(&mut self) -> Result<TaskHandle, AsyncStateError> {
        self.tasks.prepare_insert(1)?;
        let seal = self.tasks.insert_prepared(Task {
            result: TaskResultState::Pending,
            callback: TaskCallbackState::Running,
            cancel: TaskCancelState::None,
            waiting: None,
        })?;
        Ok(TaskHandle {
            state_id: self.id,
            seal,
        })
    }

    pub fn task_info(&self, task: TaskHandle) -> Result<TaskInfo, AsyncStateError> {
        let task = self.task(task)?;
        Ok(TaskInfo {
            result: task.result,
            callback: task.callback,
            cancel: task.cancel,
            waiting: task.waiting.is_some(),
        })
    }

    pub fn resolve_task_result(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let task = self.task_mut(task)?;
        if task.result == TaskResultState::Resolved {
            return Err(AsyncStateError::TaskAlreadyResolved);
        }
        // The pinned `task.return` transition supersedes either a pending or
        // delivered cancellation. Once resolved, no later callback wait may
        // redeliver the old cancellation request.
        task.cancel = TaskCancelState::None;
        task.result = TaskResultState::Resolved;
        Ok(())
    }

    pub fn request_task_cancel(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let task = self.task_mut(task)?;
        if task.result == TaskResultState::Resolved || task.cancel != TaskCancelState::None {
            return Err(AsyncStateError::TaskCancelState);
        }
        task.cancel = TaskCancelState::Requested;
        Ok(())
    }

    /// Selects the event for one stackless callback `YIELD` transition.
    ///
    /// Cancellation is delivered at most once: an exact pending request is
    /// atomically advanced to `Delivered`; all other cancellation states yield
    /// `NONE`. A callback which has exited or already owns a blocked `WAIT`
    /// cannot yield again.
    pub fn callback_yield(&mut self, task: TaskHandle) -> Result<Event, AsyncStateError> {
        let task = self.task_mut(task)?;
        if task.callback != TaskCallbackState::Running {
            return Err(AsyncStateError::TaskAlreadyExited);
        }
        if task.waiting.is_some() {
            return Err(AsyncStateError::AlreadyWaiting);
        }
        if task.cancel == TaskCancelState::Requested {
            task.cancel = TaskCancelState::Delivered;
            Ok(task_cancelled_event())
        } else {
            Ok(none_event())
        }
    }

    /// Implements the selected `task.cancel` builtin after a cancellable wait
    /// delivered `TASK_CANCELLED` to this exact task.
    pub fn acknowledge_task_cancel(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let task = self.task_mut(task)?;
        if task.cancel != TaskCancelState::Delivered || task.result == TaskResultState::Resolved {
            return Err(AsyncStateError::TaskCancelState);
        }
        task.cancel = TaskCancelState::Acknowledged;
        task.result = TaskResultState::Resolved;
        Ok(())
    }

    pub fn callback_exit(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let task = self.task_mut(task)?;
        if task.callback == TaskCallbackState::Exited {
            return Err(AsyncStateError::TaskAlreadyExited);
        }
        if task.result != TaskResultState::Resolved || task.waiting.is_some() {
            return Err(AsyncStateError::TaskNotResolved);
        }
        task.callback = TaskCallbackState::Exited;
        Ok(())
    }

    pub fn drop_task(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let seal = self.task_seal(task)?;
        let task = self.tasks.get(seal)?;
        if task.result != TaskResultState::Resolved
            || task.callback != TaskCallbackState::Exited
            || task.waiting.is_some()
        {
            return Err(AsyncStateError::TaskIncomplete);
        }
        self.tasks.remove(seal)?;
        Ok(())
    }

    /// Removes a task after fail-stop executor teardown. An active wait owns a
    /// registration in both the task and waitable set, so it must be cancelled
    /// first; rejection leaves both sides of that registration unchanged.
    pub(crate) fn abort_task(&mut self, task: TaskHandle) -> Result<(), AsyncStateError> {
        let seal = self.task_seal(task)?;
        if self.tasks.get(seal)?.waiting.is_some() {
            return Err(AsyncStateError::AlreadyWaiting);
        }
        self.tasks.remove(seal)?;
        Ok(())
    }

    /// Registers the stackless callback's `WAIT(set)` transition.
    /// Cancellation is selected before an endpoint event, matching the pinned
    /// cancellable-wait ordering.
    pub fn begin_callback_wait(
        &mut self,
        task: TaskHandle,
        set: AsyncHandle,
    ) -> Result<WaitBegin, AsyncStateError> {
        let task_seal = self.task_seal(task)?;
        let set_seal = self.handle_seal(set)?;
        self.waitable_set_by_seal(set_seal)?;
        {
            let task = self.tasks.get(task_seal)?;
            if task.callback != TaskCallbackState::Running || task.waiting.is_some() {
                return Err(AsyncStateError::AlreadyWaiting);
            }
        }
        if self.waitable_set_by_seal(set_seal)?.waiter.is_some() {
            return Err(AsyncStateError::WaitableSetWaiting);
        }
        if self.tasks.get(task_seal)?.cancel == TaskCancelState::Requested {
            self.tasks.get_mut(task_seal)?.cancel = TaskCancelState::Delivered;
            return Ok(WaitBegin::Ready(EventLease::task_cancelled(
                task_cancelled_event(),
            )));
        }
        if let Some(event) = self.pending_event_in_set(set_seal)? {
            return Ok(WaitBegin::Ready(EventLease::endpoint_pending(event)));
        }
        let epoch = {
            let set = self.waitable_set_by_seal(set_seal)?;
            if set.next_wait == 0 || set.next_wait == u64::MAX {
                return Err(AsyncStateError::GenerationExhausted);
            }
            NonZeroU64::new(set.next_wait).ok_or(AsyncStateError::GenerationExhausted)?
        };
        {
            let set = self.waitable_set_by_seal_mut(set_seal)?;
            set.next_wait = set
                .next_wait
                .checked_add(1)
                .ok_or(AsyncStateError::GenerationExhausted)?;
            set.waiter = Some(WaitRegistration {
                task: task_seal,
                epoch,
            });
        }
        self.tasks.get_mut(task_seal)?.waiting = Some((set_seal, epoch));
        Ok(WaitBegin::Blocked {
            ticket: WaitTicket {
                state_id: self.id,
                task: task_seal,
                set: set_seal,
                epoch,
                active: true,
            },
        })
    }

    pub fn resume_callback_wait(
        &mut self,
        ticket: &mut WaitTicket,
    ) -> Result<WaitResume, AsyncStateError> {
        self.validate_wait_ticket(ticket)?;
        if self.tasks.get(ticket.task)?.cancel == TaskCancelState::Requested {
            self.clear_wait_registration(ticket)?;
            self.tasks.get_mut(ticket.task)?.cancel = TaskCancelState::Delivered;
            ticket.active = false;
            return Ok(WaitResume::Ready(EventLease::task_cancelled(
                task_cancelled_event(),
            )));
        }
        let Some(event) = self.pending_event_in_set(ticket.set)? else {
            return Ok(WaitResume::Pending);
        };
        self.clear_wait_registration(ticket)?;
        ticket.active = false;
        Ok(WaitResume::Ready(EventLease::endpoint_pending(event)))
    }

    pub fn cancel_callback_wait(&mut self, ticket: &mut WaitTicket) -> Result<(), AsyncStateError> {
        self.validate_wait_ticket(ticket)?;
        self.clear_wait_registration(ticket)?;
        ticket.active = false;
        Ok(())
    }

    fn validate_wait_ticket(&self, ticket: &WaitTicket) -> Result<(), AsyncStateError> {
        if ticket.state_id != self.id || !ticket.active {
            return Err(AsyncStateError::StaleWait);
        }
        let registration = WaitRegistration {
            task: ticket.task,
            epoch: ticket.epoch,
        };
        if self.waitable_set_by_seal(ticket.set)?.waiter != Some(registration)
            || self.tasks.get(ticket.task)?.waiting != Some((ticket.set, ticket.epoch))
        {
            return Err(AsyncStateError::StaleWait);
        }
        Ok(())
    }

    fn clear_wait_registration(&mut self, ticket: &WaitTicket) -> Result<(), AsyncStateError> {
        self.validate_wait_ticket(ticket)?;
        self.waitable_set_by_seal_mut(ticket.set)?.waiter = None;
        self.tasks.get_mut(ticket.task)?.waiting = None;
        Ok(())
    }

    fn pending_event_in_set(&self, set: Seal) -> Result<Option<EventToken>, AsyncStateError> {
        for member in &self.waitable_set_by_seal(set)?.members {
            let endpoint = self.endpoint_by_seal(*member)?;
            if let Some(event) = endpoint
                .event
                .as_ref()
                .filter(|event| event.phase == EventPhase::Pending)
            {
                return Ok(Some(EventToken {
                    state_id: self.id,
                    endpoint: *member,
                    operation: event.operation,
                    generation: event.generation,
                }));
            }
        }
        Ok(None)
    }

    fn task_seal(&self, task: TaskHandle) -> Result<Seal, AsyncStateError> {
        if task.state_id != self.id {
            return Err(AsyncStateError::WrongState);
        }
        self.tasks.get(task.seal)?;
        Ok(task.seal)
    }

    fn task(&self, task: TaskHandle) -> Result<&Task, AsyncStateError> {
        self.tasks.get(self.task_seal(task)?)
    }

    fn task_mut(&mut self, task: TaskHandle) -> Result<&mut Task, AsyncStateError> {
        let seal = self.task_seal(task)?;
        self.tasks.get_mut(seal)
    }
}

const fn task_cancelled_event() -> Event {
    Event {
        code: EventCode::TaskCancelled,
        p1: 0,
        p2: 0,
    }
}

const fn none_event() -> Event {
    Event {
        code: EventCode::None,
        p1: 0,
        p2: 0,
    }
}

fn validate_host_result(
    kind: EndpointKind,
    direction: EndpointDirection,
    result: CopyResult,
    progress: u32,
    elements: u32,
) -> Result<u32, AsyncStateError> {
    match kind {
        EndpointKind::Stream => {
            if progress >= (1_u32 << 28)
                || progress > elements
                || (result != CopyResult::Completed && progress != 0)
            {
                return Err(AsyncStateError::ProgressLimit);
            }
            Ok(progress)
        }
        EndpointKind::Future => {
            if progress != u32::from(result == CopyResult::Completed) || elements != 1 {
                return Err(AsyncStateError::ProgressLimit);
            }
            if result == CopyResult::Dropped && direction == EndpointDirection::Read {
                return Err(AsyncStateError::InvalidCopyResult);
            }
            Ok(0)
        }
    }
}

fn validate_event_result(
    kind: EndpointKind,
    direction: EndpointDirection,
    result: CopyResult,
    progress: u32,
    elements: u32,
) -> Result<(), AsyncStateError> {
    match kind {
        EndpointKind::Stream => {
            if progress >= (1_u32 << 28)
                || progress > elements
                || (result != CopyResult::Completed && progress != 0)
            {
                return Err(AsyncStateError::ProgressLimit);
            }
        }
        EndpointKind::Future => {
            if progress != 0 || elements != 1 {
                return Err(AsyncStateError::ProgressLimit);
            }
            if result == CopyResult::Dropped && direction == EndpointDirection::Read {
                return Err(AsyncStateError::InvalidCopyResult);
            }
        }
    }
    Ok(())
}

const fn settled_copy_state(kind: EndpointKind, result: CopyResult) -> CopyState {
    match (kind, result) {
        (EndpointKind::Stream, CopyResult::Dropped)
        | (EndpointKind::Future, CopyResult::Completed | CopyResult::Dropped) => CopyState::Done,
        _ => CopyState::Idle,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::async_abi::{unpack_stream_copy_result, StreamCopyResult};

    fn limits() -> AsyncStateLimits {
        AsyncStateLimits {
            handles: 16,
            pairs: 8,
            tasks: 8,
            waitables_per_set: 8,
        }
    }

    fn ty(raw: u32) -> AsyncValueTypeId {
        AsyncValueTypeId::new(raw).unwrap()
    }

    fn lease(slot: u32, elements: u32) -> BufferLease {
        BufferLease::issue(1, slot, 1, elements).unwrap()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct EndpointSnapshot {
        info: EndpointInfo,
        next_operation: u64,
        next_event: u64,
        active_operation: Option<u64>,
        event: Option<(u64, u32, u32, u64, bool)>,
    }

    fn endpoint_snapshot(state: &AsyncState, handle: AsyncHandle) -> EndpointSnapshot {
        let endpoint = state.endpoint(handle).unwrap();
        EndpointSnapshot {
            info: state.endpoint_info(handle).unwrap(),
            next_operation: endpoint.next_operation,
            next_event: endpoint.next_event,
            active_operation: endpoint
                .active
                .as_ref()
                .map(|active| active.operation.get()),
            event: endpoint.event.as_ref().map(|event| {
                (
                    event.operation.get(),
                    event.result as u32,
                    event.progress,
                    event.generation.get(),
                    event.phase == EventPhase::Delivered,
                )
            }),
        }
    }

    fn blocked(value: CopyBegin) -> CopyOpToken {
        match value {
            CopyBegin::Blocked { abi, operation } => {
                assert_eq!(abi, BLOCKED);
                operation
            }
            other => panic!("expected blocked, got {other:?}"),
        }
    }

    fn ready(value: CopyBegin) -> EventToken {
        match value {
            CopyBegin::Ready(event) => event,
            other => panic!("expected ready, got {other:?}"),
        }
    }

    fn local(value: CopyBegin) -> LocalCopyTicket {
        match value {
            CopyBegin::Local(ticket) => ticket,
            other => panic!("expected local match, got {other:?}"),
        }
    }

    fn reclaim_ok(state: &mut AsyncState, event: &EventToken) -> Event {
        let (event, mut reclaim) = state.deliver_event(event).unwrap();
        state
            .reclaim_event(&mut reclaim, |_| Ok::<_, ()>(()))
            .unwrap();
        event
    }

    fn finish_endpoint_lease(state: &mut AsyncState, lease: &mut EventLease) -> Event {
        lease.prepare_endpoint(state).unwrap();
        lease.finish_endpoint(state, |_| Ok::<_, ()>(())).unwrap()
    }

    #[test]
    fn zero_is_reserved_and_state_and_slot_generations_are_sealed() {
        let mut first = AsyncState::new(limits()).unwrap();
        let second = AsyncState::new(limits()).unwrap();
        assert_eq!(
            first.resolve_guest_handle(0),
            Err(AsyncStateError::InvalidHandle)
        );

        let pair = first.create_stream_pair(ty(1)).unwrap();
        assert_eq!(
            second.endpoint_info(pair.readable),
            Err(AsyncStateError::WrongState)
        );
        first
            .drop_endpoint(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            )
            .unwrap();
        assert_eq!(
            first.endpoint_info(pair.readable),
            Err(AsyncStateError::StaleHandle)
        );
        let replacement = first.create_stream_pair(ty(1)).unwrap();
        if replacement.readable.raw() == pair.readable.raw() {
            assert_ne!(
                replacement.readable.generation(),
                pair.readable.generation()
            );
        }
    }

    #[test]
    fn raw_waitable_set_resolution_seals_kind_before_execution() {
        let mut state = AsyncState::new(limits()).unwrap();
        let endpoint = state.create_stream_pair(ty(1)).unwrap().readable;
        let set = state.create_waitable_set().unwrap();

        assert_eq!(state.resolve_guest_waitable_set(set.raw()), Ok(set));
        assert_eq!(
            state.resolve_guest_waitable_set(endpoint.raw()),
            Err(AsyncStateError::WrongHandleKind)
        );
        assert_eq!(
            state.resolve_guest_waitable_set(0),
            Err(AsyncStateError::InvalidHandle)
        );
        state.drop_waitable_set(set).unwrap();
        assert_eq!(
            state.resolve_guest_waitable_set(set.raw()),
            Err(AsyncStateError::StaleHandle)
        );
    }

    #[test]
    fn raw_endpoint_resolution_is_exact_and_read_only() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();
        let set = state.create_waitable_set().unwrap();
        let before = state.endpoint_info(pair.readable).unwrap();

        assert_eq!(
            state.resolve_guest_endpoint(
                pair.readable.raw(),
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Ok(pair.readable)
        );
        assert_eq!(state.endpoint_info(pair.readable), Ok(before));
        assert_eq!(
            state.resolve_guest_endpoint(
                pair.readable.raw(),
                EndpointKind::Future,
                EndpointDirection::Read,
                ty(1),
            ),
            Err(AsyncStateError::WrongEndpointKind)
        );
        assert_eq!(
            state.resolve_guest_endpoint(
                pair.readable.raw(),
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(1),
            ),
            Err(AsyncStateError::WrongDirection)
        );
        assert_eq!(
            state.resolve_guest_endpoint(
                pair.readable.raw(),
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(2),
            ),
            Err(AsyncStateError::WrongType)
        );
        assert_eq!(
            state.resolve_guest_endpoint(
                set.raw(),
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Err(AsyncStateError::WrongHandleKind)
        );
        assert_eq!(
            state.resolve_guest_endpoint(0, EndpointKind::Stream, EndpointDirection::Read, ty(1),),
            Err(AsyncStateError::InvalidHandle)
        );

        state
            .drop_endpoint(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            )
            .unwrap();
        assert_eq!(
            state.resolve_guest_endpoint(
                pair.readable.raw(),
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Err(AsyncStateError::StaleHandle)
        );
    }

    #[test]
    fn begin_failure_returns_the_exact_lease_without_starting_an_operation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();

        let wrong_type = BufferLease::issue(7, 91, 9, 3).unwrap();
        let failure = state
            .begin_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(2),
                wrong_type,
            )
            .unwrap_err();
        let (error, returned) = failure.into_parts();
        assert_eq!(error, AsyncStateError::WrongType);
        assert_eq!((returned.registry(), returned.slot()), (7, 91));
        assert_eq!((returned.generation(), returned.elements()), (9, 3));
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Idle
        );

        let _active = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(1),
                    lease(1, 4),
                )
                .unwrap(),
        );
        let busy = BufferLease::issue(8, 92, 10, 4).unwrap();
        let failure = state
            .begin_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
                busy,
            )
            .unwrap_err();
        let (error, returned) = failure.into_parts();
        assert_eq!(error, AsyncStateError::EndpointBusy);
        assert_eq!((returned.registry(), returned.slot()), (8, 92));
        assert_eq!((returned.generation(), returned.elements()), (10, 4));
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Copying
        );
    }

    #[test]
    fn begin_preflight_is_read_only_and_composes_with_the_exact_transition() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();
        let pair_seal = state.endpoint(pair.readable).unwrap().pair;
        let before_read = endpoint_snapshot(&state, pair.readable);
        let before_phase = state.pairs.get(pair_seal).unwrap().phase;
        let before_match = state.pairs.get(pair_seal).unwrap().next_match;

        assert_eq!(
            state.preflight_begin_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
                3,
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before_read);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);
        assert_eq!(state.pairs.get(pair_seal).unwrap().next_match, before_match);
        assert_eq!(
            state.preflight_begin_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(2),
                3,
            ),
            Err(AsyncStateError::WrongType)
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before_read);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);

        let _read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(1),
                    lease(1, 3),
                )
                .unwrap(),
        );
        let before_read = endpoint_snapshot(&state, pair.readable);
        let before_write = endpoint_snapshot(&state, pair.writable);
        let before_phase = state.pairs.get(pair_seal).unwrap().phase;
        let before_match = state.pairs.get(pair_seal).unwrap().next_match;
        assert_eq!(
            state.preflight_begin_copy(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(1),
                5,
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before_read);
        assert_eq!(endpoint_snapshot(&state, pair.writable), before_write);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);
        assert_eq!(state.pairs.get(pair_seal).unwrap().next_match, before_match);

        let ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(1),
                    lease(2, 5),
                )
                .unwrap(),
        );
        assert_eq!(state.local_copy_progress(&ticket), Ok(3));

        let future = state.create_future_pair(ty(2)).unwrap();
        let before_future = endpoint_snapshot(&state, future.readable);
        assert_eq!(
            state.preflight_begin_copy(
                future.readable,
                EndpointKind::Future,
                EndpointDirection::Read,
                ty(2),
                0,
            ),
            Err(AsyncStateError::ProgressLimit)
        );
        assert_eq!(endpoint_snapshot(&state, future.readable), before_future);
        assert_eq!(
            state.preflight_begin_copy(
                future.readable,
                EndpointKind::Future,
                EndpointDirection::Read,
                ty(2),
                1,
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, future.readable), before_future);
    }

    #[test]
    fn cancel_preflight_is_read_only_for_waiting_matching_and_existing_events() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();
        let operation = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(1),
                    lease(1, 4),
                )
                .unwrap(),
        );
        let pair_seal = operation.pair;
        let before = endpoint_snapshot(&state, pair.readable);
        let before_phase = state.pairs.get(pair_seal).unwrap().phase;
        assert_eq!(
            state.preflight_cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(2),
            ),
            Err(AsyncStateError::WrongType)
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);

        let set = state.create_waitable_set().unwrap();
        state.join_waitable(pair.readable, set.raw()).unwrap();
        let joined = endpoint_snapshot(&state, pair.readable);
        assert_eq!(
            state.preflight_cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Err(AsyncStateError::CancelWhileJoined)
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), joined);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);
        state.join_waitable(pair.readable, 0).unwrap();

        let before = endpoint_snapshot(&state, pair.readable);
        assert_eq!(
            state.preflight_cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before);
        assert!(state.pairs.get(pair_seal).unwrap().phase == before_phase);
        let event = state
            .cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            )
            .unwrap();

        let pending = endpoint_snapshot(&state, pair.readable);
        let pending_phase = state.pairs.get(pair_seal).unwrap().phase;
        assert_eq!(
            state.preflight_cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), pending);
        assert!(state.pairs.get(pair_seal).unwrap().phase == pending_phase);
        let repeated = state
            .cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            )
            .unwrap();
        assert_eq!(event, repeated);
        assert_eq!(endpoint_snapshot(&state, pair.readable), pending);

        let (_, mut reclaim) = state.deliver_event(&event).unwrap();
        let delivered = endpoint_snapshot(&state, pair.readable);
        assert_eq!(
            state.preflight_cancel_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(1),
            ),
            Err(AsyncStateError::EventAlreadyDelivered)
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), delivered);
        state
            .reclaim_event(&mut reclaim, |_| Ok::<_, ()>(()))
            .unwrap();

        let pair = state.create_stream_pair(ty(3)).unwrap();
        let peer = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(3),
                    lease(2, 4),
                )
                .unwrap(),
        );
        let _ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(3),
                    lease(3, 4),
                )
                .unwrap(),
        );
        let before_read = endpoint_snapshot(&state, pair.readable);
        let before_write = endpoint_snapshot(&state, pair.writable);
        let before_phase = state.pairs.get(peer.pair).unwrap().phase;
        assert_eq!(
            state.preflight_cancel_copy(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(3),
            ),
            Ok(())
        );
        assert_eq!(endpoint_snapshot(&state, pair.readable), before_read);
        assert_eq!(endpoint_snapshot(&state, pair.writable), before_write);
        assert!(state.pairs.get(peer.pair).unwrap().phase == before_phase);
        let cancelled = state
            .cancel_copy(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(3),
            )
            .unwrap();
        assert!(
            state.pairs.get(peer.pair).unwrap().phase
                == PairPhase::Waiting(OpRef {
                    endpoint: peer.endpoint,
                    operation: peer.operation,
                })
        );
        reclaim_ok(&mut state, &cancelled);
    }

    #[test]
    fn local_stream_commit_and_reclaim_are_two_phase_and_exact() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();
        let read_op = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(1),
                    lease(1, 3),
                )
                .unwrap(),
        );
        let mut ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(1),
                    lease(2, 5),
                )
                .unwrap(),
        );
        assert_eq!(
            state.commit_local_copy(&mut ticket, 4, |_, _, _| Ok::<_, ()>(())),
            Err(CommitError::State(AsyncStateError::ProgressLimit))
        );
        assert_eq!(
            state.commit_local_copy(&mut ticket, 3, |source, target, progress| {
                assert_eq!((source.slot(), target.slot(), progress), (2, 1, 3));
                Err::<(), _>(7_u8)
            }),
            Err(CommitError::Operation(7))
        );
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Copying
        );

        let write_event = state
            .commit_local_copy(&mut ticket, 3, |source, target, progress| {
                assert_eq!((source.elements(), target.elements(), progress), (5, 3, 3));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(
            state.prepare_host_copy(
                &HostEndpointAuthority {
                    state_id: state.id,
                    pair: read_op.pair,
                    kind: EndpointKind::Stream,
                    direction: EndpointDirection::Write,
                    value_type: ty(1),
                    active: true,
                },
                &read_op,
            ),
            Err(AsyncStateError::AuthorityConsumed)
        ));

        let (event, mut reclaim) = state.deliver_event(&write_event).unwrap();
        assert_eq!(
            unpack_stream_copy_result(event.p2).unwrap(),
            StreamCopyResult {
                result: CopyResult::Completed,
                progress: 3,
            }
        );
        assert_eq!(
            state.reclaim_event(&mut reclaim, |_| Err::<(), _>(9_u8)),
            Err(ReclaimError::Operation(9))
        );
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Copying
        );
        state
            .reclaim_event(&mut reclaim, |lease| {
                assert_eq!(lease.slot(), 2);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Idle
        );

        let read_event = state.event_token(OpRef {
            endpoint: read_op.endpoint,
            operation: read_op.operation,
        });
        let read_event = read_event.unwrap();
        let event = reclaim_ok(&mut state, &read_event);
        assert_eq!(event.p1, pair.readable.raw());
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Idle
        );
    }

    #[test]
    fn local_copy_progress_revalidates_the_whole_rendezvous() {
        let mut state = AsyncState::new(limits()).unwrap();
        let other = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(1)).unwrap();
        let _read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(1),
                    lease(1, 3),
                )
                .unwrap(),
        );
        let mut ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(1),
                    lease(2, 5),
                )
                .unwrap(),
        );

        let before_read = state.endpoint_info(pair.readable).unwrap();
        let before_write = state.endpoint_info(pair.writable).unwrap();
        assert_eq!(state.local_copy_progress(&ticket), Ok(3));
        assert_eq!(state.endpoint_info(pair.readable), Ok(before_read));
        assert_eq!(state.endpoint_info(pair.writable), Ok(before_write));
        assert_eq!(
            other.local_copy_progress(&ticket),
            Err(AsyncStateError::StaleOperation)
        );

        let current = ticket.current;
        ticket.current = OpRef {
            endpoint: current.endpoint,
            operation: NonZeroU64::new(current.operation.get() + 1).unwrap(),
        };
        assert_eq!(
            state.local_copy_progress(&ticket),
            Err(AsyncStateError::PairInvariant)
        );
        ticket.current = current;

        state
            .endpoint_by_seal_mut(ticket.read.endpoint)
            .unwrap()
            .direction = EndpointDirection::Write;
        assert_eq!(
            state.local_copy_progress(&ticket),
            Err(AsyncStateError::PairInvariant)
        );
        state
            .endpoint_by_seal_mut(ticket.read.endpoint)
            .unwrap()
            .direction = EndpointDirection::Read;

        let operation = state
            .endpoint_by_seal(ticket.write.endpoint)
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .operation;
        state
            .endpoint_by_seal_mut(ticket.write.endpoint)
            .unwrap()
            .active
            .as_mut()
            .unwrap()
            .operation = NonZeroU64::new(operation.get() + 1).unwrap();
        assert_eq!(
            state.local_copy_progress(&ticket),
            Err(AsyncStateError::StaleOperation)
        );
        state
            .endpoint_by_seal_mut(ticket.write.endpoint)
            .unwrap()
            .active
            .as_mut()
            .unwrap()
            .operation = operation;

        assert_eq!(state.local_copy_progress(&ticket), Ok(3));
        state
            .commit_local_copy(&mut ticket, 3, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(
            state.local_copy_progress(&ticket),
            Err(AsyncStateError::StaleOperation)
        );
    }

    #[test]
    fn abort_all_copies_moves_every_lease_and_invalidates_late_authority() {
        let mut state = AsyncState::new(limits()).unwrap();

        let (host_readable, host_authority) = state
            .insert_host_readable(EndpointKind::Stream, ty(20))
            .unwrap();
        let host_operation = blocked(
            state
                .begin_copy(
                    host_readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(20),
                    lease(1, 4),
                )
                .unwrap(),
        );
        let mut host_ticket = state
            .prepare_host_copy(&host_authority, &host_operation)
            .unwrap();

        let matching = state.create_stream_pair(ty(21)).unwrap();
        let _matching_read = blocked(
            state
                .begin_copy(
                    matching.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(21),
                    lease(2, 3),
                )
                .unwrap(),
        );
        let matching_ticket = local(
            state
                .begin_copy(
                    matching.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(21),
                    lease(3, 5),
                )
                .unwrap(),
        );

        let dropped = state.create_stream_pair(ty(22)).unwrap();
        state
            .drop_endpoint(
                dropped.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(22),
            )
            .unwrap();
        let dropped_event = ready(
            state
                .begin_copy(
                    dropped.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(22),
                    lease(4, 2),
                )
                .unwrap(),
        );
        let (_, mut dropped_reclaim) = state.deliver_event(&dropped_event).unwrap();

        let completed_stream = state.create_stream_pair(ty(23)).unwrap();
        let _completed_read = blocked(
            state
                .begin_copy(
                    completed_stream.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(23),
                    lease(5, 2),
                )
                .unwrap(),
        );
        let mut completed_stream_ticket = local(
            state
                .begin_copy(
                    completed_stream.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(23),
                    lease(6, 2),
                )
                .unwrap(),
        );
        let old_stream_event = state
            .commit_local_copy(&mut completed_stream_ticket, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();

        let completed_future = state.create_future_pair(ty(24)).unwrap();
        let _completed_future_read = blocked(
            state
                .begin_copy(
                    completed_future.readable,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(24),
                    lease(7, 1),
                )
                .unwrap(),
        );
        let mut completed_future_ticket = local(
            state
                .begin_copy(
                    completed_future.writable,
                    EndpointKind::Future,
                    EndpointDirection::Write,
                    ty(24),
                    lease(8, 1),
                )
                .unwrap(),
        );
        let future_event = state
            .commit_local_copy(&mut completed_future_ticket, 1, |_, _, _| Ok::<_, ()>(()))
            .unwrap();

        let mut released = [0_u32; 8];
        let mut released_len = 0;
        state.abort_all_copies(|lease| {
            released[released_len] = lease.slot();
            released_len += 1;
        });
        assert_eq!(released_len, released.len());
        released.sort_unstable();
        assert_eq!(released, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(state
            .pairs
            .slots
            .iter()
            .filter_map(|slot| slot.value.as_ref())
            .all(|pair| pair.phase == PairPhase::Idle));

        for endpoint in [
            host_readable,
            matching.readable,
            matching.writable,
            completed_stream.readable,
            completed_stream.writable,
            completed_future.readable,
            completed_future.writable,
        ] {
            assert!(!state.endpoint_info(endpoint).unwrap().has_pending_event);
        }
        assert_eq!(
            state.endpoint_info(host_readable).unwrap().copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state.endpoint_info(matching.readable).unwrap().copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state.endpoint_info(matching.writable).unwrap().copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state.endpoint_info(dropped.readable).unwrap().copy_state,
            CopyState::Done
        );
        assert_eq!(
            state
                .endpoint_info(completed_stream.readable)
                .unwrap()
                .copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state
                .endpoint_info(completed_stream.writable)
                .unwrap()
                .copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state
                .endpoint_info(completed_future.readable)
                .unwrap()
                .copy_state,
            CopyState::Done
        );
        assert_eq!(
            state
                .endpoint_info(completed_future.writable)
                .unwrap()
                .copy_state,
            CopyState::Done
        );

        assert_eq!(
            state.local_copy_progress(&matching_ticket),
            Err(AsyncStateError::StaleOperation)
        );
        assert_eq!(
            state.commit_host_copy(
                &mut host_ticket,
                CopyResult::Completed,
                4,
                |_, _| Ok::<_, ()>(()),
            ),
            Err(CommitError::State(AsyncStateError::StaleOperation))
        );
        assert_eq!(
            state
                .reclaim_event(&mut dropped_reclaim, |_| Ok::<_, ()>(()))
                .err(),
            Some(ReclaimError::State(AsyncStateError::StaleEvent))
        );
        assert_eq!(
            state.deliver_event(&old_stream_event).err(),
            Some(AsyncStateError::NoPendingEvent)
        );
        assert_eq!(
            state.deliver_event(&future_event).err(),
            Some(AsyncStateError::NoPendingEvent)
        );

        let mut released_again = 0;
        state.abort_all_copies(|_| released_again += 1);
        assert_eq!(released_again, 0);

        let new_host_operation = blocked(
            state
                .begin_copy(
                    host_readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(20),
                    lease(9, 4),
                )
                .unwrap(),
        );
        assert_ne!(new_host_operation.operation, host_operation.operation);
        assert_eq!(
            state
                .prepare_host_copy(&host_authority, &host_operation)
                .err(),
            Some(AsyncStateError::StaleOperation)
        );
        assert!(state
            .prepare_host_copy(&host_authority, &new_host_operation)
            .is_ok());

        let _new_read = blocked(
            state
                .begin_copy(
                    completed_stream.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(23),
                    lease(10, 2),
                )
                .unwrap(),
        );
        let mut new_match = local(
            state
                .begin_copy(
                    completed_stream.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(23),
                    lease(11, 2),
                )
                .unwrap(),
        );
        let _new_stream_event = state
            .commit_local_copy(&mut new_match, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(
            state.deliver_event(&old_stream_event).err(),
            Some(AsyncStateError::StaleEvent)
        );
    }

    #[test]
    fn abort_all_copies_can_resume_after_a_cleanup_unwind_without_duplication() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(25)).unwrap();
        let _read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(25),
                    lease(1, 2),
                )
                .unwrap(),
        );
        let ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(25),
                    lease(2, 2),
                )
                .unwrap(),
        );

        let mut released = [0_u32; 2];
        let mut released_len = 0;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            state.abort_all_copies(|lease| {
                released[released_len] = lease.slot();
                released_len += 1;
                panic!("simulated infallible cleanup contract violation");
            });
        }));
        assert!(unwind.is_err());
        assert_eq!(
            state.local_copy_progress(&ticket),
            Err(AsyncStateError::StaleOperation)
        );
        state.abort_all_copies(|lease| {
            released[released_len] = lease.slot();
            released_len += 1;
        });
        assert_eq!(released_len, released.len());
        released.sort_unstable();
        assert_eq!(released, [1, 2]);
        assert!(state
            .pairs
            .slots
            .iter()
            .filter_map(|slot| slot.value.as_ref())
            .all(|pair| pair.phase == PairPhase::Idle));
    }

    #[test]
    fn future_completes_both_ends_once_and_writer_can_then_drop() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_future_pair(ty(2)).unwrap();
        let read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(2),
                    lease(1, 1),
                )
                .unwrap(),
        );
        let mut ticket = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Future,
                    EndpointDirection::Write,
                    ty(2),
                    lease(2, 1),
                )
                .unwrap(),
        );
        let write_event = state
            .commit_local_copy(&mut ticket, 1, |_, _, n| {
                assert_eq!(n, 1);
                Ok::<_, ()>(())
            })
            .unwrap();
        let read_event = state
            .event_token(OpRef {
                endpoint: read.endpoint,
                operation: read.operation,
            })
            .unwrap();
        assert_eq!(
            reclaim_ok(&mut state, &write_event).p2,
            CopyResult::Completed as u32
        );
        assert_eq!(
            reclaim_ok(&mut state, &read_event).p2,
            CopyResult::Completed as u32
        );
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Done
        );
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Done
        );
        state
            .drop_endpoint(
                pair.writable,
                EndpointKind::Future,
                EndpointDirection::Write,
                ty(2),
            )
            .unwrap();
    }

    #[test]
    fn host_readables_pair_is_atomic_and_preserves_exact_shapes() {
        let mut state = AsyncState::new(limits()).unwrap();
        let bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(30)),
                (EndpointKind::Future, ty(31)),
            )
            .unwrap();
        let HostReadableBindingsPair {
            first:
                HostReadableBinding {
                    guest: stream,
                    host: stream_host,
                },
            second:
                HostReadableBinding {
                    guest: future,
                    host: future_host,
                },
            ..
        } = bindings;

        assert_eq!(state.pairs.live, 2);
        assert_eq!(state.handles.live, 2);
        assert_eq!(
            state.endpoint_info(stream).unwrap(),
            EndpointInfo {
                kind: EndpointKind::Stream,
                direction: EndpointDirection::Read,
                value_type: ty(30),
                copy_state: CopyState::Idle,
                has_pending_event: false,
                event_delivered: false,
                joined_set: None,
            }
        );
        assert_eq!(stream_host.kind(), EndpointKind::Stream);
        assert_eq!(stream_host.direction(), EndpointDirection::Write);
        assert_eq!(stream_host.value_type(), ty(30));
        assert_eq!(
            state.endpoint_info(future).unwrap(),
            EndpointInfo {
                kind: EndpointKind::Future,
                direction: EndpointDirection::Read,
                value_type: ty(31),
                copy_state: CopyState::Idle,
                has_pending_event: false,
                event_delivered: false,
                joined_set: None,
            }
        );
        assert_eq!(future_host.kind(), EndpointKind::Future);
        assert_eq!(future_host.direction(), EndpointDirection::Write);
        assert_eq!(future_host.value_type(), ty(31));
    }

    #[test]
    fn host_readables_pair_rolls_back_a_second_commit_failure() {
        let mut state = AsyncState::new(limits()).unwrap();

        // Pre-reserve the exact storage that the batch will use, then corrupt
        // only its second free slot's generation. The first insert commits;
        // the second must fail while constructing its seal.
        state.handles.prepare_insert(2).unwrap();
        state.handles.slots.push(Slot {
            generation: 1,
            value: None,
            retired: false,
        });
        state.handles.slots.push(Slot {
            generation: 0,
            value: None,
            retired: false,
        });

        assert!(matches!(
            state.insert_host_readables_pair(
                (EndpointKind::Stream, ty(32)),
                (EndpointKind::Future, ty(33)),
            ),
            Err(AsyncStateError::GenerationExhausted)
        ));
        assert_eq!(state.pairs.live, 0);
        assert_eq!(state.handles.live, 0);
        assert!(state.pairs.slots.iter().all(|slot| slot.value.is_none()));
        assert!(state.handles.slots.iter().all(|slot| slot.value.is_none()));

        // Repair only the deliberately malformed, pre-existing slot. The
        // failed aggregate retained all of its logical table capacity.
        state.handles.slots[1].generation = 1;
        state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(32)),
                (EndpointKind::Future, ty(33)),
            )
            .unwrap();
        assert_eq!(state.pairs.live, 2);
        assert_eq!(state.handles.live, 2);
    }

    #[test]
    fn host_readables_pair_preflight_failure_consumes_no_capacity() {
        let mut state = AsyncState::new(AsyncStateLimits {
            handles: 2,
            pairs: 1,
            tasks: 1,
            waitables_per_set: 1,
        })
        .unwrap();

        assert!(matches!(
            state.insert_host_readables_pair(
                (EndpointKind::Stream, ty(34)),
                (EndpointKind::Future, ty(35)),
            ),
            Err(AsyncStateError::PairTableFull)
        ));
        assert_eq!(state.pairs.live, 0);
        assert_eq!(state.handles.live, 0);

        state
            .insert_host_readable(EndpointKind::Stream, ty(34))
            .unwrap();
        assert_eq!(state.pairs.live, 1);
        assert_eq!(state.handles.live, 1);
    }

    #[test]
    fn discard_host_readables_pair_consumes_the_exact_idle_aggregate() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(40)),
                (EndpointKind::Future, ty(41)),
            )
            .unwrap();
        let first = bindings.first.guest;
        let second = bindings.second.guest;

        state.discard_host_readables_pair(&mut bindings).unwrap();

        assert_eq!(state.handles.live, 0);
        assert_eq!(state.pairs.live, 0);
        assert_eq!(
            state.endpoint_info(first),
            Err(AsyncStateError::StaleHandle)
        );
        assert_eq!(
            state.endpoint_info(second),
            Err(AsyncStateError::StaleHandle)
        );
        assert!(!bindings.first.host.active);
        assert!(!bindings.second.host.active);
        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::AuthorityConsumed)
        );
    }

    #[test]
    fn discard_host_readables_pair_rejects_reordering_and_mixed_aggregates() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut first = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(42)),
                (EndpointKind::Future, ty(43)),
            )
            .unwrap();
        let mut second = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(44)),
                (EndpointKind::Future, ty(45)),
            )
            .unwrap();
        let handles = [
            first.first.guest,
            first.second.guest,
            second.first.guest,
            second.second.guest,
        ];
        let snapshots = handles.map(|handle| endpoint_snapshot(&state, handle));

        core::mem::swap(&mut first.first, &mut first.second);
        assert_eq!(
            state.discard_host_readables_pair(&mut first),
            Err(AsyncStateError::PairInvariant)
        );
        core::mem::swap(&mut first.first, &mut first.second);

        core::mem::swap(&mut first.second, &mut second.second);
        assert_eq!(
            state.discard_host_readables_pair(&mut first),
            Err(AsyncStateError::PairInvariant)
        );
        assert_eq!(
            state.discard_host_readables_pair(&mut second),
            Err(AsyncStateError::PairInvariant)
        );
        assert_eq!(state.handles.live, 4);
        assert_eq!(state.pairs.live, 4);
        for (handle, snapshot) in handles.into_iter().zip(snapshots) {
            assert_eq!(endpoint_snapshot(&state, handle), snapshot);
        }
        assert!(first.first.host.active);
        assert!(first.second.host.active);
        assert!(second.first.host.active);
        assert!(second.second.host.active);

        core::mem::swap(&mut first.second, &mut second.second);
        state.discard_host_readables_pair(&mut first).unwrap();
        state.discard_host_readables_pair(&mut second).unwrap();
    }

    #[test]
    fn discard_host_readables_pair_busy_or_joined_second_is_zero_mutation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(46)),
                (EndpointKind::Future, ty(47)),
            )
            .unwrap();
        let operation = blocked(
            state
                .begin_copy(
                    bindings.first.guest,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(46),
                    lease(1, 4),
                )
                .unwrap(),
        );
        let busy_first = endpoint_snapshot(&state, bindings.first.guest);
        let idle_second = endpoint_snapshot(&state, bindings.second.guest);
        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::EndpointBusy)
        );
        assert_eq!(endpoint_snapshot(&state, bindings.first.guest), busy_first);
        assert_eq!(
            endpoint_snapshot(&state, bindings.second.guest),
            idle_second
        );
        assert!(bindings.first.host.active);
        assert!(bindings.second.host.active);

        let cancelled = state
            .cancel_copy(
                bindings.first.guest,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(46),
            )
            .unwrap();
        reclaim_ok(&mut state, &cancelled);
        assert!(operation.operation.get() > 0);

        let set = state.create_waitable_set().unwrap();
        state
            .join_waitable(bindings.second.guest, set.raw())
            .unwrap();
        let unjoined_first = endpoint_snapshot(&state, bindings.first.guest);
        let joined_second = endpoint_snapshot(&state, bindings.second.guest);
        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::TransferWhileJoined)
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.first.guest),
            unjoined_first
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.second.guest),
            joined_second
        );
        assert!(bindings.first.host.active);
        assert!(bindings.second.host.active);

        state.join_waitable(bindings.second.guest, 0).unwrap();
        state.discard_host_readables_pair(&mut bindings).unwrap();
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn discard_host_readables_pair_rejects_stale_aba_without_touching_replacement() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(48)),
                (EndpointKind::Future, ty(49)),
            )
            .unwrap();
        let stale = bindings.first.guest;
        state
            .drop_endpoint(stale, EndpointKind::Stream, EndpointDirection::Read, ty(48))
            .unwrap();
        let replacement = state.create_stream_pair(ty(50)).unwrap();
        assert_eq!(replacement.readable.raw(), stale.raw());
        assert_ne!(replacement.readable.generation(), stale.generation());
        let replacement_snapshot = endpoint_snapshot(&state, replacement.readable);
        let second_snapshot = endpoint_snapshot(&state, bindings.second.guest);
        let handles_live = state.handles.live;
        let pairs_live = state.pairs.live;

        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::StaleHandle)
        );
        assert_eq!(state.handles.live, handles_live);
        assert_eq!(state.pairs.live, pairs_live);
        assert_eq!(
            endpoint_snapshot(&state, replacement.readable),
            replacement_snapshot
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.second.guest),
            second_snapshot
        );
        assert!(bindings.first.host.active);
        assert!(bindings.second.host.active);
    }

    #[test]
    fn discard_host_readables_pair_second_validation_failure_preserves_first() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(51)),
                (EndpointKind::Future, ty(52)),
            )
            .unwrap();
        let impostor = state.create_future_pair(ty(52)).unwrap();
        let original_second = bindings.second.guest;
        bindings.second.guest = impostor.readable;
        let first_snapshot = endpoint_snapshot(&state, bindings.first.guest);
        let second_snapshot = endpoint_snapshot(&state, original_second);
        let impostor_snapshot = endpoint_snapshot(&state, impostor.readable);

        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::PairInvariant)
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.first.guest),
            first_snapshot
        );
        assert_eq!(endpoint_snapshot(&state, original_second), second_snapshot);
        assert_eq!(
            endpoint_snapshot(&state, impostor.readable),
            impostor_snapshot
        );
        assert!(bindings.first.host.active);
        assert!(bindings.second.host.active);

        bindings.second.guest = original_second;
        state.discard_host_readables_pair(&mut bindings).unwrap();
    }

    #[test]
    fn discard_host_readables_pair_rejects_a_completed_future() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut bindings = state
            .insert_host_readables_pair(
                (EndpointKind::Stream, ty(53)),
                (EndpointKind::Future, ty(54)),
            )
            .unwrap();
        let operation = blocked(
            state
                .begin_copy(
                    bindings.second.guest,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(54),
                    lease(1, 1),
                )
                .unwrap(),
        );
        let mut ticket = state
            .prepare_host_copy(&bindings.second.host, &operation)
            .unwrap();
        let event = state
            .commit_host_copy(&mut ticket, CopyResult::Completed, 1, |_, progress| {
                assert_eq!(progress, 1);
                Ok::<_, ()>(())
            })
            .unwrap();
        reclaim_ok(&mut state, &event);
        let first_snapshot = endpoint_snapshot(&state, bindings.first.guest);
        let future_snapshot = endpoint_snapshot(&state, bindings.second.guest);

        assert_eq!(
            state.discard_host_readables_pair(&mut bindings),
            Err(AsyncStateError::EndpointBusy)
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.first.guest),
            first_snapshot
        );
        assert_eq!(
            endpoint_snapshot(&state, bindings.second.guest),
            future_snapshot
        );
        assert!(bindings.first.host.active);
        assert!(bindings.second.host.active);
    }

    #[test]
    fn host_copy_progress_limit_revalidates_stale_and_committed_tickets() {
        let mut state = AsyncState::new(limits()).unwrap();
        let (readable, authority) = state
            .insert_host_readable(EndpointKind::Stream, ty(36))
            .unwrap();
        let operation = blocked(
            state
                .begin_copy(
                    readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(36),
                    lease(1, 7),
                )
                .unwrap(),
        );
        let mut ticket = state.prepare_host_copy(&authority, &operation).unwrap();
        assert_eq!(state.host_copy_progress_limit(&ticket), Ok(7));
        let event = state
            .commit_host_copy(&mut ticket, CopyResult::Completed, 4, |_, progress| {
                assert_eq!(progress, 4);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            state.host_copy_progress_limit(&ticket),
            Err(AsyncStateError::StaleOperation)
        );
        reclaim_ok(&mut state, &event);

        let (readable, authority) = state
            .insert_host_readable(EndpointKind::Stream, ty(37))
            .unwrap();
        let operation = blocked(
            state
                .begin_copy(
                    readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(37),
                    lease(2, 5),
                )
                .unwrap(),
        );
        let ticket = state.prepare_host_copy(&authority, &operation).unwrap();
        assert_eq!(state.host_copy_progress_limit(&ticket), Ok(5));
        let cancelled = state
            .cancel_copy(
                readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(37),
            )
            .unwrap();
        assert_eq!(
            state.host_copy_progress_limit(&ticket),
            Err(AsyncStateError::StaleOperation)
        );
        reclaim_ok(&mut state, &cancelled);
    }

    #[test]
    fn reactive_host_completion_is_exact_and_late_completion_cannot_hit_restart() {
        let mut state = AsyncState::new(limits()).unwrap();
        let (readable, authority) = state
            .insert_host_readable(EndpointKind::Stream, ty(3))
            .unwrap();
        let operation_a = blocked(
            state
                .begin_copy(
                    readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(3),
                    lease(1, 8),
                )
                .unwrap(),
        );
        let cancel_event = state
            .cancel_copy(
                readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(3),
            )
            .unwrap();
        assert!(matches!(
            state.prepare_host_copy(&authority, &operation_a),
            Err(AsyncStateError::StaleOperation)
        ));
        let cancelled = reclaim_ok(&mut state, &cancel_event);
        assert_eq!(
            unpack_stream_copy_result(cancelled.p2).unwrap().result,
            CopyResult::Cancelled
        );

        let operation_b = blocked(
            state
                .begin_copy(
                    readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(3),
                    lease(2, 8),
                )
                .unwrap(),
        );
        assert!(matches!(
            state.prepare_host_copy(&authority, &operation_a),
            Err(AsyncStateError::StaleOperation)
        ));
        let mut host = state.prepare_host_copy(&authority, &operation_b).unwrap();
        assert_eq!(
            state.commit_host_copy(&mut host, CopyResult::Completed, 9, |_, _| {
                Ok::<_, ()>(())
            }),
            Err(CommitError::State(AsyncStateError::ProgressLimit))
        );
        let event = state
            .commit_host_copy(&mut host, CopyResult::Completed, 4, |lease, n| {
                assert_eq!((lease.slot(), n), (2, 4));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            unpack_stream_copy_result(reclaim_ok(&mut state, &event).p2)
                .unwrap()
                .progress,
            4
        );
    }

    #[test]
    fn dropping_lifted_readable_wakes_exact_pending_writer_and_latches_drop() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(4)).unwrap();
        let mut readable = state
            .detach_readable(pair.readable, EndpointKind::Stream, ty(4))
            .unwrap();
        let write_a = blocked(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(4),
                    lease(1, 4),
                )
                .unwrap(),
        );
        state.drop_host_endpoint(&mut readable).unwrap();
        let event = state
            .event_token(OpRef {
                endpoint: write_a.endpoint,
                operation: write_a.operation,
            })
            .unwrap();
        assert_eq!(
            unpack_stream_copy_result(reclaim_ok(&mut state, &event).p2)
                .unwrap()
                .result,
            CopyResult::Dropped
        );
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Done
        );
        let failure = state
            .begin_copy(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(4),
                lease(2, 1),
            )
            .unwrap_err();
        let (error, returned) = failure.into_parts();
        assert_eq!(error, AsyncStateError::EndpointDone);
        assert_eq!((returned.registry(), returned.slot()), (1, 2));
        assert_eq!((returned.generation(), returned.elements()), (1, 1));
    }

    #[test]
    fn drop_rejects_copying_and_future_writer_before_done_without_mutation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(5)).unwrap();
        let _operation = blocked(
            state
                .begin_copy(
                    stream.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(5),
                    lease(1, 1),
                )
                .unwrap(),
        );
        assert_eq!(
            state.drop_endpoint(
                stream.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(5),
            ),
            Err(AsyncStateError::DropWhileCopying)
        );
        assert!(state.endpoint_info(stream.readable).is_ok());

        let future = state.create_future_pair(ty(6)).unwrap();
        assert_eq!(
            state.drop_endpoint(
                future.writable,
                EndpointKind::Future,
                EndpointDirection::Write,
                ty(6),
            ),
            Err(AsyncStateError::FutureWritableNotDone)
        );
        assert!(state.endpoint_info(future.writable).is_ok());
    }

    #[test]
    fn zero_length_stream_cases_preserve_the_pinned_pending_side() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(7)).unwrap();
        let write = blocked(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(7),
                    lease(1, 3),
                )
                .unwrap(),
        );
        let empty_read = ready(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(7),
                    lease(2, 0),
                )
                .unwrap(),
        );
        assert_eq!(
            unpack_stream_copy_result(reclaim_ok(&mut state, &empty_read).p2)
                .unwrap()
                .progress,
            0
        );
        let write_ref = OpRef {
            endpoint: write.endpoint,
            operation: write.operation,
        };
        assert!(state.active_for(write_ref).is_ok());

        let mut match_ticket = local(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(7),
                    lease(3, 2),
                )
                .unwrap(),
        );
        state
            .commit_local_copy(&mut match_ticket, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();

        let reverse = state.create_stream_pair(ty(7)).unwrap();
        let pending_read = blocked(
            state
                .begin_copy(
                    reverse.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(7),
                    lease(4, 3),
                )
                .unwrap(),
        );
        let empty_write = ready(
            state
                .begin_copy(
                    reverse.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(7),
                    lease(5, 0),
                )
                .unwrap(),
        );
        assert_eq!(
            unpack_stream_copy_result(reclaim_ok(&mut state, &empty_write).p2)
                .unwrap()
                .progress,
            0
        );
        assert!(state
            .active_for(OpRef {
                endpoint: pending_read.endpoint,
                operation: pending_read.operation,
            })
            .is_ok());
        let mut reverse_match = local(
            state
                .begin_copy(
                    reverse.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(7),
                    lease(6, 3),
                )
                .unwrap(),
        );
        state
            .commit_local_copy(&mut reverse_match, 3, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
    }

    #[test]
    fn local_match_abort_restores_peer_and_cancels_only_current_operation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(8)).unwrap();
        let read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(8),
                    lease(1, 4),
                )
                .unwrap(),
        );
        let mut first_match = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(8),
                    lease(2, 4),
                )
                .unwrap(),
        );
        let aborted = state.abort_local_copy(&mut first_match).unwrap();
        assert_eq!(
            unpack_stream_copy_result(reclaim_ok(&mut state, &aborted.cancelled).p2)
                .unwrap()
                .result,
            CopyResult::Cancelled
        );
        assert_eq!(aborted.peer.operation, read.operation);
        assert_eq!(
            state.abort_local_copy(&mut first_match).err(),
            Some(AsyncStateError::StaleOperation)
        );
        let mut second_match = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(8),
                    lease(3, 4),
                )
                .unwrap(),
        );
        state
            .commit_local_copy(&mut second_match, 4, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
    }

    #[test]
    fn handle_cancel_recovers_a_match_after_its_local_ticket_is_dropped() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(8)).unwrap();
        let original_peer = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(8),
                    lease(21, 4),
                )
                .unwrap(),
        );
        let abandoned = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(8),
                    lease(22, 4),
                )
                .unwrap(),
        );
        drop(abandoned);

        let cancelled = state
            .cancel_copy(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                ty(8),
            )
            .unwrap();
        let (event, mut reclaim) = state.deliver_event(&cancelled).unwrap();
        assert_eq!(
            unpack_stream_copy_result(event.p2).unwrap().result,
            CopyResult::Cancelled
        );
        state
            .reclaim_event(&mut reclaim, |lease| {
                assert_eq!(lease.slot(), 22);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Copying
        );
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Idle
        );

        let mut restarted = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(8),
                    lease(23, 4),
                )
                .unwrap(),
        );
        let write_event = state
            .commit_local_copy(&mut restarted, 4, |source, target, progress| {
                assert_eq!((source.slot(), target.slot(), progress), (23, 21, 4));
                Ok::<_, ()>(())
            })
            .unwrap();
        let read_event = state.pending_event(pair.readable).unwrap().unwrap();
        let (_, mut write_reclaim) = state.deliver_event(&write_event).unwrap();
        state
            .reclaim_event(&mut write_reclaim, |lease| {
                assert_eq!(lease.slot(), 23);
                Ok::<_, ()>(())
            })
            .unwrap();
        let (_, mut read_reclaim) = state.deliver_event(&read_event).unwrap();
        state
            .reclaim_event(&mut read_reclaim, |lease| {
                assert_eq!(lease.slot(), 21);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(original_peer.operation.get() > 0);
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().copy_state,
            CopyState::Idle
        );
        assert_eq!(
            state.endpoint_info(pair.writable).unwrap().copy_state,
            CopyState::Idle
        );
    }

    #[test]
    fn callback_wait_ticket_is_task_exact_and_membership_survives_delivery() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(9)).unwrap();
        let set = state.create_waitable_set().unwrap();
        state.join_waitable(pair.readable, set.raw()).unwrap();
        let task = state.create_task().unwrap();
        state.resolve_task_result(task).unwrap();
        let mut wait = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };
        assert!(matches!(
            state.resume_callback_wait(&mut wait),
            Ok(WaitResume::Pending)
        ));

        let read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(9),
                    lease(1, 2),
                )
                .unwrap(),
        );
        let mut matched = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(9),
                    lease(2, 2),
                )
                .unwrap(),
        );
        let write_event = state
            .commit_local_copy(&mut matched, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        reclaim_ok(&mut state, &write_event);
        let mut read_event = match state.resume_callback_wait(&mut wait).unwrap() {
            WaitResume::Ready(event) => event,
            _ => panic!("joined endpoint event not delivered"),
        };
        assert_eq!(read_event.state(), EventLeaseState::EndpointPending);
        assert_eq!(
            state.cancel_callback_wait(&mut wait),
            Err(AsyncStateError::StaleWait)
        );
        assert_eq!(
            finish_endpoint_lease(&mut state, &mut read_event).p1,
            pair.readable.raw()
        );
        assert_eq!(read_event.state(), EventLeaseState::Consumed);
        assert_eq!(
            state.endpoint_info(pair.readable).unwrap().joined_set,
            Some(set.raw())
        );
        assert_eq!(state.pending_event(pair.readable).unwrap(), None);
        assert!(read.operation.get() > 0);
        state.callback_exit(task).unwrap();
        state.drop_task(task).unwrap();
        state.join_waitable(pair.readable, 0).unwrap();
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn callback_wait_selects_cancellation_without_consuming_a_ready_endpoint() {
        let mut state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(9)).unwrap();
        let set = state.create_waitable_set().unwrap();
        state.join_waitable(pair.readable, set.raw()).unwrap();
        let task = state.create_task().unwrap();
        let mut wait = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };

        let read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(9),
                    lease(1, 2),
                )
                .unwrap(),
        );
        let mut matched = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(9),
                    lease(2, 2),
                )
                .unwrap(),
        );
        let write_event = state
            .commit_local_copy(&mut matched, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        reclaim_ok(&mut state, &write_event);

        state.request_task_cancel(task).unwrap();
        let mut cancellation = match state.resume_callback_wait(&mut wait).unwrap() {
            WaitResume::Ready(event) => event,
            WaitResume::Pending => panic!("ready cancellation did not wake callback"),
        };
        assert_eq!(cancellation.state(), EventLeaseState::TaskCancelled);
        assert_eq!(
            cancellation.take_task_cancelled(),
            Some(task_cancelled_event())
        );
        assert!(state.pending_event(pair.readable).unwrap().is_some());
        assert!(read.operation.get() > 0);

        state.acknowledge_task_cancel(task).unwrap();
        state.callback_exit(task).unwrap();
        state.drop_task(task).unwrap();

        let begin_task = state.create_task().unwrap();
        state.request_task_cancel(begin_task).unwrap();
        let mut begin_cancellation = match state.begin_callback_wait(begin_task, set).unwrap() {
            WaitBegin::Ready(event) => event,
            WaitBegin::Blocked { .. } => panic!("begin did not select ready cancellation first"),
        };
        assert_eq!(
            begin_cancellation.take_task_cancelled(),
            Some(task_cancelled_event())
        );
        assert!(state.pending_event(pair.readable).unwrap().is_some());
        state.acknowledge_task_cancel(begin_task).unwrap();
        state.callback_exit(begin_task).unwrap();
        state.drop_task(begin_task).unwrap();

        let successor = state.create_task().unwrap();
        let mut endpoint = match state.begin_callback_wait(successor, set).unwrap() {
            WaitBegin::Ready(event) => event,
            WaitBegin::Blocked { .. } => panic!("pending endpoint was consumed by cancellation"),
        };
        assert_eq!(endpoint.state(), EventLeaseState::EndpointPending);
        assert_eq!(
            finish_endpoint_lease(&mut state, &mut endpoint).p1,
            pair.readable.raw()
        );
        state.resolve_task_result(successor).unwrap();
        state.callback_exit(successor).unwrap();
        state.drop_task(successor).unwrap();
    }

    #[test]
    fn endpoint_event_lease_retries_delivery_and_reclaim_and_releases_once() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut wrong_state = AsyncState::new(limits()).unwrap();
        let pair = state.create_stream_pair(ty(9)).unwrap();
        let set = state.create_waitable_set().unwrap();
        state.join_waitable(pair.readable, set.raw()).unwrap();
        let task = state.create_task().unwrap();

        let _read = blocked(
            state
                .begin_copy(
                    pair.readable,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    ty(9),
                    lease(31, 2),
                )
                .unwrap(),
        );
        let mut matched = local(
            state
                .begin_copy(
                    pair.writable,
                    EndpointKind::Stream,
                    EndpointDirection::Write,
                    ty(9),
                    lease(32, 2),
                )
                .unwrap(),
        );
        let write_event = state
            .commit_local_copy(&mut matched, 2, |_, _, _| Ok::<_, ()>(()))
            .unwrap();
        reclaim_ok(&mut state, &write_event);
        let mut event = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Ready(event) => event,
            WaitBegin::Blocked { .. } => panic!("joined endpoint event was not selected"),
        };

        assert_eq!(event.state(), EventLeaseState::EndpointPending);
        assert_eq!(event.take_task_cancelled(), None);
        assert_eq!(event.state(), EventLeaseState::EndpointPending);
        assert_eq!(
            event.prepare_endpoint(&mut wrong_state),
            Err(AsyncStateError::WrongState)
        );
        assert_eq!(event.state(), EventLeaseState::EndpointPending);
        event.prepare_endpoint(&mut state).unwrap();
        assert_eq!(event.state(), EventLeaseState::EndpointDelivered);
        assert_eq!(
            event.prepare_endpoint(&mut state),
            Err(AsyncStateError::StaleEvent)
        );
        assert_eq!(
            event.finish_endpoint(&mut state, |_| Err::<(), _>(7_u8)),
            Err(ReclaimError::Operation(7))
        );
        assert_eq!(event.state(), EventLeaseState::EndpointDelivered);
        let delivered = event
            .finish_endpoint(&mut state, |buffer| {
                assert_eq!(buffer.slot(), 31);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(delivered.p1, pair.readable.raw());
        assert_eq!(event.state(), EventLeaseState::Consumed);
        assert_eq!(
            event.finish_endpoint(&mut state, |_| Ok::<_, ()>(())),
            Err(ReclaimError::State(AsyncStateError::AuthorityConsumed))
        );

        state.resolve_task_result(task).unwrap();
        state.callback_exit(task).unwrap();
        state.drop_task(task).unwrap();
    }

    #[test]
    fn task_cancellation_event_lease_rejects_endpoint_phases_and_consumes_once() {
        let mut state = AsyncState::new(limits()).unwrap();
        let task = state.create_task().unwrap();
        let set = state.create_waitable_set().unwrap();
        state.request_task_cancel(task).unwrap();
        let mut event = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Ready(event) => event,
            WaitBegin::Blocked { .. } => panic!("requested cancellation was not selected"),
        };

        assert_eq!(event.state(), EventLeaseState::TaskCancelled);
        assert_eq!(
            event.prepare_endpoint(&mut state),
            Err(AsyncStateError::StaleEvent)
        );
        assert_eq!(
            event.finish_endpoint(&mut state, |_| Ok::<_, ()>(())),
            Err(ReclaimError::State(AsyncStateError::StaleEvent))
        );
        assert_eq!(event.take_task_cancelled(), Some(task_cancelled_event()));
        assert_eq!(event.take_task_cancelled(), None);
        assert_eq!(event.state(), EventLeaseState::Consumed);
        assert_eq!(
            event.prepare_endpoint(&mut state),
            Err(AsyncStateError::AuthorityConsumed)
        );
        assert_eq!(
            event.finish_endpoint(&mut state, |_| Ok::<_, ()>(())),
            Err(ReclaimError::State(AsyncStateError::AuthorityConsumed))
        );

        state.acknowledge_task_cancel(task).unwrap();
        state.callback_exit(task).unwrap();
        state.drop_task(task).unwrap();
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn abort_task_rejects_a_live_wait_then_succeeds_after_ticket_cancellation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let task = state.create_task().unwrap();
        let set = state.create_waitable_set().unwrap();
        let mut wait = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };

        assert_eq!(state.abort_task(task), Err(AsyncStateError::AlreadyWaiting));
        assert!(
            state.task_info(task).unwrap().waiting,
            "failed abort must preserve the wait registration"
        );
        assert!(matches!(
            state.resume_callback_wait(&mut wait),
            Ok(WaitResume::Pending)
        ));
        state.cancel_callback_wait(&mut wait).unwrap();
        state.abort_task(task).unwrap();
        assert_eq!(state.task_info(task), Err(AsyncStateError::StaleHandle));
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn stale_wait_ticket_cannot_cancel_a_new_registration_on_the_same_set() {
        let mut state = AsyncState::new(limits()).unwrap();
        let task = state.create_task().unwrap();
        let set = state.create_waitable_set().unwrap();
        let mut old = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };
        state.cancel_callback_wait(&mut old).unwrap();
        let mut current = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };

        assert_eq!(
            state.cancel_callback_wait(&mut old),
            Err(AsyncStateError::StaleWait)
        );
        assert!(matches!(
            state.resume_callback_wait(&mut current),
            Ok(WaitResume::Pending)
        ));
        state.cancel_callback_wait(&mut current).unwrap();
        state.abort_task(task).unwrap();
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn callback_yield_delivers_requested_cancellation_exactly_once() {
        let mut state = AsyncState::new(limits()).unwrap();
        let task = state.create_task().unwrap();
        assert_eq!(state.callback_yield(task), Ok(none_event()));

        state.request_task_cancel(task).unwrap();
        assert_eq!(state.callback_yield(task), Ok(task_cancelled_event()));
        assert_eq!(
            state.task_info(task).unwrap().cancel,
            TaskCancelState::Delivered
        );
        assert_eq!(state.callback_yield(task), Ok(none_event()));

        state.acknowledge_task_cancel(task).unwrap();
        assert_eq!(state.callback_yield(task), Ok(none_event()));
        state.callback_exit(task).unwrap();
        state.drop_task(task).unwrap();
    }

    #[test]
    fn callback_yield_rejects_wrong_state_and_stale_task_seals() {
        let mut first = AsyncState::new(limits()).unwrap();
        let mut second = AsyncState::new(limits()).unwrap();
        let task = first.create_task().unwrap();
        assert_eq!(
            second.callback_yield(task),
            Err(AsyncStateError::WrongState)
        );

        first.resolve_task_result(task).unwrap();
        first.callback_exit(task).unwrap();
        first.drop_task(task).unwrap();
        assert_eq!(
            first.callback_yield(task),
            Err(AsyncStateError::StaleHandle)
        );
    }

    #[test]
    fn callback_yield_rejects_waiting_and_exited_callbacks() {
        let mut state = AsyncState::new(limits()).unwrap();
        let set = state.create_waitable_set().unwrap();
        let task = state.create_task().unwrap();
        let mut wait = match state.begin_callback_wait(task, set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };
        assert_eq!(
            state.callback_yield(task),
            Err(AsyncStateError::AlreadyWaiting)
        );

        state.cancel_callback_wait(&mut wait).unwrap();
        state.resolve_task_result(task).unwrap();
        state.callback_exit(task).unwrap();
        assert_eq!(
            state.callback_yield(task),
            Err(AsyncStateError::TaskAlreadyExited)
        );
        state.drop_task(task).unwrap();
        state.drop_waitable_set(set).unwrap();
    }

    #[test]
    fn task_return_clears_pending_and_delivered_yield_cancellation() {
        let mut state = AsyncState::new(limits()).unwrap();

        let pending = state.create_task().unwrap();
        state.request_task_cancel(pending).unwrap();
        state.resolve_task_result(pending).unwrap();
        assert_eq!(state.callback_yield(pending), Ok(none_event()));
        assert_eq!(
            state.task_info(pending).unwrap().cancel,
            TaskCancelState::None
        );
        state.callback_exit(pending).unwrap();
        state.drop_task(pending).unwrap();

        let delivered = state.create_task().unwrap();
        state.request_task_cancel(delivered).unwrap();
        assert_eq!(state.callback_yield(delivered), Ok(task_cancelled_event()));
        state.resolve_task_result(delivered).unwrap();
        assert_eq!(state.callback_yield(delivered), Ok(none_event()));
        assert_eq!(
            state.task_info(delivered).unwrap().cancel,
            TaskCancelState::None
        );
        state.callback_exit(delivered).unwrap();
        state.drop_task(delivered).unwrap();
    }

    #[test]
    fn cancellation_wakes_only_the_bound_task_and_ticket_epoch() {
        let mut state = AsyncState::new(limits()).unwrap();
        let set_a = state.create_waitable_set().unwrap();
        let set_b = state.create_waitable_set().unwrap();
        let task_a = state.create_task().unwrap();
        let task_b = state.create_task().unwrap();
        let mut wait_a = match state.begin_callback_wait(task_a, set_a).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            _ => panic!("unexpected ready"),
        };
        let mut wait_b = match state.begin_callback_wait(task_b, set_b).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            _ => panic!("unexpected ready"),
        };
        state.request_task_cancel(task_a).unwrap();
        let mut cancellation = match state.resume_callback_wait(&mut wait_a).unwrap() {
            WaitResume::Ready(event) => event,
            WaitResume::Pending => panic!("task cancellation did not wake its callback"),
        };
        assert_eq!(cancellation.state(), EventLeaseState::TaskCancelled);
        assert_eq!(
            cancellation.take_task_cancelled(),
            Some(Event {
                code: EventCode::TaskCancelled,
                p1: 0,
                p2: 0,
            })
        );
        assert_eq!(cancellation.state(), EventLeaseState::Consumed);
        assert!(matches!(
            state.resume_callback_wait(&mut wait_b),
            Ok(WaitResume::Pending)
        ));
        assert_eq!(
            state.resume_callback_wait(&mut wait_a).err(),
            Some(AsyncStateError::StaleWait)
        );
        state.acknowledge_task_cancel(task_a).unwrap();
        state.callback_exit(task_a).unwrap();
        state.drop_task(task_a).unwrap();

        state.cancel_callback_wait(&mut wait_b).unwrap();
        state.resolve_task_result(task_b).unwrap();
        state.callback_exit(task_b).unwrap();
        state.drop_task(task_b).unwrap();
    }

    #[test]
    fn task_return_supersedes_pending_and_delivered_cancellation() {
        let mut state = AsyncState::new(limits()).unwrap();

        let pending = state.create_task().unwrap();
        let pending_set = state.create_waitable_set().unwrap();
        state.request_task_cancel(pending).unwrap();
        state.resolve_task_result(pending).unwrap();
        assert_eq!(
            state.task_info(pending).unwrap(),
            TaskInfo {
                result: TaskResultState::Resolved,
                callback: TaskCallbackState::Running,
                cancel: TaskCancelState::None,
                waiting: false,
            }
        );
        let mut pending_wait = match state.begin_callback_wait(pending, pending_set).unwrap() {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("resolved task received a stale cancellation"),
        };
        state.cancel_callback_wait(&mut pending_wait).unwrap();
        state.callback_exit(pending).unwrap();
        state.drop_task(pending).unwrap();
        state.drop_waitable_set(pending_set).unwrap();

        let delivered = state.create_task().unwrap();
        let delivered_set = state.create_waitable_set().unwrap();
        let mut delivered_wait = match state.begin_callback_wait(delivered, delivered_set).unwrap()
        {
            WaitBegin::Blocked { ticket } => ticket,
            WaitBegin::Ready(_) => panic!("empty set became ready"),
        };
        state.request_task_cancel(delivered).unwrap();
        let mut cancellation = match state.resume_callback_wait(&mut delivered_wait).unwrap() {
            WaitResume::Ready(event) => event,
            WaitResume::Pending => panic!("task cancellation did not wake its callback"),
        };
        assert_eq!(
            cancellation.take_task_cancelled(),
            Some(task_cancelled_event())
        );
        state.resolve_task_result(delivered).unwrap();
        assert_eq!(
            state.task_info(delivered).unwrap().cancel,
            TaskCancelState::None
        );
        state.callback_exit(delivered).unwrap();
        state.drop_task(delivered).unwrap();
        state.drop_waitable_set(delivered_set).unwrap();
    }

    #[test]
    fn pair_detach_is_atomic_and_preserves_result_order() {
        let mut state = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(60)).unwrap();
        let future = state.create_future_pair(ty(61)).unwrap();
        let handles_live = state.handles.live;

        let (first, second) = state
            .detach_readables_pair(
                ReadableTransferRequest {
                    handle: stream.readable,
                    kind: EndpointKind::Stream,
                    value_type: ty(60),
                },
                ReadableTransferRequest {
                    handle: future.readable,
                    kind: EndpointKind::Future,
                    value_type: ty(61),
                },
            )
            .unwrap();

        assert_eq!(
            (first.kind(), first.value_type()),
            (EndpointKind::Stream, ty(60))
        );
        assert_eq!(
            (second.kind(), second.value_type()),
            (EndpointKind::Future, ty(61))
        );
        assert_eq!(state.handles.live, handles_live - 2);
        assert_eq!(
            state.endpoint_info(stream.readable),
            Err(AsyncStateError::StaleHandle)
        );
        assert_eq!(
            state.endpoint_info(future.readable),
            Err(AsyncStateError::StaleHandle)
        );
        assert!(state.endpoint_info(stream.writable).is_ok());
        assert!(state.endpoint_info(future.writable).is_ok());
    }

    #[test]
    fn pair_detach_duplicate_kind_and_type_failures_are_zero_mutation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(62)).unwrap();
        let future = state.create_future_pair(ty(63)).unwrap();
        let stream_request = ReadableTransferRequest {
            handle: stream.readable,
            kind: EndpointKind::Stream,
            value_type: ty(62),
        };
        let future_request = ReadableTransferRequest {
            handle: future.readable,
            kind: EndpointKind::Future,
            value_type: ty(63),
        };
        let stream_snapshot = endpoint_snapshot(&state, stream.readable);
        let future_snapshot = endpoint_snapshot(&state, future.readable);

        assert_eq!(
            state.detach_readables_pair(stream_request, stream_request),
            Err(AsyncStateError::DuplicateHandle)
        );
        assert_eq!(
            state.detach_readables_pair(
                stream_request,
                ReadableTransferRequest {
                    kind: EndpointKind::Stream,
                    ..future_request
                },
            ),
            Err(AsyncStateError::WrongEndpointKind)
        );
        assert_eq!(
            state.detach_readables_pair(
                stream_request,
                ReadableTransferRequest {
                    value_type: ty(64),
                    ..future_request
                },
            ),
            Err(AsyncStateError::WrongType)
        );
        assert_eq!(endpoint_snapshot(&state, stream.readable), stream_snapshot);
        assert_eq!(endpoint_snapshot(&state, future.readable), future_snapshot);
        assert_eq!(state.handles.live, 4);
    }

    #[test]
    fn pair_detach_foreign_second_handle_preserves_both_states() {
        let mut state = AsyncState::new(limits()).unwrap();
        let mut foreign = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(65)).unwrap();
        let future = foreign.create_future_pair(ty(66)).unwrap();
        let stream_snapshot = endpoint_snapshot(&state, stream.readable);
        let future_snapshot = endpoint_snapshot(&foreign, future.readable);

        assert_eq!(
            state.detach_readables_pair(
                ReadableTransferRequest {
                    handle: stream.readable,
                    kind: EndpointKind::Stream,
                    value_type: ty(65),
                },
                ReadableTransferRequest {
                    handle: future.readable,
                    kind: EndpointKind::Future,
                    value_type: ty(66),
                },
            ),
            Err(AsyncStateError::WrongState)
        );
        assert_eq!(endpoint_snapshot(&state, stream.readable), stream_snapshot);
        assert_eq!(
            endpoint_snapshot(&foreign, future.readable),
            future_snapshot
        );
    }

    #[test]
    fn pair_detach_busy_or_joined_second_is_zero_mutation() {
        let mut state = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(67)).unwrap();
        let future = state.create_future_pair(ty(68)).unwrap();
        let requests = (
            ReadableTransferRequest {
                handle: stream.readable,
                kind: EndpointKind::Stream,
                value_type: ty(67),
            },
            ReadableTransferRequest {
                handle: future.readable,
                kind: EndpointKind::Future,
                value_type: ty(68),
            },
        );
        let operation = blocked(
            state
                .begin_copy(
                    future.readable,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(68),
                    lease(1, 1),
                )
                .unwrap(),
        );
        let idle_first = endpoint_snapshot(&state, stream.readable);
        let busy_second = endpoint_snapshot(&state, future.readable);
        assert_eq!(
            state.detach_readables_pair(requests.0, requests.1),
            Err(AsyncStateError::EndpointBusy)
        );
        assert_eq!(endpoint_snapshot(&state, stream.readable), idle_first);
        assert_eq!(endpoint_snapshot(&state, future.readable), busy_second);
        let cancelled = state
            .cancel_copy(
                future.readable,
                EndpointKind::Future,
                EndpointDirection::Read,
                ty(68),
            )
            .unwrap();
        reclaim_ok(&mut state, &cancelled);
        assert!(operation.operation.get() > 0);

        let set = state.create_waitable_set().unwrap();
        state.join_waitable(future.readable, set.raw()).unwrap();
        let idle_first = endpoint_snapshot(&state, stream.readable);
        let joined_second = endpoint_snapshot(&state, future.readable);
        assert_eq!(
            state.detach_readables_pair(requests.0, requests.1),
            Err(AsyncStateError::TransferWhileJoined)
        );
        assert_eq!(endpoint_snapshot(&state, stream.readable), idle_first);
        assert_eq!(endpoint_snapshot(&state, future.readable), joined_second);
    }

    #[test]
    fn pair_detach_rejects_stale_aba_handle_without_touching_replacement() {
        let mut state = AsyncState::new(limits()).unwrap();
        let first = state.create_future_pair(ty(69)).unwrap();
        let obsolete = state.create_stream_pair(ty(70)).unwrap();
        state
            .drop_endpoint(
                obsolete.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                ty(70),
            )
            .unwrap();
        let replacement = state.create_stream_pair(ty(70)).unwrap();
        assert_eq!(obsolete.readable.raw(), replacement.readable.raw());
        assert_ne!(
            obsolete.readable.generation(),
            replacement.readable.generation()
        );
        let first_snapshot = endpoint_snapshot(&state, first.readable);
        let replacement_snapshot = endpoint_snapshot(&state, replacement.readable);

        assert_eq!(
            state.detach_readables_pair(
                ReadableTransferRequest {
                    handle: first.readable,
                    kind: EndpointKind::Future,
                    value_type: ty(69),
                },
                ReadableTransferRequest {
                    handle: obsolete.readable,
                    kind: EndpointKind::Stream,
                    value_type: ty(70),
                },
            ),
            Err(AsyncStateError::StaleHandle)
        );
        assert_eq!(endpoint_snapshot(&state, first.readable), first_snapshot);
        assert_eq!(
            endpoint_snapshot(&state, replacement.readable),
            replacement_snapshot
        );

        state
            .detach_readables_pair(
                ReadableTransferRequest {
                    handle: first.readable,
                    kind: EndpointKind::Future,
                    value_type: ty(69),
                },
                ReadableTransferRequest {
                    handle: replacement.readable,
                    kind: EndpointKind::Stream,
                    value_type: ty(70),
                },
            )
            .unwrap();
    }

    #[test]
    fn batch_detach_rolls_back_all_fields_then_preserves_order() {
        let mut state = AsyncState::new(limits()).unwrap();
        let stream = state.create_stream_pair(ty(10)).unwrap();
        let future = state.create_future_pair(ty(11)).unwrap();
        let busy = blocked(
            state
                .begin_copy(
                    future.readable,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(11),
                    lease(1, 1),
                )
                .unwrap(),
        );
        let requests = [
            ReadableTransferRequest {
                handle: stream.readable,
                kind: EndpointKind::Stream,
                value_type: ty(10),
            },
            ReadableTransferRequest {
                handle: future.readable,
                kind: EndpointKind::Future,
                value_type: ty(11),
            },
        ];
        assert_eq!(
            state.detach_readables_batch(&requests).err(),
            Some(AsyncStateError::EndpointBusy)
        );
        assert!(state.endpoint_info(stream.readable).is_ok());
        assert!(state.endpoint_info(future.readable).is_ok());
        let cancelled = state
            .cancel_copy(
                future.readable,
                EndpointKind::Future,
                EndpointDirection::Read,
                ty(11),
            )
            .unwrap();
        reclaim_ok(&mut state, &cancelled);
        assert!(busy.operation.get() > 0);
        assert_eq!(
            state
                .detach_readables_batch(&[requests[0], requests[0]])
                .err(),
            Some(AsyncStateError::DuplicateHandle)
        );
        assert!(state.endpoint_info(stream.readable).is_ok());

        let tokens = state.detach_readables_batch(&requests).unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(
            (tokens[0].kind(), tokens[0].value_type()),
            (EndpointKind::Stream, ty(10))
        );
        assert_eq!(
            (tokens[1].kind(), tokens[1].value_type()),
            (EndpointKind::Future, ty(11))
        );
        assert_eq!(
            state.endpoint_info(stream.readable),
            Err(AsyncStateError::StaleHandle)
        );
    }

    #[test]
    fn host_future_writer_drop_requires_completed_write() {
        let mut state = AsyncState::new(limits()).unwrap();
        let (readable, mut writer) = state
            .insert_host_readable(EndpointKind::Future, ty(12))
            .unwrap();
        assert_eq!(
            state.drop_host_endpoint(&mut writer),
            Err(AsyncStateError::FutureWritableNotDone)
        );
        let operation = blocked(
            state
                .begin_copy(
                    readable,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    ty(12),
                    lease(1, 1),
                )
                .unwrap(),
        );
        let mut host = state.prepare_host_copy(&writer, &operation).unwrap();
        assert_eq!(
            state.commit_host_copy(&mut host, CopyResult::Cancelled, 0, |_, _| {
                Ok::<_, ()>(())
            }),
            Err(CommitError::State(AsyncStateError::InvalidCopyResult))
        );
        let event = state
            .commit_host_copy(&mut host, CopyResult::Completed, 1, |_, n| {
                assert_eq!(n, 1);
                Ok::<_, ()>(())
            })
            .unwrap();
        reclaim_ok(&mut state, &event);
        state.drop_host_endpoint(&mut writer).unwrap();
    }
}

#[derive(Clone, Copy)]
enum BeginAction {
    Dropped,
    Wait,
    CompleteCurrentKeepPeer,
    CompletePeerWaitCurrent(OpRef),
    Match(OpRef),
}

struct PreparedBeginCopy {
    endpoint: Seal,
    pair: Seal,
    operation: NonZeroU64,
    next_operation: u64,
    action: BeginAction,
    original_phase: PairPhase,
}

enum CancelAction {
    Existing(EventToken),
    New {
        pair: Seal,
        original_phase: PairPhase,
        next_phase: PairPhase,
        generation: NonZeroU64,
        next_event: u64,
    },
}

struct PreparedCancelCopy {
    endpoint: Seal,
    operation: OpRef,
    action: CancelAction,
}

fn validate_endpoint(
    endpoint: &Endpoint,
    kind: EndpointKind,
    direction: EndpointDirection,
    value_type: AsyncValueTypeId,
) -> Result<(), AsyncStateError> {
    if endpoint.kind != kind {
        return Err(AsyncStateError::WrongEndpointKind);
    }
    if endpoint.direction != direction {
        return Err(AsyncStateError::WrongDirection);
    }
    if endpoint.value_type != value_type {
        return Err(AsyncStateError::WrongType);
    }
    Ok(())
}
