//! Inert, bounded Component Model resource-table state.
//!
//! Guest-visible handles are opaque identifiers, never encoded slot numbers or
//! generations. Reservations and ownership transfers are linear transactions:
//! every failed commit returns the reservation to the caller, while abandoning
//! an ownership transfer restores its source entry.

use alloc::vec::Vec;
use core::{
    fmt,
    marker::PhantomData,
    mem,
    sync::atomic::{AtomicU64, Ordering},
};
use vibeos_component_format::PROFILE_1_LIMITS;

static NEXT_TABLE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_CROSS_TABLE_BORROW_SCOPE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceTypeId(pub u32);

/// A host-bound wrapper around one untrusted guest resource integer.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceToken {
    table_identity: u64,
    encoded: u32,
}

impl fmt::Debug for ResourceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceToken(<opaque>)")
    }
}

impl ResourceToken {
    pub const fn guest_index(self) -> u32 {
        self.encoded
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ResourceError {
    TableFull = 1,
    InvalidReservation = 2,
    WrongInstance = 3,
    Stale = 4,
    WrongType = 5,
    NotOwned = 6,
    WrongScope = 7,
    GenerationExhausted = 8,
}

impl ResourceError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

struct Entry<A> {
    resource_type: ResourceTypeId,
    authority: A,
}

struct Slot<A> {
    reservation_nonce: Option<u64>,
    handle: Option<u32>,
    entry: Option<Entry<A>>,
    guest_owned: bool,
}

struct GuestBorrowAlias {
    scope_nonce: u64,
    handle: u32,
    slot: u16,
    resource_type: ResourceTypeId,
}

#[derive(Clone, Copy)]
struct GuestOwnMove {
    slot: u16,
    previous_handle: u32,
    next_handle: u32,
    previous_guest_owned: bool,
    next_guest_owned: bool,
}

/// Linear state for one Component call's guest-visible resource handles.
///
/// This type is crate-private because it deliberately does not borrow the
/// table: the synchronous executor must retain it across `Pending`. The only
/// constructors and consumers live in this module, and the executor always
/// closes it on success, trap, cancellation, and drop.
pub(crate) struct GuestCallResources {
    table_identity: u64,
    nonce: u64,
    own_moves: Vec<GuestOwnMove>,
    committed: bool,
}

/// A linear, opaque claim on one empty slot.
///
/// The reservation keeps the originating table mutably borrowed and rolls
/// itself back on drop. It intentionally implements neither `Clone` nor `Copy`;
/// forgetting to explicitly commit or roll back therefore cannot strand table
/// capacity during ordinary return or unwinding.
#[must_use = "a reservation must be committed or rolled back"]
pub struct Reservation<'table, A> {
    table: &'table mut ResourceTable<A>,
    slot: u16,
    nonce: u64,
    handle: u32,
    active: bool,
}

impl<A> fmt::Debug for Reservation<'_, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Reservation(<opaque>)")
    }
}

/// Failed direct insertion. The authority is returned intact.
#[must_use = "the returned authority must be recovered"]
pub struct InsertFailure<A> {
    error: ResourceError,
    authority: A,
}

impl<A> InsertFailure<A> {
    pub const fn error(&self) -> ResourceError {
        self.error
    }

    pub fn into_parts(self) -> (ResourceError, A) {
        (self.error, self.authority)
    }
}

impl<A> fmt::Debug for InsertFailure<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InsertFailure")
            .field("error", &self.error)
            .field("authority", &"<opaque>")
            .finish()
    }
}

/// Failed ownership move. Dropping the transfer restores its source, and this
/// error returns the target reservation for rollback at the table that made it.
#[must_use = "the returned reservation must be recovered"]
pub struct ReservationFailure<'table, A> {
    error: ResourceError,
    reservation: Reservation<'table, A>,
}

impl<'table, A> ReservationFailure<'table, A> {
    pub const fn error(&self) -> ResourceError {
        self.error
    }

    pub fn into_parts(self) -> (ResourceError, Reservation<'table, A>) {
        (self.error, self.reservation)
    }
}

impl<A> fmt::Debug for ReservationFailure<'_, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservationFailure")
            .field("error", &self.error)
            .field("reservation", &"<opaque>")
            .finish()
    }
}

pub struct Borrowed<'a, A> {
    authority: &'a A,
    resource_type: ResourceTypeId,
}

impl<A> fmt::Debug for Borrowed<'_, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BorrowedResource")
            .field("resource_type", &self.resource_type)
            .field("scope", &"<active>")
            .finish_non_exhaustive()
    }
}

impl<A> Borrowed<'_, A> {
    pub const fn resource_type(&self) -> ResourceTypeId {
        self.resource_type
    }

    pub fn with<R>(&self, operation: impl FnOnce(&A) -> R) -> R {
        operation(self.authority)
    }
}

/// An active dynamic borrow scope. Its fields are private and it can only be
/// created by `ResourceTable::with_borrow_scope`, so an integer cannot forge it.
pub struct BorrowScope<'table, A> {
    table: &'table ResourceTable<A>,
    nonce: u64,
}

impl<A> fmt::Debug for BorrowScope<'_, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BorrowScope(<active>)")
    }
}

impl<A> BorrowScope<'_, A> {
    pub fn with_borrow<R>(
        &self,
        token: ResourceToken,
        expected: ResourceTypeId,
        operation: impl for<'borrow> FnOnce(Borrowed<'borrow, A>) -> R,
    ) -> Result<R, ResourceError> {
        // Reading the nonce makes the active-scope proof explicit without ever
        // exposing it as a forgeable value.
        let _active_nonce = self.nonce;
        let entry = self
            .table
            .live_slot(token, expected)?
            .entry
            .as_ref()
            .ok_or(ResourceError::Stale)?;
        Ok(operation(Borrowed {
            authority: &entry.authority,
            resource_type: entry.resource_type,
        }))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CrossTableBorrowSeal {
    scope_nonce: u64,
    source_table_identity: u64,
    source_generation: u64,
    source_token: ResourceToken,
    source_type: ResourceTypeId,
    target_table_identity: u64,
    target_generation: u64,
    target_type: ResourceTypeId,
}

/// An opaque, non-owning alias branded for exactly one cross-table invocation.
///
/// The alias contains no guest handle and cannot be converted into a resource
/// token. Its fields are private, it implements neither `Clone` nor `Copy`, and
/// its invariant lifetime brand cannot escape the higher-ranked callback that
/// created it.
///
/// ```compile_fail
/// use vibeos_component_runtime::resource::{
///     CrossTableBorrowAlias, ResourceTable, ResourceToken, ResourceTypeId,
/// };
///
/// fn escape<'tables, A, B>(
///     source: &'tables ResourceTable<A>,
///     source_token: ResourceToken,
///     target: &'tables ResourceTable<B>,
/// ) -> CrossTableBorrowAlias<'tables> {
///     source
///         .with_cross_table_borrow(
///             source_token,
///             ResourceTypeId(1),
///             target,
///             ResourceTypeId(1),
///             |scope| scope.alias(),
///         )
///         .unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_runtime::resource::CrossTableBorrowAlias;
///
/// fn duplicate(alias: CrossTableBorrowAlias<'_>) {
///     let _: CrossTableBorrowAlias<'_> = Clone::clone(&alias);
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_runtime::resource::{CrossTableBorrowAlias, ResourceToken};
///
/// fn into_token(alias: CrossTableBorrowAlias<'_>) -> ResourceToken {
///     alias.into()
/// }
/// ```
#[must_use = "a cross-table borrow alias is usable only by its active scope"]
pub struct CrossTableBorrowAlias<'call> {
    seal: CrossTableBorrowSeal,
    // Mentioning the lifetime in both input and output position makes the
    // invocation brand invariant rather than a lifetime that can be widened.
    _brand: PhantomData<fn(&'call ()) -> &'call ()>,
}

impl fmt::Debug for CrossTableBorrowAlias<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossTableBorrowAlias(<active>)")
    }
}

/// The only resolver for a [`CrossTableBorrowAlias`].
///
/// Both tables remain borrowed for the complete callback. The target table is
/// used only as an exact incarnation and resource-type policy boundary: this
/// scope never inserts an entry or produces a target token.
pub struct CrossTableBorrowScope<'call, A, B> {
    source: &'call ResourceTable<A>,
    target: &'call ResourceTable<B>,
    seal: CrossTableBorrowSeal,
}

impl<A, B> fmt::Debug for CrossTableBorrowScope<'_, A, B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CrossTableBorrowScope(<active>)")
    }
}

impl<'call, A, B> CrossTableBorrowScope<'call, A, B> {
    /// Creates a non-owning alias for this invocation.
    pub fn alias(&self) -> CrossTableBorrowAlias<'call> {
        CrossTableBorrowAlias {
            seal: self.seal,
            _brand: PhantomData,
        }
    }

    /// Uses an alias only when every private invocation and table seal matches.
    pub fn with_alias<R>(
        &self,
        alias: &CrossTableBorrowAlias<'_>,
        operation: impl for<'borrow> FnOnce(Borrowed<'borrow, A>) -> R,
    ) -> Result<R, ResourceError> {
        if alias.seal != self.seal {
            return Err(ResourceError::WrongScope);
        }
        if self.source.table_identity != self.seal.source_table_identity
            || self.source.instance_generation != self.seal.source_generation
            || self.target.table_identity != self.seal.target_table_identity
            || self.target.instance_generation != self.seal.target_generation
        {
            return Err(ResourceError::WrongInstance);
        }
        let entry = self
            .source
            .live_slot(self.seal.source_token, self.seal.source_type)?
            .entry
            .as_ref()
            .ok_or(ResourceError::Stale)?;
        Ok(operation(Borrowed {
            authority: &entry.authority,
            resource_type: entry.resource_type,
        }))
    }
}

pub struct ResourceTable<A> {
    instance_generation: u64,
    table_identity: u64,
    maximum: u16,
    next_reservation_nonce: u64,
    next_handle_counter: u32,
    next_scope_nonce: u64,
    slots: Vec<Slot<A>>,
    guest_borrows: Vec<GuestBorrowAlias>,
}

impl<A> ResourceTable<A> {
    pub fn new(instance_generation: u64, maximum: u16) -> Result<Self, ResourceError> {
        if instance_generation == 0
            || maximum == 0
            || usize::from(maximum) > PROFILE_1_LIMITS.max_resources as usize
            || maximum > 256
        {
            return Err(ResourceError::TableFull);
        }
        let table_identity = NEXT_TABLE_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ResourceError::GenerationExhausted)?;
        Ok(Self {
            instance_generation,
            table_identity,
            maximum,
            next_reservation_nonce: 1,
            next_handle_counter: 1,
            next_scope_nonce: 1,
            slots: Vec::new(),
            guest_borrows: Vec::new(),
        })
    }

    pub const fn instance_generation(&self) -> u64 {
        self.instance_generation
    }

    /// Binds an untrusted guest integer to this exact table incarnation.
    pub const fn token_from_guest_index(&self, encoded: u32) -> ResourceToken {
        ResourceToken {
            table_identity: self.table_identity,
            encoded,
        }
    }

    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.entry.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn reserve(&mut self) -> Result<Reservation<'_, A>, ResourceError> {
        let vacant = self
            .slots
            .iter()
            .position(|state| state.entry.is_none() && state.reservation_nonce.is_none());
        let slot = match vacant {
            Some(slot) => slot,
            None => {
                if self.slots.len() >= usize::from(self.maximum) {
                    return Err(ResourceError::TableFull);
                }
                self.slots
                    .try_reserve(1)
                    .map_err(|_| ResourceError::TableFull)?;
                self.slots.push(Slot {
                    reservation_nonce: None,
                    handle: None,
                    entry: None,
                    guest_owned: false,
                });
                self.slots.len() - 1
            }
        };
        let nonce = take_u64_counter(&mut self.next_reservation_nonce)?;
        let handle = self.allocate_handle()?;
        self.slots[slot].reservation_nonce = Some(nonce);
        Ok(Reservation {
            table: self,
            slot: slot as u16,
            nonce,
            handle,
            active: true,
        })
    }

    pub fn insert_owned(
        &mut self,
        resource_type: ResourceTypeId,
        authority: A,
    ) -> Result<ResourceToken, InsertFailure<A>> {
        let reservation = match self.reserve() {
            Ok(reservation) => reservation,
            Err(error) => return Err(InsertFailure { error, authority }),
        };
        Ok(reservation.commit(resource_type, authority))
    }

    /// Opens an unforgeable dynamic scope. The HRTB prevents the scope, table,
    /// or any borrowed authority from escaping the callback.
    pub fn with_borrow_scope<R>(
        &mut self,
        operation: impl for<'scope> FnOnce(BorrowScope<'scope, A>) -> R,
    ) -> Result<R, ResourceError> {
        let nonce = take_u64_counter(&mut self.next_scope_nonce)?;
        Ok(operation(BorrowScope { table: self, nonce }))
    }

    /// Convenience wrapper for a scope containing one borrow.
    pub fn with_borrow<R>(
        &mut self,
        token: ResourceToken,
        expected: ResourceTypeId,
        operation: impl for<'borrow> FnOnce(Borrowed<'borrow, A>) -> R,
    ) -> Result<R, ResourceError> {
        self.with_borrow_scope(|scope| scope.with_borrow(token, expected, operation))?
    }

    /// Opens a non-owning alias from one live source entry into a distinct
    /// target table's exact incarnation and resource-type policy.
    ///
    /// This operation only borrows both tables. It never inserts into the
    /// target, rotates a handle, or changes ownership in the source.
    pub fn with_cross_table_borrow<B, R>(
        &self,
        source_token: ResourceToken,
        source_type: ResourceTypeId,
        target: &ResourceTable<B>,
        target_type: ResourceTypeId,
        operation: impl for<'scope> FnOnce(CrossTableBorrowScope<'scope, A, B>) -> R,
    ) -> Result<R, ResourceError> {
        if self.table_identity == target.table_identity {
            return Err(ResourceError::WrongInstance);
        }
        self.live_slot(source_token, source_type)?;
        let scope_nonce = NEXT_CROSS_TABLE_BORROW_SCOPE_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ResourceError::GenerationExhausted)?;
        let seal = CrossTableBorrowSeal {
            scope_nonce,
            source_table_identity: self.table_identity,
            source_generation: self.instance_generation,
            source_token,
            source_type,
            target_table_identity: target.table_identity,
            target_generation: target.instance_generation,
            target_type,
        };
        Ok(operation(CrossTableBorrowScope {
            source: self,
            target,
            seal,
        }))
    }

    pub fn drop_owned(
        &mut self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<A, ResourceError> {
        let slot = self.live_slot_mut(token, expected)?;
        let entry = slot.entry.take().ok_or(ResourceError::Stale)?;
        slot.handle = None;
        slot.guest_owned = false;
        Ok(entry.authority)
    }

    pub fn begin_take_owned(
        &mut self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<OwnTransfer<'_, A>, ResourceError> {
        let slot_index = self.live_slot_index(token, expected)?;
        let entry = self.slots[slot_index]
            .entry
            .take()
            .ok_or(ResourceError::Stale)?;
        Ok(OwnTransfer {
            source: self,
            slot: slot_index,
            entry: Some(entry),
            committed: false,
        })
    }

    pub fn contains(
        &self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<bool, ResourceError> {
        self.live_slot(token, expected).map(|_| true)
    }

    pub(crate) fn begin_guest_call(&mut self) -> Result<GuestCallResources, ResourceError> {
        let nonce = take_u64_counter(&mut self.next_scope_nonce)?;
        Ok(GuestCallResources {
            table_identity: self.table_identity,
            nonce,
            own_moves: Vec::new(),
            committed: false,
        })
    }

    /// Produces a call-scoped guest alias for a host-owned resource token.
    /// The primary handle is never disclosed and remains live after the call.
    pub(crate) fn lower_borrow_for_guest(
        &mut self,
        scope: &GuestCallResources,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<ResourceToken, ResourceError> {
        self.check_guest_scope(scope)?;
        let slot = self.live_slot_index(token, expected)?;
        if let Some(alias) = self.guest_borrows.iter().find(|alias| {
            alias.scope_nonce == scope.nonce
                && usize::from(alias.slot) == slot
                && alias.resource_type == expected
        }) {
            return Ok(ResourceToken {
                table_identity: self.table_identity,
                encoded: alias.handle,
            });
        }
        let aliases_in_scope = self
            .guest_borrows
            .iter()
            .filter(|alias| alias.scope_nonce == scope.nonce)
            .count();
        if aliases_in_scope >= usize::from(self.maximum)
            || self.guest_borrows.len() >= PROFILE_1_LIMITS.max_resources as usize
        {
            return Err(ResourceError::TableFull);
        }
        self.guest_borrows
            .try_reserve(1)
            .map_err(|_| ResourceError::TableFull)?;
        let handle = self.allocate_handle()?;
        self.guest_borrows.push(GuestBorrowAlias {
            scope_nonce: scope.nonce,
            handle,
            slot: u16::try_from(slot).map_err(|_| ResourceError::TableFull)?,
            resource_type: expected,
        });
        Ok(ResourceToken {
            table_identity: self.table_identity,
            encoded: handle,
        })
    }

    /// Transfers one owned handle into the guest by rotating its opaque
    /// representation. Any host copy of the old token becomes stale.
    pub(crate) fn lower_owned_for_guest(
        &mut self,
        scope: &mut GuestCallResources,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<ResourceToken, ResourceError> {
        self.check_guest_scope(scope)?;
        let slot = self.live_slot_index(token, expected)?;
        if scope
            .own_moves
            .iter()
            .any(|movement| usize::from(movement.slot) == slot)
            || self
                .guest_borrows
                .iter()
                .any(|alias| alias.scope_nonce == scope.nonce && usize::from(alias.slot) == slot)
        {
            return Err(ResourceError::NotOwned);
        }
        scope
            .own_moves
            .try_reserve(1)
            .map_err(|_| ResourceError::TableFull)?;
        let guest_handle = self.allocate_handle()?;
        let old_handle = self.slots[slot].handle.ok_or(ResourceError::Stale)?;
        self.slots[slot].handle = Some(guest_handle);
        self.slots[slot].guest_owned = true;
        scope.own_moves.push(GuestOwnMove {
            slot: u16::try_from(slot).map_err(|_| ResourceError::TableFull)?,
            previous_handle: old_handle,
            next_handle: guest_handle,
            previous_guest_owned: false,
            next_guest_owned: true,
        });
        Ok(ResourceToken {
            table_identity: self.table_identity,
            encoded: guest_handle,
        })
    }

    /// Resolves only a borrow alias issued for this exact active call.
    #[allow(dead_code)] // C3 host imports consume this operation-time seam.
    pub(crate) fn with_guest_borrow<R>(
        &self,
        scope: &GuestCallResources,
        guest_index: u32,
        expected: ResourceTypeId,
        operation: impl for<'borrow> FnOnce(Borrowed<'borrow, A>) -> R,
    ) -> Result<R, ResourceError> {
        self.check_guest_scope(scope)?;
        let alias = self
            .guest_borrows
            .iter()
            .find(|alias| {
                alias.scope_nonce == scope.nonce
                    && alias.handle == guest_index
                    && alias.resource_type == expected
            })
            .ok_or(ResourceError::WrongScope)?;
        let slot = self
            .slots
            .get(usize::from(alias.slot))
            .ok_or(ResourceError::Stale)?;
        let entry = slot.entry.as_ref().ok_or(ResourceError::Stale)?;
        if entry.resource_type != expected {
            return Err(ResourceError::WrongType);
        }
        Ok(operation(Borrowed {
            authority: &entry.authority,
            resource_type: entry.resource_type,
        }))
    }

    /// Transfers an owned guest handle back to the host, again rotating the
    /// representation so a retained guest integer is stale immediately.
    pub(crate) fn lift_owned_from_guest(
        &mut self,
        scope: &mut GuestCallResources,
        guest_index: u32,
        expected: ResourceTypeId,
    ) -> Result<ResourceToken, ResourceError> {
        self.check_guest_scope(scope)?;
        if self
            .guest_borrows
            .iter()
            .any(|alias| alias.scope_nonce == scope.nonce && alias.handle == guest_index)
        {
            return Err(ResourceError::NotOwned);
        }
        let guest = self.token_from_guest_index(guest_index);
        let slot = self.live_slot_index_any(guest, expected)?;
        if !self.slots[slot].guest_owned {
            return Err(ResourceError::NotOwned);
        }
        scope
            .own_moves
            .try_reserve(1)
            .map_err(|_| ResourceError::TableFull)?;
        let host_handle = self.allocate_handle()?;
        self.slots[slot].handle = Some(host_handle);
        self.slots[slot].guest_owned = false;
        scope.own_moves.push(GuestOwnMove {
            slot: u16::try_from(slot).map_err(|_| ResourceError::TableFull)?,
            previous_handle: guest_index,
            next_handle: host_handle,
            previous_guest_owned: true,
            next_guest_owned: false,
        });
        Ok(ResourceToken {
            table_identity: self.table_identity,
            encoded: host_handle,
        })
    }

    pub(crate) fn commit_guest_call(
        &self,
        scope: &mut GuestCallResources,
    ) -> Result<(), ResourceError> {
        self.check_guest_scope(scope)?;
        scope.committed = true;
        Ok(())
    }

    pub(crate) fn close_guest_call(
        &mut self,
        mut scope: GuestCallResources,
    ) -> Result<(), ResourceError> {
        self.check_guest_scope(&scope)?;
        self.guest_borrows
            .retain(|alias| alias.scope_nonce != scope.nonce);
        if !scope.committed {
            for movement in scope.own_moves.iter().rev() {
                let slot = self
                    .slots
                    .get_mut(usize::from(movement.slot))
                    .ok_or(ResourceError::Stale)?;
                if slot.handle != Some(movement.next_handle)
                    || slot.guest_owned != movement.next_guest_owned
                {
                    return Err(ResourceError::Stale);
                }
                slot.handle = Some(movement.previous_handle);
                slot.guest_owned = movement.previous_guest_owned;
            }
        }
        scope.own_moves.clear();
        Ok(())
    }

    fn check_guest_scope(&self, scope: &GuestCallResources) -> Result<(), ResourceError> {
        if scope.table_identity == self.table_identity {
            Ok(())
        } else {
            Err(ResourceError::WrongInstance)
        }
    }

    fn allocate_handle(&mut self) -> Result<u32, ResourceError> {
        loop {
            let counter = self.next_handle_counter;
            self.next_handle_counter = counter
                .checked_add(1)
                .ok_or(ResourceError::GenerationExhausted)?;
            let handle = opaque_handle(self.instance_generation, self.table_identity, counter);
            if handle != 0 {
                return Ok(handle);
            }
        }
    }

    fn live_slot_index(
        &self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<usize, ResourceError> {
        let index = self.live_slot_index_any(token, expected)?;
        if self.slots[index].guest_owned {
            return Err(ResourceError::NotOwned);
        }
        Ok(index)
    }

    fn live_slot_index_any(
        &self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<usize, ResourceError> {
        if token.table_identity != self.table_identity {
            return Err(ResourceError::WrongInstance);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.handle == Some(token.encoded) && slot.entry.is_some())
            .ok_or(ResourceError::Stale)?;
        if self.slots[index]
            .entry
            .as_ref()
            .map(|entry| entry.resource_type)
            != Some(expected)
        {
            return Err(ResourceError::WrongType);
        }
        Ok(index)
    }

    pub(crate) fn contains_guest_owned_index(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
    ) -> Result<bool, ResourceError> {
        let token = self.token_from_guest_index(guest_index);
        let index = self.live_slot_index_any(token, expected)?;
        if !self.slots[index].guest_owned {
            return Err(ResourceError::NotOwned);
        }
        Ok(true)
    }

    fn live_slot(
        &self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<&Slot<A>, ResourceError> {
        let index = self.live_slot_index(token, expected)?;
        Ok(&self.slots[index])
    }

    fn live_slot_mut(
        &mut self,
        token: ResourceToken,
        expected: ResourceTypeId,
    ) -> Result<&mut Slot<A>, ResourceError> {
        let index = self.live_slot_index(token, expected)?;
        Ok(&mut self.slots[index])
    }
}

impl<A> Reservation<'_, A> {
    /// Explicit rollback is optional; dropping the guard has the same effect.
    pub fn rollback(mut self) {
        self.release();
    }

    pub fn commit(mut self, resource_type: ResourceTypeId, authority: A) -> ResourceToken {
        let slot = &mut self.table.slots[usize::from(self.slot)];
        debug_assert_eq!(slot.reservation_nonce, Some(self.nonce));
        debug_assert!(slot.entry.is_none());
        debug_assert!(slot.handle.is_none());
        slot.entry = Some(Entry {
            resource_type,
            authority,
        });
        slot.handle = Some(self.handle);
        slot.guest_owned = false;
        slot.reservation_nonce = None;
        self.active = false;
        ResourceToken {
            table_identity: self.table.table_identity,
            encoded: self.handle,
        }
    }

    fn release(&mut self) {
        if self.active {
            let slot = &mut self.table.slots[usize::from(self.slot)];
            if slot.reservation_nonce == Some(self.nonce)
                && slot.entry.is_none()
                && slot.handle.is_none()
            {
                slot.reservation_nonce = None;
            }
            self.active = false;
        }
    }
}

impl<A> Drop for Reservation<'_, A> {
    fn drop(&mut self) {
        self.release();
    }
}

pub struct OwnTransfer<'a, A> {
    source: &'a mut ResourceTable<A>,
    slot: usize,
    entry: Option<Entry<A>>,
    committed: bool,
}

impl<A> fmt::Debug for OwnTransfer<'_, A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnTransfer")
            .field("authority", &"<opaque>")
            .field("committed", &self.committed)
            .finish()
    }
}

impl<A> OwnTransfer<'_, A> {
    pub fn authority(&self) -> Result<&A, ResourceError> {
        self.entry
            .as_ref()
            .map(|entry| &entry.authority)
            .ok_or(ResourceError::NotOwned)
    }

    pub fn commit(mut self) -> Result<A, ResourceError> {
        let entry = self.entry.take().ok_or(ResourceError::NotOwned)?;
        self.source.slots[self.slot].handle = None;
        self.source.slots[self.slot].guest_owned = false;
        self.committed = true;
        Ok(entry.authority)
    }

    pub fn commit_into<'target>(
        mut self,
        reservation: Reservation<'target, A>,
        expected: ResourceTypeId,
    ) -> Result<ResourceToken, ReservationFailure<'target, A>> {
        let Some(entry) = self.entry.as_ref() else {
            return Err(ReservationFailure {
                error: ResourceError::NotOwned,
                reservation,
            });
        };
        if entry.resource_type != expected {
            return Err(ReservationFailure {
                error: ResourceError::WrongType,
                reservation,
            });
        }
        // From this point onward both updates are allocation-free and infallible.
        let entry = self.entry.take().expect("live ownership transfer");
        let token = reservation.commit(expected, entry.authority);
        self.source.slots[self.slot].handle = None;
        self.source.slots[self.slot].guest_owned = false;
        self.committed = true;
        Ok(token)
    }
}

impl<A> Drop for OwnTransfer<'_, A> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(entry) = self.entry.take() {
                self.source.slots[self.slot].entry = Some(entry);
            }
        }
    }
}

fn take_u64_counter(counter: &mut u64) -> Result<u64, ResourceError> {
    let value = *counter;
    *counter = value
        .checked_add(1)
        .filter(|next| *next != 0)
        .ok_or(ResourceError::GenerationExhausted)?;
    Ok(value)
}

/// A keyed permutation of a monotonic counter. This is collision-free for the
/// life of the counter and, unlike the former XOR slot encoding, one observed
/// handle does not reveal another slot's handle. The full keys remain host-only.
fn opaque_handle(instance: u64, table: u64, counter: u32) -> u32 {
    let low = (instance as u32) ^ (table.rotate_left(17) as u32);
    let high = ((instance >> 32) as u32) ^ ((table >> 32) as u32).rotate_left(9);
    let mut value = counter ^ low;
    value = value.wrapping_add(high | 1).rotate_left((high & 31) + 1);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846c_a68b);
    value ^= value >> 16;
    value ^ low.rotate_left(7)
}

const _: () = assert!(PROFILE_1_LIMITS.max_resources <= 256);
const _: () = assert!(mem::size_of::<ResourceToken>() <= 16);

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: ResourceTypeId = ResourceTypeId(1);

    #[test]
    fn guest_borrows_are_scoped_aliases_and_never_disclose_primary_handles() {
        let mut table = ResourceTable::new(1, 2).unwrap();
        let primary = table.insert_owned(RANDOM, 7_u32).unwrap();
        let scope = table.begin_guest_call().unwrap();
        let guest = table
            .lower_borrow_for_guest(&scope, primary, RANDOM)
            .unwrap();
        assert_ne!(guest.guest_index(), primary.guest_index());
        assert_eq!(
            table.with_guest_borrow(&scope, guest.guest_index(), RANDOM, |borrowed| {
                borrowed.with(|authority| *authority)
            }),
            Ok(7)
        );
        table.close_guest_call(scope).unwrap();
        assert_eq!(
            table.contains(table.token_from_guest_index(guest.guest_index()), RANDOM),
            Err(ResourceError::Stale)
        );
        assert_eq!(table.drop_owned(primary, RANDOM), Ok(7));
    }

    #[test]
    fn guest_own_moves_rotate_handles_and_rollback_or_commit_linearly() {
        let mut table = ResourceTable::new(2, 2).unwrap();
        let original = table.insert_owned(RANDOM, 9_u32).unwrap();

        let mut rollback = table.begin_guest_call().unwrap();
        let guest = table
            .lower_owned_for_guest(&mut rollback, original, RANDOM)
            .unwrap();
        assert_eq!(table.contains(original, RANDOM), Err(ResourceError::Stale));
        assert_eq!(table.contains(guest, RANDOM), Err(ResourceError::NotOwned));
        assert_eq!(
            table.contains_guest_owned_index(guest.guest_index(), RANDOM),
            Ok(true)
        );
        table.close_guest_call(rollback).unwrap();
        assert_eq!(table.contains(original, RANDOM), Ok(true));
        assert_eq!(table.contains(guest, RANDOM), Err(ResourceError::Stale));

        let mut committed = table.begin_guest_call().unwrap();
        let guest = table
            .lower_owned_for_guest(&mut committed, original, RANDOM)
            .unwrap();
        assert_eq!(
            table.lower_owned_for_guest(&mut committed, guest, RANDOM),
            Err(ResourceError::NotOwned),
            "one owned input cannot be duplicated"
        );
        let returned = table
            .lift_owned_from_guest(&mut committed, guest.guest_index(), RANDOM)
            .unwrap();
        assert_eq!(table.contains(guest, RANDOM), Err(ResourceError::Stale));
        table.commit_guest_call(&mut committed).unwrap();
        table.close_guest_call(committed).unwrap();
        assert_eq!(table.contains(original, RANDOM), Err(ResourceError::Stale));
        assert_eq!(table.contains(returned, RANDOM), Ok(true));
        assert_eq!(table.drop_owned(returned, RANDOM), Ok(9));
    }

    #[test]
    fn guest_cannot_claim_a_guessed_host_owned_handle() {
        let mut table = ResourceTable::new(3, 2).unwrap();
        let host = table.insert_owned(RANDOM, 11_u32).unwrap();
        let mut scope = table.begin_guest_call().unwrap();

        assert_eq!(
            table.lift_owned_from_guest(&mut scope, host.guest_index(), RANDOM),
            Err(ResourceError::NotOwned)
        );
        table.close_guest_call(scope).unwrap();
        assert_eq!(table.drop_owned(host, RANDOM), Ok(11));
    }

    #[test]
    fn guest_borrow_aliases_are_reused_and_bounded() {
        let mut table = ResourceTable::new(4, 1).unwrap();
        let primary = table.insert_owned(RANDOM, 13_u32).unwrap();
        let scope = table.begin_guest_call().unwrap();
        let first = table
            .lower_borrow_for_guest(&scope, primary, RANDOM)
            .unwrap();
        let duplicate = table
            .lower_borrow_for_guest(&scope, primary, RANDOM)
            .unwrap();
        assert_eq!(first, duplicate);
        assert_eq!(table.guest_borrows.len(), 1);
        table.close_guest_call(scope).unwrap();
        assert_eq!(table.drop_owned(primary, RANDOM), Ok(13));
    }

    #[test]
    fn borrow_and_own_of_the_same_resource_fail_in_both_orders_and_roll_back() {
        let mut table = ResourceTable::new(5, 1).unwrap();
        let original = table.insert_owned(RANDOM, 17_u32).unwrap();

        let mut borrow_first = table.begin_guest_call().unwrap();
        let alias = table
            .lower_borrow_for_guest(&borrow_first, original, RANDOM)
            .unwrap();
        assert_eq!(
            table.lower_owned_for_guest(&mut borrow_first, original, RANDOM),
            Err(ResourceError::NotOwned)
        );
        table.close_guest_call(borrow_first).unwrap();
        assert_eq!(
            table.contains(table.token_from_guest_index(alias.guest_index()), RANDOM),
            Err(ResourceError::Stale)
        );

        let mut own_first = table.begin_guest_call().unwrap();
        let guest = table
            .lower_owned_for_guest(&mut own_first, original, RANDOM)
            .unwrap();
        assert_eq!(
            table.lower_borrow_for_guest(&own_first, original, RANDOM),
            Err(ResourceError::Stale)
        );
        table.close_guest_call(own_first).unwrap();
        assert_eq!(
            table.contains_guest_owned_index(guest.guest_index(), RANDOM),
            Err(ResourceError::Stale)
        );
        assert_eq!(table.drop_owned(original, RANDOM), Ok(17));
    }
}
