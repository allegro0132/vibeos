//! Typed, authority-neutral boundary for synchronous Component host imports.
//!
//! The Component runtime owns Canonical ABI decoding and resource-handle
//! validation. A platform dispatcher receives only validated values and may
//! reach a borrowed authority exclusively through a higher-ranked callback.
//! It never receives the resource table, its primary token, or guest memory.

use crate::{
    execution::HostImportInfo,
    resource::{GuestCallResources, ResourceTable},
    value::{CanonicalValue, ResourceOwnership, ValueType},
};
use alloc::vec::Vec;
use core::{
    fmt,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};
use vibeos_component_format::PROFILE_1_LIMITS;

/// Stable failures at the trusted host-import boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum HostError {
    Denied = 1,
    Unavailable = 2,
    Exhausted = 3,
    InvalidArgument = 4,
    BackendFault = 5,
    BudgetExceeded = 6,
    /// The backend published an ordinary typed failure, distinct from a
    /// structural or authority fault.
    Failed = 7,
    /// The exact operation was cancelled by its owning supervisor.
    Cancelled = 8,
    /// The backend published a typed invalid-state terminal. This is distinct
    /// from malformed guest arguments at the host-call boundary.
    InvalidState = 9,
}

impl HostError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// Successful typed results plus deterministic host-side work to charge.
///
/// The dispatcher is trusted to report its service work, while Canonical ABI
/// lift/lower work is measured independently by the runtime. C3 dispatchers
/// use fixed base costs plus exact byte counts; an oversized charge is rejected
/// against the invocation's remaining budget before guest resumption.
pub struct HostResponse {
    values: Vec<CanonicalValue>,
    work: u64,
}

/// One payload allocation which the runtime must prepare before dispatch.
/// Dispatchers derive this only from inert metadata and already-lifted copied
/// arguments; it must not inspect authority or invoke a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPayloadAllocation {
    pub size: u32,
    pub alignment: u32,
}

/// Copy-only identity for one dispatcher-owned suspended operation.
///
/// The token carries no authority and does not own the operation. Its sole
/// purpose is exact-generation comparison at the runtime/dispatcher boundary;
/// the dispatcher remains responsible for minting globally non-repeating
/// generations and for owning every waiter and backend reservation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostOperationToken(NonZeroU64);

impl HostOperationToken {
    /// Wrap one dispatcher-minted non-zero generation.
    ///
    /// There is deliberately no inverse accessor: portable continuation state
    /// may compare or return this token, but cannot derive a registry index or
    /// otherwise treat it as authority.
    pub const fn from_generation(generation: u64) -> Option<Self> {
        match NonZeroU64::new(generation) {
            Some(generation) => Some(Self(generation)),
            None => None,
        }
    }

    pub(crate) const fn strictly_after(self, previous: Self) -> bool {
        self.0.get() > previous.0.get()
    }
}

impl fmt::Debug for HostOperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostOperationToken(..)")
    }
}

/// Fault-stable, authority-neutral storage for one exact backend operation.
///
/// The slot deliberately exposes only opaque-token comparisons. It lets a
/// stable supervisor mirror an arena-owned payload's current backend wait so
/// fault teardown can revoke that exact operation even when the payload's
/// destructor cannot run. Publishing before wake registration closes the
/// registration/fault race: a concurrent supervisor may cancel the already
/// started backend operation, after which registration fails inertly.
pub struct AtomicHostOperationSlot {
    generation: AtomicU64,
}

impl AtomicHostOperationSlot {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
        }
    }

    /// Publish one exact operation only while the slot is empty.
    pub fn publish(&self, operation: HostOperationToken) -> bool {
        self.generation
            .compare_exchange(0, operation.0.get(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Reconstruct the currently mirrored opaque token without exposing its
    /// numeric generation.
    pub fn load(&self) -> Option<HostOperationToken> {
        NonZeroU64::new(self.generation.load(Ordering::Acquire)).map(HostOperationToken)
    }

    /// Check that the exact operation remains supervisor-visible.
    pub fn contains(&self, operation: HostOperationToken) -> bool {
        self.generation.load(Ordering::Acquire) == operation.0.get()
    }

    /// Clear only the exact mirrored operation. A stale payload or supervisor
    /// cannot erase a replacement generation.
    pub fn clear_exact(&self, operation: HostOperationToken) -> bool {
        self.generation
            .compare_exchange(operation.0.get(), 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn is_empty(&self) -> bool {
        self.generation.load(Ordering::Acquire) == 0
    }
}

impl Default for AtomicHostOperationSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AtomicHostOperationSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AtomicHostOperationSlot(<redacted>)")
    }
}

/// Fixed-size wake envelope copied into a dispatcher-owned wait slot.
///
/// The four machine words are intentionally uninterpreted by the Component
/// runtime. Invoking `wake` never grants access to guest memory, a resource
/// table, or a dispatcher; it merely calls the supervisor-selected callback.
#[derive(Clone, Copy)]
pub struct HostWakeToken {
    words: [usize; 4],
    callback: fn([usize; 4]),
}

impl HostWakeToken {
    pub const fn new(words: [usize; 4], callback: fn([usize; 4])) -> Self {
        Self { words, callback }
    }

    pub fn wake(self) {
        (self.callback)(self.words);
    }
}

impl fmt::Debug for HostWakeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostWakeToken(..)")
    }
}

/// A dispatcher reservation whose backend effect has not happened yet.
///
/// `allocations` are the exact Canonical ABI payload spans required by the
/// eventual response. The runtime validates and prepares them before calling
/// [`HostDispatcher::commit_prepared`]. Private fields prevent callers from
/// manufacturing a response or treating the operation token as owning state.
pub struct HostPrepared {
    operation: HostOperationToken,
    allocations: Vec<HostPayloadAllocation>,
}

impl HostPrepared {
    pub fn new(
        operation: HostOperationToken,
        allocations: Vec<HostPayloadAllocation>,
    ) -> Result<Self, HostError> {
        if allocations.is_empty()
            || allocations.len() > PROFILE_1_LIMITS.max_abi_allocations as usize
            || allocations.iter().any(|allocation| {
                allocation.size == 0
                    || allocation.alignment == 0
                    || !allocation.alignment.is_power_of_two()
            })
        {
            return Err(HostError::InvalidArgument);
        }
        Ok(Self {
            operation,
            allocations,
        })
    }

    pub const fn operation(&self) -> HostOperationToken {
        self.operation
    }

    pub fn allocations(&self) -> &[HostPayloadAllocation] {
        &self.allocations
    }

    pub(crate) fn into_parts(self) -> (HostOperationToken, Vec<HostPayloadAllocation>) {
        (self.operation, self.allocations)
    }
}

impl fmt::Debug for HostPrepared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPrepared")
            .field("operation", &self.operation)
            .field("allocations", &self.allocations)
            .finish()
    }
}

/// One attempt to cross an async-capable host boundary.
pub enum HostDispatch {
    /// The operation completed without suspension or a deferred backend
    /// mutation. Legacy scalar imports normally use this path.
    Ready(HostResponse),
    /// The SYSTEM dispatcher owns a wait registration. Ordinary `poll` calls
    /// must return this token without retrying the backend.
    Pending(HostOperationToken),
    /// The dispatcher has reserved an exact result but has not performed its
    /// backend mutation. Only exact allocation preparation followed by
    /// `commit_prepared` may consume it.
    Prepared(HostPrepared),
}

impl HostResponse {
    pub fn new(values: Vec<CanonicalValue>, work: u64) -> Result<Self, HostError> {
        if work == 0 {
            return Err(HostError::InvalidArgument);
        }
        Ok(Self { values, work })
    }

    pub fn one(value: CanonicalValue, work: u64) -> Result<Self, HostError> {
        Self::reserve_one(work)?.commit(value)
    }

    pub fn unit(work: u64) -> Result<Self, HostError> {
        Self::new(Vec::new(), work)
    }

    pub fn values(&self) -> &[CanonicalValue] {
        &self.values
    }

    pub const fn work(&self) -> u64 {
        self.work
    }

    pub(crate) fn into_parts(self) -> (Vec<CanonicalValue>, u64) {
        (self.values, self.work)
    }
}

/// A fallibly allocated one-value response envelope. Dispatchers which may
/// perform an external side effect reserve this before invoking the backend;
/// `commit` is allocation-free.
#[must_use = "a reserved host response should be committed or dropped"]
pub struct OneResponseReservation {
    values: Vec<CanonicalValue>,
    work: u64,
}

impl HostResponse {
    pub fn reserve_one(work: u64) -> Result<OneResponseReservation, HostError> {
        if work == 0 {
            return Err(HostError::InvalidArgument);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(1)
            .map_err(|_| HostError::Exhausted)?;
        Ok(OneResponseReservation { values, work })
    }
}

impl OneResponseReservation {
    pub fn commit(mut self, value: CanonicalValue) -> Result<HostResponse, HostError> {
        debug_assert!(self.values.capacity() >= 1);
        self.values.push(value);
        HostResponse::new(self.values, self.work)
    }
}

/// One validated host call suspended at its exact Canonical ABI boundary.
pub struct HostRequest<'call, A> {
    import: &'call HostImportInfo,
    arguments: &'call [CanonicalValue],
    resources: &'call ResourceTable<A>,
    resource_scope: &'call GuestCallResources,
}

impl<'call, A> HostRequest<'call, A> {
    pub(crate) const fn new(
        import: &'call HostImportInfo,
        arguments: &'call [CanonicalValue],
        resources: &'call ResourceTable<A>,
        resource_scope: &'call GuestCallResources,
    ) -> Self {
        Self {
            import,
            arguments,
            resources,
            resource_scope,
        }
    }

    pub const fn import(&self) -> &HostImportInfo {
        self.import
    }

    pub const fn arguments(&self) -> &[CanonicalValue] {
        self.arguments
    }

    /// Use one `borrow<T>` argument without exposing its table-primary token
    /// and without allowing either the authority reference or a borrowed value
    /// derived from it to escape this dynamic host call.
    pub fn with_borrow_argument<R>(
        &self,
        index: usize,
        operation: impl for<'borrow> FnOnce(&'borrow A) -> R,
    ) -> Result<R, HostError> {
        let parameter = self
            .import
            .function_type
            .parameters
            .get(index)
            .ok_or(HostError::InvalidArgument)?;
        let ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } = &parameter.value
        else {
            return Err(HostError::InvalidArgument);
        };
        let CanonicalValue::Resource(token) = self
            .arguments
            .get(index)
            .ok_or(HostError::InvalidArgument)?
        else {
            return Err(HostError::InvalidArgument);
        };
        self.resources
            .with_guest_borrow(
                self.resource_scope,
                token.guest_index(),
                *resource_type,
                |borrowed| borrowed.with(operation),
            )
            .map_err(|_| HostError::Denied)
    }
}

/// Platform implementation of the exact synchronous WIT import allowlist.
///
/// This trait is object-safe so one component call can borrow a dispatcher
/// across bounded Core polls without storing platform-specific types in the
/// portable runtime.
pub trait HostDispatcher<A>: Send {
    /// Returns the deterministic charge for this exact validated shape before
    /// any authority lookup or backend side effect is permitted.
    ///
    /// The runtime precharges this value and requires [`HostResponse::work`]
    /// to match it exactly. Implementations must derive it only from the inert
    /// import metadata and copied canonical arguments.
    fn required_work(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<u64, HostError>;

    /// Returns the exact worst-case payload spans for this invocation. The
    /// runtime allocates these while the outer guest is suspended and before
    /// `dispatch`, so allocator failure cannot follow a backend side effect.
    fn result_allocations(
        &self,
        _import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<Vec<HostPayloadAllocation>, HostError> {
        Ok(Vec::new())
    }

    /// Begin one exact operation. The default preserves the pre-C5 synchronous
    /// dispatcher contract.
    fn start(&mut self, request: HostRequest<'_, A>) -> Result<HostDispatch, HostError> {
        self.dispatch(request).map(HostDispatch::Ready)
    }

    /// Legacy synchronous entry point. Async-only dispatchers may leave this
    /// default in place and implement `start` instead.
    fn dispatch(&mut self, _request: HostRequest<'_, A>) -> Result<HostResponse, HostError> {
        Err(HostError::Denied)
    }

    /// Install the sole copy-only wake envelope for an exact pending token.
    /// Implementations must register before rechecking readiness and invoke a
    /// raced wake outside internal locks.
    fn register_wake(
        &mut self,
        _operation: HostOperationToken,
        _wake: HostWakeToken,
    ) -> Result<(), HostError> {
        Err(HostError::InvalidArgument)
    }

    /// Retry only after an explicit supervisor wake. Every return consumes the
    /// supplied operation. A new `Pending` or `Prepared` return must carry a
    /// freshly minted token, never the consumed generation.
    fn resume(
        &mut self,
        _operation: HostOperationToken,
        _request: HostRequest<'_, A>,
    ) -> Result<HostDispatch, HostError> {
        Err(HostError::InvalidArgument)
    }

    /// Perform the deferred backend mutation for one prepared result.
    ///
    /// The runtime calls this only after all exact guest allocations and
    /// reallocations have succeeded. A successful return consumes
    /// `operation`. An ordinary error before backend publication must preserve
    /// the exact reservation so the runtime can cancel it before rolling back
    /// known guest spans. Returning an error after mutation is a dispatcher
    /// invariant failure: the subsequent exact cancel must fail, causing the
    /// runtime to poison the instance and conservatively leak ambiguous spans.
    /// Implementations must therefore reserve the response envelope and
    /// validate the fresh request before mutating the backend.
    fn commit_prepared(
        &mut self,
        _operation: HostOperationToken,
        _request: HostRequest<'_, A>,
    ) -> Result<HostResponse, HostError> {
        Err(HostError::InvalidArgument)
    }

    /// Detach a not-yet-committed pending/prepared operation. Cancellation is
    /// exact and idempotence is deliberately not implied: a stale, duplicate,
    /// or mismatched token must fail closed in the dispatcher.
    fn cancel(&mut self, _operation: HostOperationToken) -> Result<(), HostError> {
        Err(HostError::InvalidArgument)
    }
}

/// Default policy for components which declared no executable host imports.
pub struct RejectHost;

impl<A> HostDispatcher<A> for RejectHost {
    fn required_work(
        &self,
        _import: &HostImportInfo,
        _arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        Err(HostError::Denied)
    }

    fn dispatch(&mut self, _request: HostRequest<'_, A>) -> Result<HostResponse, HostError> {
        Err(HostError::Denied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn atomic_operation_slot_is_exact_stale_safe_and_redacted() {
        let slot = AtomicHostOperationSlot::new();
        let first = HostOperationToken::from_generation(41).unwrap();
        let replacement = HostOperationToken::from_generation(42).unwrap();

        assert!(slot.is_empty());
        assert!(slot.publish(first));
        assert!(!slot.publish(replacement));
        assert!(slot.contains(first));
        assert_eq!(slot.load(), Some(first));
        assert!(!slot.clear_exact(replacement));
        assert!(slot.contains(first));
        assert!(slot.clear_exact(first));
        assert!(slot.publish(replacement));
        assert!(!slot.clear_exact(first));
        assert!(slot.contains(replacement));
        assert_eq!(format!("{slot:?}"), "AtomicHostOperationSlot(<redacted>)");
    }
}
