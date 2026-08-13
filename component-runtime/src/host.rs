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
pub trait HostDispatcher<A> {
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

    fn dispatch(&mut self, request: HostRequest<'_, A>) -> Result<HostResponse, HostError>;
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
