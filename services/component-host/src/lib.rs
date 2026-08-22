//! Capability bindings for component host resources.
//!
//! A [`ComponentAuthority`] is deliberately not a portable capability handle.
//! It is bound to one exact [`CSpace`] wrapper and one CSpace incarnation, and
//! it resolves the underlying [`Cap`] again for every operation. The authority
//! stores no CSpace owner, so a component resource table cannot keep a dead
//! component's authority alive.
//!
//! Durable capabilities are never installed directly. A trusted host may
//! install an attenuated, boot-local [`PersistentProxy`] whose parent token
//! observes durable revocation. This crate intentionally exposes neither
//! durable object IDs nor persistent capability identities.
//!
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt;

use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_core::cap::{CSpace, CSpaceIdentity, Cap, CapError, Resource, Revocable, Rights};
use vibeos_core::sync::SpinLock;

mod resources;
mod runtime_dispatch;
mod service;
mod stream;
mod transfer;

pub use resources::{
    BlobBackend, BlobBackendFault, BlobError, BlobResource, ClockBackend, ClockBackendFault,
    ClockError, ClockResource, LogField, LogLevel, RandomBackend, RandomBackendFault, RandomError,
    RandomResource, StructuredLogError, StructuredLogEvent, StructuredLogResource,
    StructuredLogSink, StructuredLogSinkFault, ValidatedLogEvent, ValidatedLogField,
    MAX_BLOB_READ_BYTES, MAX_LOG_EVENT_BYTES, MAX_LOG_FIELDS, MAX_LOG_FIELD_KEY_BYTES,
    MAX_LOG_FIELD_VALUE_BYTES, MAX_LOG_MESSAGE_BYTES, MAX_LOG_TARGET_BYTES, MAX_RANDOM_FILL_BYTES,
};
pub use runtime_dispatch::{
    ComponentHostDispatcher, HostManifestError, VibeHostManifest, VibeHostRequirement,
    BLOB_INTERFACE, BLOB_LEN_FUNCTION, BLOB_READ_FUNCTION, CLOCK_INTERFACE, CLOCK_NOW_FUNCTION,
    LOG_INTERFACE, LOG_WRITE_FUNCTION, RANDOM_FILL_FUNCTION, RANDOM_INTERFACE,
    STREAM_CLOSE_READER_FUNCTION, STREAM_CLOSE_WRITER_FUNCTION, STREAM_INTERFACE,
    STREAM_READ_FUNCTION, STREAM_WRITE_FUNCTION,
};
pub use service::{ComponentCallError, ComponentHostServices};
pub use stream::{
    ByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter, StreamCloseObservation,
    StreamCloseOutcome, StreamCloseReason, StreamError, StreamPreparedReceive, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, StreamTerminalDispatch, MAX_STREAM_CHUNK_BYTES,
    STREAM_BUFFER_CHUNKS,
};
pub use transfer::{
    prepare_owned_supervised, revoke_owned_supervised, transfer_owned, with_supervised_borrow,
    OwnedTransferError, PreparedSupervisedOwnTransfer, SupervisedBorrowError,
    SupervisedBorrowScope, SupervisedOwnTransferGuard, SupervisedRevokeError,
};

/// Shared ownership used by the trusted host to serialize one CSpace.
pub type SharedCSpace = Arc<SpinLock<CSpace>>;

/// Semantic host-resource kinds that may be placed in a component table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostResourceKind {
    Clock,
    Random,
    Blob,
    StructuredLog,
    ByteStreamReader,
    ByteStreamWriter,
}

/// Ties a concrete Rust type to exactly one component-facing resource kind.
///
/// Binding APIs infer the kind from `T`; callers cannot assert an unrelated
/// kind for a capability and bypass the typed CSpace check.
pub trait ComponentHostResource: Resource {
    const HOST_KIND: HostResourceKind;
    const OPERATION_RIGHTS: Rights;
}

/// Whether an authority names an ordinary volatile resource or a boot-local
/// proxy whose parent is durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityClass {
    Ephemeral,
    /// Volatile source authority sealed for one supervisor-controlled edge
    /// transfer. Component operations can use only `rights_ceiling`; the hidden
    /// `GRANT` bit is never exposed and cannot cross into the target.
    EphemeralGrantSource,
    PersistentProxy,
}

/// Fail-closed errors returned by component authority binding and use.
///
/// None of these variants includes the opaque capability or durable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    WrongSpace,
    IncarnationMismatch,
    InvalidOrRevoked,
    InsufficientRights,
    RightsExceedCeiling,
    WrongResourceType,
    WrongResourceKind,
    RawPersistentAuthority,
    PersistentAuthorityRequired,
    PersistentGrantRequired,
    PersistentProxyRights,
    PersistentProxyTarget,
    SupervisorDistinctSpacesRequired,
    SupervisorGrantRequired,
    TableNotEmpty,
    TeardownRejected,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongSpace => "authority belongs to a different component CSpace",
            Self::IncarnationMismatch => "component CSpace incarnation changed",
            Self::InvalidOrRevoked => "invalid, revoked, or unavailable authority",
            Self::InsufficientRights => "authority has insufficient rights",
            Self::RightsExceedCeiling => "authority rights exceed the component ceiling",
            Self::WrongResourceType => "authority names the wrong resource type",
            Self::WrongResourceKind => "authority names the wrong host resource kind",
            Self::RawPersistentAuthority => "raw persistent authority cannot enter a component",
            Self::PersistentAuthorityRequired => "persistent source authority is required",
            Self::PersistentGrantRequired => "persistent source lacks GRANT authority",
            Self::PersistentProxyRights => "persistent proxy requested forbidden rights",
            Self::PersistentProxyTarget => {
                "persistent proxy target must be a distinct volatile CSpace"
            }
            Self::SupervisorDistinctSpacesRequired => {
                "supervised resource routing requires two distinct CSpaces"
            }
            Self::SupervisorGrantRequired => {
                "cross-principal volatile transfer requires sealed GRANT authority"
            }
            Self::TableNotEmpty => "component resource table must be empty before teardown",
            Self::TeardownRejected => "component CSpace refused volatile teardown",
        })
    }
}

fn map_cap_error(error: CapError) -> AuthorityError {
    match error {
        CapError::Invalid
        | CapError::PersistentIdentityMismatch
        | CapError::PersistentQuarantined
        | CapError::PersistentLifecycleRequired => AuthorityError::InvalidOrRevoked,
        CapError::InsufficientRights | CapError::Amplification => {
            AuthorityError::InsufficientRights
        }
        CapError::WrongType => AuthorityError::WrongResourceType,
        CapError::NotPersistent => AuthorityError::PersistentAuthorityRequired,
    }
}

struct SpaceBinding {
    identity: CSpaceIdentity,
    incarnation: u64,
    cspace: SharedCSpace,
}

/// An exact, incarnation-bound route to one component CSpace.
///
/// Clone this value when several host subsystems serve the same component.
/// A separately constructed wrapper around the same raw CSpace has the same
/// core-issued identity and is therefore an equivalent exact route.
#[derive(Clone)]
pub struct ComponentAuthoritySpace {
    inner: Arc<SpaceBinding>,
}

impl fmt::Debug for ComponentAuthoritySpace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentAuthoritySpace")
            .field("cspace", &"<redacted>")
            .field("incarnation", &"<redacted>")
            .finish()
    }
}

impl ComponentAuthoritySpace {
    /// Bind a host route to the expected live incarnation.
    pub fn new(cspace: SharedCSpace, expected_incarnation: u64) -> Result<Self, AuthorityError> {
        let guard = cspace.lock();
        if guard.incarnation() != expected_incarnation {
            return Err(AuthorityError::IncarnationMismatch);
        }
        let identity = guard.identity();
        drop(guard);
        Ok(Self {
            inner: Arc::new(SpaceBinding {
                identity,
                incarnation: expected_incarnation,
                cspace,
            }),
        })
    }

    /// Bind a live, typed, non-persistent cap with a non-amplifying ceiling.
    pub fn bind_ephemeral<T: ComponentHostResource>(
        &self,
        cap: Cap,
        rights_ceiling: Rights,
    ) -> Result<ComponentAuthority, AuthorityError> {
        let guard = self.inner.cspace.lock();
        self.check_incarnation(&guard)?;
        validate_ephemeral_cap::<T>(&guard, cap, rights_ceiling)?;
        drop(guard);

        Ok(self.authority(cap, T::HOST_KIND, rights_ceiling, AuthorityClass::Ephemeral))
    }

    /// Resolve through this exact space, rejecting authorities from any other
    /// wrapper even if the opaque cap bits collide.
    pub fn with_revocable<T, R, F>(
        &self,
        authority: &ComponentAuthority,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        authority.with_revocable::<T, R, F>(&self.inner.cspace, need, operation)
    }

    /// Revoke one authority removed from its owning component resource table.
    ///
    /// The caller must first consume the table's `own<T>` entry with
    /// `ResourceTable::drop_owned`; passing an authority still published in a
    /// table would intentionally make that handle fail on its next use.
    pub fn revoke_dropped(&self, authority: ComponentAuthority) -> Result<usize, AuthorityError> {
        if authority.cspace_identity != self.inner.identity {
            return Err(AuthorityError::WrongSpace);
        }
        if authority.cspace_incarnation != self.inner.incarnation {
            return Err(AuthorityError::IncarnationMismatch);
        }
        let mut guard = self.inner.cspace.lock();
        self.check_incarnation(&guard)?;
        match authority.class {
            AuthorityClass::Ephemeral
            | AuthorityClass::EphemeralGrantSource
            | AuthorityClass::PersistentProxy => guard
                .revoke_exact_admin(authority.cap)
                .map_err(map_cap_error),
        }
    }

    /// Complete component teardown after calls are cancelled and the resource
    /// table is no longer externally published.
    ///
    /// The empty-table proof makes the lifecycle order explicit: first close
    /// publication, then drop/consume every table entry, then reset this CSpace.
    /// Reset revokes all remaining volatile descendants, frees their slots, and
    /// advances the incarnation so no stale authority can revive.
    pub fn teardown(
        &self,
        resource_table: &ResourceTable<ComponentAuthority>,
    ) -> Result<usize, AuthorityError> {
        if !resource_table.is_empty() {
            return Err(AuthorityError::TableNotEmpty);
        }
        let mut guard = self.inner.cspace.lock();
        self.check_incarnation(&guard)?;
        if guard.persistent_space_id().is_some() {
            return Err(AuthorityError::TeardownRejected);
        }
        let previous_incarnation = guard.incarnation();
        let killed = guard.reset();
        if guard.incarnation() == previous_incarnation {
            return Err(AuthorityError::TeardownRejected);
        }
        Ok(killed)
    }

    /// Install an attenuated volatile proxy for one durable resource.
    ///
    /// The exact source-space binding protects the trusted broker from cap
    /// collision and restart races. The durable source must carry `GRANT`; the
    /// proxy itself can never carry `GRANT`, `REVOKE`, or `INVOKE`.
    fn install_persistent_proxy<T: ComponentHostResource>(
        &self,
        source: &ComponentAuthoritySpace,
        source_cap: Cap,
        rights: Rights,
    ) -> Result<ComponentAuthority, AuthorityError> {
        const FORBIDDEN: Rights = Rights::GRANT.union(Rights::REVOKE).union(Rights::INVOKE);
        if self.inner.identity == source.inner.identity {
            return Err(AuthorityError::PersistentProxyTarget);
        }
        {
            let target_guard = self.inner.cspace.lock();
            self.check_incarnation(&target_guard)?;
            if target_guard.persistent_space_id().is_some() {
                return Err(AuthorityError::PersistentProxyTarget);
            }
        }
        if rights.intersect(FORBIDDEN) != Rights::NONE {
            return Err(AuthorityError::PersistentProxyRights);
        }
        if !T::OPERATION_RIGHTS.contains(rights) {
            return Err(AuthorityError::RightsExceedCeiling);
        }

        let source_guard = source.inner.cspace.lock();
        source.check_incarnation(&source_guard)?;
        let held = source_guard.rights_of(source_cap).map_err(map_cap_error)?;
        if !held.contains(Rights::GRANT) {
            return Err(AuthorityError::PersistentGrantRequired);
        }
        if !held.contains(rights) {
            return Err(AuthorityError::InsufficientRights);
        }
        let parent = source_guard
            .lookup_persistent_revocable::<T>(source_cap, rights.union(Rights::GRANT))
            .map_err(map_cap_error)?;
        drop(source_guard);

        let proxy = Arc::new(PersistentProxy { parent, rights });
        let mut target_guard = self.inner.cspace.lock();
        self.check_incarnation(&target_guard)?;
        if target_guard.persistent_space_id().is_some() {
            return Err(AuthorityError::PersistentProxyTarget);
        }
        let cap = target_guard.mint(proxy, rights);
        drop(target_guard);

        Ok(self.authority(cap, T::HOST_KIND, rights, AuthorityClass::PersistentProxy))
    }

    fn authority(
        &self,
        cap: Cap,
        kind: HostResourceKind,
        rights_ceiling: Rights,
        class: AuthorityClass,
    ) -> ComponentAuthority {
        ComponentAuthority {
            cspace_identity: self.inner.identity,
            cspace_incarnation: self.inner.incarnation,
            cap,
            kind,
            rights_ceiling,
            class,
        }
    }

    fn check_incarnation(&self, cspace: &CSpace) -> Result<(), AuthorityError> {
        if cspace.identity() != self.inner.identity {
            return Err(AuthorityError::WrongSpace);
        }
        if cspace.incarnation() != self.inner.incarnation {
            return Err(AuthorityError::IncarnationMismatch);
        }
        Ok(())
    }
}

/// Failure to transactionally publish one persistent proxy into a component
/// resource table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentProxyInstallError {
    TargetTable(ResourceError),
    Authority(AuthorityError),
}

/// Reserve component-table capacity before minting a boot-local persistent
/// proxy, then publish both pieces without another fallible step.
///
/// Keeping the raw mint operation private prevents a successful CSpace mint
/// from being stranded when a caller discovers only afterwards that the
/// component resource table is full.
pub fn install_persistent_proxy_owned<T: ComponentHostResource>(
    target_table: &mut ResourceTable<ComponentAuthority>,
    target_type: ResourceTypeId,
    target_space: &ComponentAuthoritySpace,
    source_space: &ComponentAuthoritySpace,
    source_cap: Cap,
    rights: Rights,
) -> Result<ResourceToken, PersistentProxyInstallError> {
    let reservation = target_table
        .reserve()
        .map_err(PersistentProxyInstallError::TargetTable)?;
    let authority = target_space
        .install_persistent_proxy::<T>(source_space, source_cap, rights)
        .map_err(PersistentProxyInstallError::Authority)?;
    Ok(reservation.commit(target_type, authority))
}

/// Component-facing authority with a redacted capability and exact CSpace route.
pub struct ComponentAuthority {
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
    cap: Cap,
    kind: HostResourceKind,
    rights_ceiling: Rights,
    class: AuthorityClass,
}

/// Opaque, detached proof that one exact volatile capability was validated as
/// a sealed supervisor transfer source.
///
/// This detached one-shot receipt is suitable for return from a reserved-space
/// callback. Its private fields and redacted debug output do not expose the
/// capability.
#[must_use = "the prepared authority must be published or its reserved CSpace reset"]
pub struct PreparedSupervisedEphemeralSource {
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
    cap: Cap,
    kind: HostResourceKind,
    rights_ceiling: Rights,
}

/// Opaque detached proof for one boot-local proxy whose durable parent was
/// resolved through an exact typed CSpace reference.
///
/// No durable identity, parent token, or local capability is exposed. The
/// one-shot receipt can leave a reserved-space callback for table publication
/// after registry postflight.
#[must_use = "the prepared proxy must be published or its reserved CSpace reset"]
pub struct PreparedSupervisedPersistentProxySource {
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
    cap: Cap,
    kind: HostResourceKind,
    rights_ceiling: Rights,
}

impl fmt::Debug for PreparedSupervisedPersistentProxySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSupervisedPersistentProxySource(<redacted>)")
    }
}

impl PreparedSupervisedPersistentProxySource {
    /// Materialize the already-validated proxy authority without lookup.
    pub const fn into_authority(self) -> ComponentAuthority {
        ComponentAuthority {
            cspace_identity: self.cspace_identity,
            cspace_incarnation: self.cspace_incarnation,
            cap: self.cap,
            kind: self.kind,
            rights_ceiling: self.rights_ceiling,
            class: AuthorityClass::PersistentProxy,
        }
    }
}

impl fmt::Debug for PreparedSupervisedEphemeralSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSupervisedEphemeralSource(<redacted>)")
    }
}

impl PreparedSupervisedEphemeralSource {
    /// Materialize the already-validated authority after the CSpace callback.
    /// This performs no allocation, lookup, or validation.
    pub const fn into_authority(self) -> ComponentAuthority {
        ComponentAuthority {
            cspace_identity: self.cspace_identity,
            cspace_incarnation: self.cspace_incarnation,
            cap: self.cap,
            kind: self.kind,
            rights_ceiling: self.rights_ceiling,
            class: AuthorityClass::EphemeralGrantSource,
        }
    }
}

impl fmt::Debug for ComponentAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentAuthority")
            .field("kind", &self.kind)
            .field("class", &self.class)
            .field("rights_ceiling", &self.rights_ceiling)
            .field("cspace", &"<redacted>")
            .field("cap", &"<redacted>")
            .finish()
    }
}

impl ComponentAuthority {
    /// Bind directly inside an already stable CSpace without retaining an Arc,
    /// lock owner, or resource pointer. The returned authority contains only
    /// the exact space identity/incarnation seal, opaque Cap, semantic kind,
    /// and non-amplifying rights ceiling.
    pub fn bind_ephemeral_in<T: ComponentHostResource>(
        cspace: &SpinLock<CSpace>,
        cap: Cap,
        rights_ceiling: Rights,
    ) -> Result<Self, AuthorityError> {
        let guard = cspace.lock();
        validate_ephemeral_cap::<T>(&guard, cap, rights_ceiling)?;
        let authority = Self {
            cspace_identity: guard.identity(),
            cspace_incarnation: guard.incarnation(),
            cap,
            kind: T::HOST_KIND,
            rights_ceiling,
            class: AuthorityClass::Ephemeral,
        };
        drop(guard);
        Ok(authority)
    }

    /// Seal one exact volatile cap as a supervisor-only transfer source.
    ///
    /// The held rights must equal the component operation ceiling plus
    /// `GRANT`; `REVOKE` and `INVOKE` are forbidden. Ordinary bindings continue
    /// to reject `GRANT`, so only this explicit constructor can enter the
    /// cross-principal derive-and-retire path.
    pub fn bind_supervised_ephemeral_source_in<T: ComponentHostResource>(
        cspace: &CSpace,
        cap: Cap,
        rights_ceiling: Rights,
    ) -> Result<Self, AuthorityError> {
        Self::prepare_supervised_ephemeral_source_in::<T>(cspace, cap, rights_ceiling)
            .map(PreparedSupervisedEphemeralSource::into_authority)
    }

    /// Validate inside a reserved-space callback and return a detached,
    /// non-duplicable receipt containing only copyable metadata for publication
    /// after that callback succeeds.
    pub fn prepare_supervised_ephemeral_source_in<T: ComponentHostResource>(
        cspace: &CSpace,
        cap: Cap,
        rights_ceiling: Rights,
    ) -> Result<PreparedSupervisedEphemeralSource, AuthorityError> {
        const FORBIDDEN: Rights = Rights::REVOKE.union(Rights::INVOKE);
        if rights_ceiling.intersect(Rights::GRANT.union(FORBIDDEN)) != Rights::NONE
            || !T::OPERATION_RIGHTS.contains(rights_ceiling)
        {
            return Err(AuthorityError::RightsExceedCeiling);
        }
        let held = cspace.rights_of(cap).map_err(map_cap_error)?;
        if held != rights_ceiling.union(Rights::GRANT) {
            return Err(if held.contains(Rights::GRANT) {
                AuthorityError::RightsExceedCeiling
            } else {
                AuthorityError::SupervisorGrantRequired
            });
        }
        drop(
            cspace
                .lookup_revocable::<T>(cap, Rights::NONE)
                .map_err(map_cap_error)?,
        );
        match cspace.persistent_witness::<T>(cap, Rights::NONE) {
            Ok(_) => return Err(AuthorityError::RawPersistentAuthority),
            Err(CapError::NotPersistent) => {}
            Err(error) => return Err(map_cap_error(error)),
        }
        Ok(PreparedSupervisedEphemeralSource {
            cspace_identity: cspace.identity(),
            cspace_incarnation: cspace.incarnation(),
            cap,
            kind: T::HOST_KIND,
            rights_ceiling,
        })
    }

    /// Mint a typed, boot-local persistent proxy into an exact volatile source
    /// CSpace for later sealed pair transfer.
    ///
    /// The durable parent is resolved at preparation time with `GRANT` plus the
    /// requested operation rights. Only its revocation-aware typed token enters
    /// the private proxy; no durable ID or raw persistent capability escapes.
    /// The local proxy never carries `GRANT`, `REVOKE`, or `INVOKE`.
    ///
    /// # Safety
    ///
    /// `target` must be an exclusively held, unpublished registry CSpace. The
    /// caller must reserve the matching ResourceTable entry before this call and
    /// publish the consumed receipt only after registry postflight. A failed
    /// postflight must not publish the receipt: the registry must retain the
    /// affected CSpace in sticky quarantine or tear it down through the exact
    /// reservation path. The callback must not let the receipt or minted proxy
    /// escape by any other path.
    pub unsafe fn prepare_supervised_persistent_proxy_source_in<T: ComponentHostResource>(
        target: &mut CSpace,
        source: &CSpace,
        source_cap: Cap,
        rights: Rights,
    ) -> Result<PreparedSupervisedPersistentProxySource, AuthorityError> {
        const FORBIDDEN: Rights = Rights::GRANT.union(Rights::REVOKE).union(Rights::INVOKE);
        if core::ptr::eq(target, source)
            || target.identity() == source.identity()
            || target.persistent_space_id().is_some()
        {
            return Err(AuthorityError::PersistentProxyTarget);
        }
        if source.persistent_space_id().is_none() {
            return Err(AuthorityError::PersistentAuthorityRequired);
        }
        if rights.intersect(FORBIDDEN) != Rights::NONE {
            return Err(AuthorityError::PersistentProxyRights);
        }
        if !T::OPERATION_RIGHTS.contains(rights) {
            return Err(AuthorityError::RightsExceedCeiling);
        }
        let held = source.rights_of(source_cap).map_err(map_cap_error)?;
        if !held.contains(Rights::GRANT) {
            return Err(AuthorityError::PersistentGrantRequired);
        }
        if !held.contains(rights) {
            return Err(AuthorityError::InsufficientRights);
        }
        let parent = source
            .lookup_persistent_revocable::<T>(source_cap, rights.union(Rights::GRANT))
            .map_err(map_cap_error)?;
        let cap = target.mint(Arc::new(PersistentProxy { parent, rights }), rights);
        Ok(PreparedSupervisedPersistentProxySource {
            cspace_identity: target.identity(),
            cspace_incarnation: target.incarnation(),
            cap,
            kind: T::HOST_KIND,
            rights_ceiling: rights,
        })
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights_ceiling(&self) -> Rights {
        self.rights_ceiling
    }

    pub const fn class(&self) -> AuthorityClass {
        self.class
    }

    /// Resolve from the current CSpace table for one operation. No `Arc<T>` or
    /// resource borrow can escape the higher-ranked callback.
    pub fn with_revocable<T, R, F>(
        &self,
        cspace: &SpinLock<CSpace>,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        self.with_cspace::<T, R, F>(cspace, need, operation)
    }

    /// Resolve a persistent proxy and revalidate its durable parent for the
    /// same operation.
    pub fn with_persistent_proxy<T, R, F>(
        &self,
        cspace: &SpinLock<CSpace>,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        if self.class != AuthorityClass::PersistentProxy {
            return Err(AuthorityError::PersistentAuthorityRequired);
        }
        self.with_revocable::<PersistentProxy<T>, _, _>(cspace, need, |proxy| {
            proxy.try_with(need, operation)
        })?
    }

    /// Resolve either authority class for one operation without exposing the
    /// different backing representation to a service implementation.
    pub fn with_resource<T, R, F>(
        &self,
        cspace: &SpinLock<CSpace>,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        match self.class {
            AuthorityClass::Ephemeral | AuthorityClass::EphemeralGrantSource => {
                self.with_revocable::<T, R, F>(cspace, need, operation)
            }
            AuthorityClass::PersistentProxy => {
                self.with_persistent_proxy::<T, R, F>(cspace, need, operation)
            }
        }
    }

    /// Resolve either authority class through an already-held exact CSpace.
    ///
    /// This is the pair-gate form of [`Self::with_resource`]: it retains no
    /// lock owner or CSpace wrapper and performs the complete identity,
    /// incarnation, rights, concrete backing type, local revocation, and (for
    /// a persistent proxy) durable-parent revocation check on every call.
    pub fn with_resource_in<T, R, F>(
        &self,
        cspace: &CSpace,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        if T::HOST_KIND != self.kind {
            return Err(AuthorityError::WrongResourceKind);
        }
        if !self.rights_ceiling.contains(need) {
            return Err(AuthorityError::RightsExceedCeiling);
        }
        if cspace.identity() != self.cspace_identity {
            return Err(AuthorityError::WrongSpace);
        }
        if cspace.incarnation() != self.cspace_incarnation {
            return Err(AuthorityError::IncarnationMismatch);
        }
        let held = cspace.rights_of(self.cap).map_err(map_cap_error)?;
        match self.class {
            AuthorityClass::Ephemeral => {
                if !self.rights_ceiling.contains(held) {
                    return Err(AuthorityError::RightsExceedCeiling);
                }
                let token = cspace
                    .lookup_revocable::<T>(self.cap, need)
                    .map_err(map_cap_error)?;
                token.try_with(operation).map_err(map_cap_error)
            }
            AuthorityClass::EphemeralGrantSource => {
                if held != self.rights_ceiling.union(Rights::GRANT) {
                    return Err(if held.contains(Rights::GRANT) {
                        AuthorityError::RightsExceedCeiling
                    } else {
                        AuthorityError::SupervisorGrantRequired
                    });
                }
                let token = cspace
                    .lookup_revocable::<T>(self.cap, need)
                    .map_err(map_cap_error)?;
                token.try_with(operation).map_err(map_cap_error)
            }
            AuthorityClass::PersistentProxy => {
                if !self.rights_ceiling.contains(held) {
                    return Err(AuthorityError::RightsExceedCeiling);
                }
                let token = cspace
                    .lookup_revocable::<PersistentProxy<T>>(self.cap, need)
                    .map_err(map_cap_error)?;
                token
                    .try_with(|proxy| proxy.try_with(need, operation))
                    .map_err(map_cap_error)?
            }
        }
    }

    fn with_cspace<T, R, F>(
        &self,
        cspace: &SpinLock<CSpace>,
        need: Rights,
        operation: F,
    ) -> Result<R, AuthorityError>
    where
        T: ComponentHostResource,
        F: for<'a> FnOnce(&'a T) -> R,
    {
        if T::HOST_KIND != self.kind {
            return Err(AuthorityError::WrongResourceKind);
        }
        if !self.rights_ceiling.contains(need) {
            return Err(AuthorityError::RightsExceedCeiling);
        }

        let guard = cspace.lock();
        if guard.identity() != self.cspace_identity {
            return Err(AuthorityError::WrongSpace);
        }
        if guard.incarnation() != self.cspace_incarnation {
            return Err(AuthorityError::IncarnationMismatch);
        }
        let held = guard.rights_of(self.cap).map_err(map_cap_error)?;
        match self.class {
            AuthorityClass::EphemeralGrantSource => {
                if held != self.rights_ceiling.union(Rights::GRANT) {
                    return Err(AuthorityError::RightsExceedCeiling);
                }
            }
            AuthorityClass::Ephemeral | AuthorityClass::PersistentProxy => {
                if !self.rights_ceiling.contains(held) {
                    return Err(AuthorityError::RightsExceedCeiling);
                }
            }
        }
        let token = guard
            .lookup_revocable::<T>(self.cap, need)
            .map_err(map_cap_error)?;
        drop(guard);
        token.try_with(operation).map_err(map_cap_error)
    }
}

fn validate_ephemeral_cap<T: ComponentHostResource>(
    cspace: &CSpace,
    cap: Cap,
    rights_ceiling: Rights,
) -> Result<(), AuthorityError> {
    let held = cspace.rights_of(cap).map_err(map_cap_error)?;

    // Resolve by the concrete caller-supplied T. `Resource::kind()` is not
    // trusted for this check because safe external implementations control it.
    drop(
        cspace
            .lookup_revocable::<T>(cap, Rights::NONE)
            .map_err(map_cap_error)?,
    );
    match cspace.persistent_witness::<T>(cap, Rights::NONE) {
        Ok(_) => return Err(AuthorityError::RawPersistentAuthority),
        Err(CapError::NotPersistent) => {}
        Err(error) => return Err(map_cap_error(error)),
    }
    if !rights_ceiling.contains(held)
        || !T::OPERATION_RIGHTS.contains(held)
        || !T::OPERATION_RIGHTS.contains(rights_ceiling)
    {
        return Err(AuthorityError::RightsExceedCeiling);
    }
    Ok(())
}

/// A boot-local, attenuated view of a durable resource.
///
/// The parent revocable token is private and has no identity accessor. Every
/// operation checks it again, so durable revocation is observed immediately.
pub struct PersistentProxy<T: ComponentHostResource> {
    parent: Revocable<T>,
    rights: Rights,
}

impl<T: ComponentHostResource> fmt::Debug for PersistentProxy<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentProxy")
            .field("kind", &T::HOST_KIND)
            .field("rights", &self.rights)
            .field("parent", &"<redacted>")
            .finish()
    }
}

impl<T: ComponentHostResource> PersistentProxy<T> {
    pub fn try_with<R, F>(&self, need: Rights, operation: F) -> Result<R, AuthorityError>
    where
        F: for<'a> FnOnce(&'a T) -> R,
    {
        if !self.rights.contains(need) {
            return Err(AuthorityError::RightsExceedCeiling);
        }
        self.parent.try_with(operation).map_err(map_cap_error)
    }
}

impl<T: ComponentHostResource> Resource for PersistentProxy<T> {
    fn kind(&self) -> &'static str {
        "component-persistent-proxy"
    }

    fn describe(&self) -> String {
        String::from("component persistent proxy")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<T: ComponentHostResource> ComponentHostResource for PersistentProxy<T> {
    const HOST_KIND: HostResourceKind = T::HOST_KIND;
    const OPERATION_RIGHTS: Rights = T::OPERATION_RIGHTS;
}
