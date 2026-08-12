//! Authority boundary for publishing committed CAS objects.
//!
//! This module deliberately knows nothing about `BlobKey`.  A successful CAS
//! commit supplies an opaque backend handle, and only that handle can be turned
//! into an [`AuthorizedObject`].  Publication creates a fresh capability root
//! for every object, even when two backend handles refer to shared physical
//! content.
//!
//! Publication is synchronous.  An async caller captures a
//! [`PublicationIntent`] before its first commit await, performs durable CAS
//! work without holding a capability-space lock, and consumes the intent only
//! after the new checkpoint has been reread and verified.

extern crate alloc;

use alloc::sync::Arc;
use core::marker::PhantomData;

/// A committed object which is eligible for capability publication.
///
/// The backend handle and stable object identity are intentionally not exposed.
/// Code outside the storage implementation can inspect harmless descriptive
/// fields, but it cannot turn a content digest into this token or extract a
/// physical address from it.
pub struct AuthorizedObject<H> {
    #[cfg_attr(not(test), allow(dead_code))]
    backend_handle: H,
    object_kind: u32,
    exact_len: u64,
}

impl<H> AuthorizedObject<H> {
    /// Construct authority only from a successful CAS commit.
    ///
    /// This remains crate-private so neither a digest nor caller-supplied
    /// metadata can manufacture publication authority.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn from_committed(
        backend_handle: H,
        object_kind: u32,
        exact_len: u64,
    ) -> Self {
        Self {
            backend_handle,
            object_kind,
            exact_len,
        }
    }

    /// Return the stable kind recorded by the committing storage backend.
    pub const fn object_kind(&self) -> u32 {
        self.object_kind
    }

    /// Return the exact logical byte length recorded at commit time.
    pub const fn exact_len(&self) -> u64 {
        self.exact_len
    }

    /// The CAS implementation may resolve this handle after a capability has
    /// already authorized the operation. It is never part of the public API.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn backend_handle(&self) -> &H {
        &self.backend_handle
    }
}

/// Publication failure deliberately distinguishes only target lifecycle from
/// an implementation failure. It contains no content-presence information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishError<E> {
    /// The target no longer has the incarnation captured before commit I/O.
    StaleIncarnation,
    /// The target could not install the new independent capability root.
    Target(E),
}

/// A synchronous target for one newly committed object.
///
/// Implementations must atomically compare `expected_incarnation` while
/// installing `object`; a check followed by a separate install is insufficient.
/// Every successful call must allocate a fresh derivation root. It must never
/// derive this object from a capability for another object, even if their CAS
/// backend handles share physical content.
pub trait ObjectPublicationTarget<H>: Send + Sync {
    /// The opaque capability returned for a newly published root.
    type Capability: Copy;
    /// A target-specific failure that does not reveal content presence.
    type Error;

    /// Return the target's current lifecycle incarnation.
    fn incarnation(&self) -> u64;

    /// Atomically publish `object` as a fresh root if the incarnation matches.
    fn publish_independent_root(
        &self,
        expected_incarnation: u64,
        object: Arc<AuthorizedObject<H>>,
    ) -> Result<Self::Capability, PublishError<Self::Error>>;
}

/// A target incarnation captured before durable commit I/O begins.
///
/// This value owns an `Arc` to the target, not a target lock or a borrowed
/// capability-table entry, so retaining it across an await does not retain a
/// lock guard.
#[must_use = "a publication intent must be consumed after commit or dropped"]
pub struct PublicationIntent<T: ?Sized, H> {
    target: Arc<T>,
    expected_incarnation: u64,
    marker: PhantomData<fn(H)>,
}

impl<T: ?Sized, H> PublicationIntent<T, H>
where
    T: ObjectPublicationTarget<H>,
{
    /// Capture the target and its current incarnation before durable I/O.
    pub fn capture(target: Arc<T>) -> Self {
        let expected_incarnation = target.incarnation();
        Self {
            target,
            expected_incarnation,
            marker: PhantomData,
        }
    }

    /// Return the incarnation captured by this intent.
    pub const fn expected_incarnation(&self) -> u64 {
        self.expected_incarnation
    }

    /// Publish a CAS-authorized object after its checkpoint is durable.
    ///
    /// There is intentionally no async work here. The target performs the
    /// incarnation comparison and root installation as one synchronous action.
    pub fn publish(
        self,
        object: AuthorizedObject<H>,
    ) -> Result<T::Capability, PublishError<T::Error>> {
        self.target
            .publish_independent_root(self.expected_incarnation, Arc::new(object))
    }
}

/// The sole externally observable object-resolution error.
///
/// A missing slot, revoked root, stale generation, absent READ right, wrong
/// object type, and backend object no longer admitted all collapse to this
/// value. Callers cannot use error shape to probe CAS presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// The requested capability does not currently authorize a readable object.
    Unavailable,
}

/// Capability-space operations used after publication.
///
/// The low-level resolver returns `None` for every failed authorization case.
/// [`resolve_authorized`] is the only public error mapping. No operation accepts
/// a digest, Merkle root, or BlobKey.
pub trait AuthorizedObjectSpace<H>: ObjectPublicationTarget<H> {
    /// Resolve an object only when `capability` grants live read authority.
    fn resolve_read(&self, capability: Self::Capability) -> Option<Arc<AuthorizedObject<H>>>;

    /// Administrative root revocation. Descendants of this exact root are the
    /// target implementation's responsibility; unrelated object roots must not
    /// be affected.
    fn revoke_root(&self, capability: Self::Capability) -> bool;
}

/// Resolve a capability while collapsing every denial into [`AccessError`].
pub fn resolve_authorized<S, H>(
    space: &S,
    capability: S::Capability,
) -> Result<Arc<AuthorizedObject<H>>, AccessError>
where
    S: AuthorizedObjectSpace<H> + ?Sized,
{
    space
        .resolve_read(capability)
        .ok_or(AccessError::Unavailable)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PrivateHandle {
        object_id: u128,
        // Test-only stand-in for a private BlobKey. The authority layer never
        // examines it and exposes no lookup operation for it.
        shared_content: [u8; 32],
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ModelCapability {
        slot: u32,
        generation: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelPublishError {
        SlotExhausted,
    }

    struct ModelSlot<H> {
        generation: u64,
        readable: bool,
        alive: bool,
        object: Arc<AuthorizedObject<H>>,
    }

    struct ModelState<H> {
        incarnation: u64,
        slots: Vec<ModelSlot<H>>,
    }

    struct ModelSpace<H> {
        state: Mutex<ModelState<H>>,
    }

    impl<H> ModelSpace<H> {
        fn new() -> Self {
            Self {
                state: Mutex::new(ModelState {
                    incarnation: 1,
                    slots: Vec::new(),
                }),
            }
        }

        fn restart(&self) {
            let mut state = self.state.lock().unwrap();
            state.incarnation = state.incarnation.checked_add(1).unwrap();
            state.slots.clear();
        }

        fn deny_read(&self, capability: ModelCapability) {
            let mut state = self.state.lock().unwrap();
            let Some(slot) = state.slots.get_mut(capability.slot as usize) else {
                return;
            };
            if slot.generation == capability.generation {
                slot.readable = false;
            }
        }
    }

    impl<H: Send + Sync + 'static> ObjectPublicationTarget<H> for ModelSpace<H> {
        type Capability = ModelCapability;
        type Error = ModelPublishError;

        fn incarnation(&self) -> u64 {
            self.state.lock().unwrap().incarnation
        }

        fn publish_independent_root(
            &self,
            expected_incarnation: u64,
            object: Arc<AuthorizedObject<H>>,
        ) -> Result<Self::Capability, PublishError<Self::Error>> {
            let mut state = self.state.lock().unwrap();
            if state.incarnation != expected_incarnation {
                return Err(PublishError::StaleIncarnation);
            }
            let slot = u32::try_from(state.slots.len())
                .map_err(|_| PublishError::Target(ModelPublishError::SlotExhausted))?;
            // Each slot owns a distinct liveness bit. Sharing backend content
            // cannot couple revocation between these roots.
            state.slots.push(ModelSlot {
                generation: 1,
                readable: true,
                alive: true,
                object,
            });
            Ok(ModelCapability {
                slot,
                generation: 1,
            })
        }
    }

    impl<H: Send + Sync + 'static> AuthorizedObjectSpace<H> for ModelSpace<H> {
        fn resolve_read(&self, capability: Self::Capability) -> Option<Arc<AuthorizedObject<H>>> {
            let state = self.state.lock().unwrap();
            let slot = state.slots.get(capability.slot as usize)?;
            if slot.generation != capability.generation || !slot.alive || !slot.readable {
                return None;
            }
            Some(slot.object.clone())
        }

        fn revoke_root(&self, capability: Self::Capability) -> bool {
            let mut state = self.state.lock().unwrap();
            let Some(slot) = state.slots.get_mut(capability.slot as usize) else {
                return false;
            };
            if slot.generation != capability.generation || !slot.alive {
                return false;
            }
            slot.alive = false;
            true
        }
    }

    fn committed(object_id: u128, shared_content: [u8; 32]) -> AuthorizedObject<PrivateHandle> {
        AuthorizedObject::from_committed(
            PrivateHandle {
                object_id,
                shared_content,
            },
            7,
            4096,
        )
    }

    #[test]
    fn shared_content_gets_independent_revocation_roots() {
        let space = Arc::new(ModelSpace::new());
        let shared_content = [0x5a; 32];
        let first = PublicationIntent::capture(space.clone())
            .publish(committed(1, shared_content))
            .unwrap();
        let second = PublicationIntent::capture(space.clone())
            .publish(committed(2, shared_content))
            .unwrap();

        let first_object = resolve_authorized(space.as_ref(), first).unwrap();
        let second_object = resolve_authorized(space.as_ref(), second).unwrap();
        assert_eq!(
            first_object.backend_handle().shared_content,
            second_object.backend_handle().shared_content
        );
        assert_ne!(
            first_object.backend_handle().object_id,
            second_object.backend_handle().object_id
        );

        assert!(space.revoke_root(first));
        assert_eq!(
            resolve_authorized(space.as_ref(), first).map(|_| ()),
            Err(AccessError::Unavailable)
        );
        assert_eq!(
            resolve_authorized(space.as_ref(), second)
                .unwrap()
                .backend_handle()
                .object_id,
            2
        );
    }

    #[test]
    fn stale_target_incarnation_cannot_receive_committed_object() {
        let space = Arc::new(ModelSpace::new());
        let intent = PublicationIntent::capture(space.clone());
        assert_eq!(intent.expected_incarnation(), 1);
        space.restart();
        assert_eq!(
            intent.publish(committed(1, [1; 32])),
            Err(PublishError::StaleIncarnation)
        );
    }

    #[test]
    fn missing_and_unauthorized_are_indistinguishable() {
        let space = Arc::new(ModelSpace::new());
        let denied = PublicationIntent::capture(space.clone())
            .publish(committed(1, [2; 32]))
            .unwrap();
        space.deny_read(denied);
        let missing = ModelCapability {
            slot: 999,
            generation: 1,
        };

        let denied_error = resolve_authorized(space.as_ref(), denied)
            .map(|_| ())
            .unwrap_err();
        let missing_error = resolve_authorized(space.as_ref(), missing)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(denied_error, AccessError::Unavailable);
        assert_eq!(missing_error, AccessError::Unavailable);
        assert_eq!(denied_error, missing_error);
    }
}
