//! The capability system is the security core. It gets the densest tests in the
//! tree: every invariant in BLUEPRINT.md §3 has a case here, and every
//! `CapError` variant has a case that produces it.

use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vibeos_core::cap::{
    grant, CSpace, CSpaceResetError, CapError, PersistentInstallError, PersistentResourceWitness,
    Resource, Rights, ScopedResource, CAPABILITY_TABLE_PAGE_SIZE, MAX_PERSISTENT_SLOTS,
};
use vibeos_core::heap::{current_owner, enter_owner, OwnerId};
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantFlags, GrantRecord, ObjectId, RecoveredGrant, RecoveredSlot,
    ResourceKind, SlotIdentity, SpaceId, TransactionId,
};

struct Widget(&'static str);
struct Gadget;

struct DropTrackedWidget {
    drops: Arc<AtomicUsize>,
}

#[derive(Debug, PartialEq, Eq)]
struct ScopedWindow {
    first: u64,
    count: u64,
    allocation_owner: OwnerId,
}

/// A safe but dishonest implementation. Typed resolution must follow the
/// trait object's actual dynamic type, never this method's answer.
struct Liar {
    disguise: Gadget,
}

impl Resource for Widget {
    fn kind(&self) -> &'static str {
        "widget"
    }
    fn describe(&self) -> String {
        self.0.to_string()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Resource for Gadget {
    fn kind(&self) -> &'static str {
        "gadget"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Resource for DropTrackedWidget {
    fn kind(&self) -> &'static str {
        "drop-tracked-widget"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Resource for ScopedWindow {
    fn kind(&self) -> &'static str {
        "scoped-window"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Safety: the implementation preserves the same logical window identity and
// constructs only a checked non-empty subset without external side effects.
unsafe impl ScopedResource for ScopedWindow {
    type Scope = (u64, u64);

    fn attenuate(&self, (relative_first, count): Self::Scope) -> Option<Arc<Self>> {
        let relative_end = relative_first.checked_add(count)?;
        if count == 0 || relative_end > self.count {
            return None;
        }
        Some(Arc::new(Self {
            first: self.first.checked_add(relative_first)?,
            count,
            allocation_owner: current_owner(),
        }))
    }
}

impl Drop for DropTrackedWidget {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl Resource for Liar {
    fn kind(&self) -> &'static str {
        "liar"
    }
    fn as_any(&self) -> &dyn Any {
        &self.disguise
    }
}

fn space() -> (CSpace, Arc<Widget>) {
    (CSpace::new("test"), Arc::new(Widget("w")))
}

#[test]
fn cspace_identity_is_unique_redacted_and_stable_across_reset() {
    let mut first = CSpace::new("first");
    let second = CSpace::new("second");
    let first_identity = first.identity();

    assert_ne!(first_identity, second.identity());
    assert_eq!(format!("{first_identity:?}"), "CSpaceIdentity(<redacted>)");
    assert!(!format!("{first_identity:?}").contains(char::is_numeric));

    assert_eq!(first.incarnation(), 1);
    assert_eq!(first.reset(), 0);
    assert_eq!(first.identity(), first_identity);
    assert_eq!(first.incarnation(), 2);
}

#[test]
fn exact_cspace_reset_rejects_identity_incarnation_and_aba_without_mutation() {
    let mut space = CSpace::new("exact-reset");
    let other = CSpace::new("foreign-reset");
    let identity = space.identity();
    let incarnation = space.incarnation();
    let cap = space.mint(Arc::new(Widget("live")), Rights::READ);

    assert_eq!(
        space.reset_exact(other.identity(), incarnation),
        Err(CSpaceResetError::IdentityMismatch)
    );
    assert_eq!(space.identity(), identity);
    assert_eq!(space.incarnation(), incarnation);
    assert_eq!(
        space.lookup_as::<Widget>(cap, Rights::READ).unwrap().0,
        "live"
    );

    assert_eq!(
        space.reset_exact(identity, incarnation + 1),
        Err(CSpaceResetError::IncarnationMismatch)
    );
    assert_eq!(space.incarnation(), incarnation);
    assert!(space.lookup_as::<Widget>(cap, Rights::READ).is_ok());

    assert_eq!(space.preflight_reset_exact(identity, incarnation), Ok(()));
    assert_eq!(space.incarnation(), incarnation);
    assert!(
        space.lookup_as::<Widget>(cap, Rights::READ).is_ok(),
        "reset preflight must not revoke live authority"
    );

    assert_eq!(space.reset_exact(identity, incarnation), Ok(1));
    assert_eq!(space.incarnation(), incarnation + 1);
    assert_eq!(
        space.lookup(cap, Rights::READ).err(),
        Some(CapError::Invalid)
    );
    let fresh = space.mint(Arc::new(Widget("fresh")), Rights::READ);

    assert_eq!(
        space.preflight_reset_exact(identity, incarnation),
        Err(CSpaceResetError::IncarnationMismatch)
    );

    assert_eq!(
        space.reset_exact(identity, incarnation),
        Err(CSpaceResetError::IncarnationMismatch),
        "a repeated stale reset cannot cross the incarnation boundary"
    );
    assert_eq!(space.incarnation(), incarnation + 1);
    assert_eq!(
        space.lookup_as::<Widget>(fresh, Rights::READ).unwrap().0,
        "fresh",
        "a stale reset cannot revoke authority from the replacement incarnation"
    );
}

#[test]
fn exact_admin_revoke_never_targets_a_reused_slot() {
    let mut space = CSpace::new("exact-admin-revoke");
    let stale = space.mint(Arc::new(Widget("old")), Rights::READ);
    assert_eq!(space.revoke_slot(stale.slot()), 1);
    let replacement = space.mint(Arc::new(Widget("replacement")), Rights::READ);
    assert_eq!(replacement.slot(), stale.slot());
    assert_ne!(replacement, stale);

    assert_eq!(space.revoke_exact_admin(stale), Err(CapError::Invalid));
    assert_eq!(
        space
            .lookup_as::<Widget>(replacement, Rights::READ)
            .unwrap()
            .0,
        "replacement",
    );
}

fn stable<T>(value: u128, constructor: fn(u128) -> Option<T>) -> T {
    constructor(value).unwrap()
}

fn durable_grant(
    transaction: u128,
    derivation: u128,
    parent: Option<u128>,
    object: u128,
    space: SpaceId,
    slot: u32,
    generation: u64,
    rights: DurableRights,
    kind: ResourceKind,
) -> RecoveredGrant {
    RecoveredGrant {
        grant: GrantRecord {
            derivation_id: stable(derivation, DerivationId::new),
            parent_id: parent.map(|id| stable(id, DerivationId::new)),
            object_id: stable(object, ObjectId::new),
            target: SlotIdentity {
                space,
                slot,
                generation,
            },
            rights,
            resource_kind: kind,
            flags: if parent.is_none() {
                GrantFlags::ROOT
            } else {
                GrantFlags::DERIVED
            },
        },
        transaction_id: stable(transaction, TransactionId::new),
        prepare_sequence: transaction as u64 * 2,
        commit_sequence: transaction as u64 * 2 + 1,
    }
}

#[test]
fn published_capability_tables_are_page_aligned_and_replaced_by_cow() {
    let (mut cs, widget) = space();
    assert_eq!(cs.capability_table_range(), None);

    let root = cs.mint(widget, Rights::ALL);
    let first = cs.capability_table_range().unwrap();
    assert_eq!(first.slot_count, 1);

    let child = cs.derive(root, Rights::READ.union(Rights::REVOKE)).unwrap();
    let second = cs.capability_table_range().unwrap();
    assert_eq!(second.slot_count, 2);
    assert_ne!(second.start, first.start);
    assert_eq!(cs.lookup_as::<Widget>(root, Rights::READ).unwrap().0, "w");
    assert_eq!(cs.lookup_as::<Widget>(child, Rights::READ).unwrap().0, "w");

    assert_eq!(cs.revoke(child), Ok(1));
    let third = cs.capability_table_range().unwrap();
    assert_ne!(third.start, second.start);
    assert_eq!(third.slot_count, 2, "vacant slots retain their generation");
    assert_eq!(
        cs.lookup(child, Rights::READ).err(),
        Some(CapError::Invalid)
    );
    assert_eq!(cs.lookup_as::<Widget>(root, Rights::READ).unwrap().0, "w");

    let replacement = cs.mint(Arc::new(Widget("replacement")), Rights::READ);
    let fourth = cs.capability_table_range().unwrap();
    assert_ne!(fourth.start, third.start);
    assert_eq!(
        cs.lookup(child, Rights::READ).err(),
        Some(CapError::Invalid)
    );
    assert_eq!(
        cs.lookup_as::<Widget>(replacement, Rights::READ).unwrap().0,
        "replacement"
    );

    for range in [first, second, third, fourth] {
        assert_eq!(range.start % CAPABILITY_TABLE_PAGE_SIZE, 0);
        assert!(range.page_count > 0);
        let byte_len = range
            .page_count
            .checked_mul(CAPABILITY_TABLE_PAGE_SIZE)
            .unwrap();
        assert_eq!(byte_len % CAPABILITY_TABLE_PAGE_SIZE, 0);
        assert!(range.start.checked_add(byte_len).is_some());
    }
}

// --- Invariant 3: rights are checked at use ---

#[test]
fn lookup_requires_the_named_right() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ.union(Rights::WRITE));
    assert!(cs.lookup(c, Rights::READ).is_ok());
    assert!(cs.lookup(c, Rights::WRITE).is_ok());
    assert!(cs.lookup(c, Rights::READ.union(Rights::WRITE)).is_ok());
    assert_eq!(
        cs.lookup(c, Rights::SEND).err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn holding_a_handle_is_not_permission() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::NONE);
    // The handle resolves to a live slot, and still authorises nothing.
    assert!(cs.rights_of(c).is_ok());
    for r in [
        Rights::READ,
        Rights::WRITE,
        Rights::SEND,
        Rights::RECV,
        Rights::GRANT,
    ] {
        assert_eq!(cs.lookup(c, r).err(), Some(CapError::InsufficientRights));
    }
}

// --- Invariant 2: monotone attenuation ---

#[test]
fn derive_requires_grant() {
    let (mut cs, w) = space();
    let no_grant = cs.mint(w, Rights::READ.union(Rights::WRITE));
    assert_eq!(
        cs.derive(no_grant, Rights::READ).err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn derive_cannot_amplify() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ.union(Rights::GRANT));
    assert_eq!(
        cs.derive(c, Rights::WRITE).err(),
        Some(CapError::Amplification)
    );
    assert_eq!(
        cs.derive(c, Rights::READ.union(Rights::REVOKE)).err(),
        Some(CapError::Amplification)
    );
}

#[test]
fn derive_produces_a_strict_subset() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::ALL);
    let weak = cs.derive(c, Rights::READ).unwrap();
    assert!(cs.lookup(weak, Rights::READ).is_ok());
    assert_eq!(
        cs.lookup(weak, Rights::WRITE).err(),
        Some(CapError::InsufficientRights)
    );
    // ...and the parent is untouched.
    assert!(cs.lookup(c, Rights::WRITE).is_ok());
}

#[test]
fn derived_caps_cannot_re_widen_through_a_chain() {
    let (mut cs, w) = space();
    let root = cs.mint(w, Rights::ALL);
    let mid = cs.derive(root, Rights::READ.union(Rights::GRANT)).unwrap();
    let leaf = cs.derive(mid, Rights::READ).unwrap();
    assert_eq!(
        cs.derive(mid, Rights::WRITE).err(),
        Some(CapError::Amplification)
    );
    assert_eq!(
        cs.derive(leaf, Rights::READ).err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn scoped_derivation_narrows_resource_and_rights_together() {
    let mut cs = CSpace::new("scoped");
    let root = cs.mint(
        Arc::new(ScopedWindow {
            first: 1_000,
            count: 500,
            allocation_owner: OwnerId::SYSTEM,
        }),
        Rights::ALL,
    );
    let child = cs
        .derive_scoped::<ScopedWindow>(root, (100, 200), Rights::READ.union(Rights::GRANT))
        .unwrap();
    let observed = cs
        .lookup_lease::<ScopedWindow>(child, Rights::READ)
        .unwrap();
    assert_eq!(
        observed.with(|window| (window.first, window.count)),
        (1_100, 200)
    );
    assert_eq!(
        cs.derive_scoped::<ScopedWindow>(child, (0, 201), Rights::READ),
        Err(CapError::Amplification)
    );
    assert_eq!(
        cs.derive_scoped::<ScopedWindow>(child, (0, 1), Rights::WRITE),
        Err(CapError::Amplification)
    );
}

#[test]
fn scoped_child_keeps_cross_space_revocation_ancestry() {
    let mut source = CSpace::new("source");
    let mut target = CSpace::new("target");
    let root = source.mint(
        Arc::new(ScopedWindow {
            first: 64,
            count: 512,
            allocation_owner: OwnerId::SYSTEM,
        }),
        Rights::ALL,
    );
    let child = source
        .derive_scoped::<ScopedWindow>(root, (16, 32), Rights::READ.union(Rights::GRANT))
        .unwrap();
    let remote = grant(&source, child, Rights::READ, &mut target).unwrap();
    assert!(target
        .lookup_lease::<ScopedWindow>(remote, Rights::READ)
        .is_ok());
    assert_eq!(source.revoke(root), Ok(2));
    assert_eq!(
        target
            .lookup_lease::<ScopedWindow>(remote, Rights::READ)
            .err(),
        Some(CapError::Invalid)
    );
}

#[test]
fn scoped_derivation_allocates_the_published_resource_to_system() {
    let mut cs = CSpace::new("scoped-allocation");
    let root = cs.mint(
        Arc::new(ScopedWindow {
            first: 0,
            count: 16,
            allocation_owner: OwnerId::SYSTEM,
        }),
        Rights::ALL,
    );
    let component_owner = OwnerId::new(901);
    let child = {
        let _component = enter_owner(component_owner);
        cs.derive_scoped::<ScopedWindow>(root, (4, 4), Rights::READ)
            .unwrap()
    };
    let child = cs
        .lookup_lease::<ScopedWindow>(child, Rights::READ)
        .unwrap();
    assert_eq!(
        child.with(|window| window.allocation_owner),
        OwnerId::SYSTEM
    );
}

// --- Invariant 4: revocation is immediate and retroactive ---

#[test]
fn revoke_invalidates_outstanding_handles() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::ALL);
    let copy = c; // a second holder's handle
    assert_eq!(cs.revoke(c).unwrap(), 1);
    assert_eq!(cs.lookup(copy, Rights::READ).err(), Some(CapError::Invalid));
}

#[test]
fn revoke_cascades_to_the_whole_derivation_subtree() {
    let (mut cs, w) = space();
    let root = cs.mint(w, Rights::ALL);
    let a = cs.derive(root, Rights::READ.union(Rights::GRANT)).unwrap();
    let b = cs.derive(a, Rights::READ.union(Rights::GRANT)).unwrap();
    let c = cs.derive(root, Rights::WRITE).unwrap();

    assert_eq!(
        cs.revoke(a).err(),
        Some(CapError::InsufficientRights),
        "a has no REVOKE"
    );
    assert_eq!(cs.revoke_slot(a.slot()), 2, "a and its descendant b");
    assert_eq!(cs.lookup(a, Rights::READ).err(), Some(CapError::Invalid));
    assert_eq!(cs.lookup(b, Rights::READ).err(), Some(CapError::Invalid));
    assert!(
        cs.lookup(c, Rights::WRITE).is_ok(),
        "a sibling branch survives"
    );
    assert!(cs.lookup(root, Rights::READ).is_ok(), "the parent survives");
}

#[test]
fn revoke_requires_the_revoke_right() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ);
    assert_eq!(cs.revoke(c).err(), Some(CapError::InsufficientRights));
}

#[test]
fn a_reused_slot_does_not_honour_the_old_handle() {
    let (mut cs, w) = space();
    let old = cs.mint(w.clone(), Rights::ALL);
    cs.revoke_slot(old.slot());
    // The allocator hands the same slot to the next mint; the generation is
    // what keeps the stale handle from resolving.
    let fresh = cs.mint(w, Rights::ALL);
    assert_eq!(fresh.slot(), old.slot());
    assert_eq!(cs.lookup(old, Rights::READ).err(), Some(CapError::Invalid));
    assert!(cs.lookup(fresh, Rights::READ).is_ok());
}

// --- Typed lookup ---

#[test]
fn typed_lookup_rejects_the_wrong_type() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::ALL);
    assert!(cs.lookup_as::<Widget>(c, Rights::READ).is_ok());
    assert_eq!(
        cs.lookup_as::<Gadget>(c, Rights::READ).err(),
        Some(CapError::WrongType)
    );
}

#[test]
fn typed_resolve_ignores_a_dishonest_as_any_implementation() {
    let mut cs = CSpace::new("liar-test");
    let cap = cs.mint(Arc::new(Liar { disguise: Gadget }), Rights::ALL);

    assert_eq!(
        cs.lookup_as::<Gadget>(cap, Rights::READ).err(),
        Some(CapError::WrongType)
    );
    assert_eq!(
        cs.lookup_revocable::<Gadget>(cap, Rights::READ).err(),
        Some(CapError::WrongType)
    );
    assert_eq!(
        cs.lookup_lease::<Gadget>(cap, Rights::READ).err(),
        Some(CapError::WrongType)
    );
}

#[test]
fn typed_lookup_checks_rights_before_type() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ);
    // Wrong type *and* missing rights: rights win, so a caller cannot use type
    // confusion to learn what a resource is without authority over it.
    assert_eq!(
        cs.lookup_as::<Gadget>(c, Rights::WRITE).err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn legacy_tcb_typed_lookup_returns_an_owned_arc_lease() {
    let (mut cs, w) = space();
    let c = cs.mint(w.clone(), Rights::ALL);
    let before = Arc::strong_count(&w);
    {
        let got = cs.lookup_as::<Widget>(c, Rights::READ).unwrap();
        assert_eq!(got.0, "w");
        assert!(Arc::strong_count(&w) > before, "lookup holds a reference");
    }
    assert_eq!(Arc::strong_count(&w), before, "and releases it on drop");
}

// --- ROADMAP 3.16: explicit resolved-capability leases ---

#[test]
fn revocable_token_revalidates_after_local_revoke() {
    let (mut cs, w) = space();
    let cap = cs.mint(w, Rights::ALL);
    let token = cs.lookup_revocable::<Widget>(cap, Rights::READ).unwrap();
    let token_copy = token.clone();

    assert_eq!(token.try_with(|widget| widget.0), Ok("w"));
    assert_eq!(cs.revoke(cap).unwrap(), 1);
    assert_eq!(
        token.try_with(|widget| widget.0),
        Err(CapError::Invalid),
        "an already-resolved token must check its node again"
    );
    assert_eq!(
        token_copy.try_with(|widget| widget.0),
        Err(CapError::Invalid),
        "cloning the token must not cache a successful validity check"
    );
}

#[test]
fn revocable_token_observes_ancestor_revoke_in_the_same_space() {
    let (mut cs, w) = space();
    let root = cs.mint(w, Rights::ALL);
    let child = cs.derive(root, Rights::READ).unwrap();
    let token = cs.lookup_revocable::<Widget>(child, Rights::READ).unwrap();

    assert_eq!(token.try_with(|widget| widget.0), Ok("w"));
    assert_eq!(cs.revoke(root).unwrap(), 2);
    assert_eq!(token.try_with(|widget| widget.0), Err(CapError::Invalid));
}

#[test]
fn revocable_token_observes_ancestor_revoke_across_spaces() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let root = src.mint(w, Rights::ALL);
    let granted = grant(&src, root, Rights::READ, &mut dst).unwrap();
    let token = dst
        .lookup_revocable::<Widget>(granted, Rights::READ)
        .unwrap();

    assert_eq!(token.try_with(|widget| widget.0), Ok("w"));
    src.revoke(root).unwrap();
    assert_eq!(token.try_with(|widget| widget.0), Err(CapError::Invalid));
}

#[test]
fn invocation_lease_survives_revoke_but_a_new_lease_does_not() {
    let (mut cs, w) = space();
    let cap = cs.mint(w, Rights::ALL);
    let lease = cs.lookup_lease::<Widget>(cap, Rights::READ).unwrap();

    assert_eq!(lease.with(|widget| widget.0), "w");
    cs.revoke(cap).unwrap();
    assert_eq!(
        lease.with(|widget| widget.0),
        "w",
        "revocation does not interrupt an invocation that already owns a lease"
    );
    assert_eq!(
        cs.lookup_lease::<Widget>(cap, Rights::READ).err(),
        Some(CapError::Invalid),
        "revocation prevents the next invocation from acquiring a lease"
    );
}

#[test]
fn invocation_lease_retains_actual_rights_for_service_side_enforcement() {
    let mut cs = CSpace::new("service-rights");
    let read = cs.mint(Arc::new(Widget("read")), Rights::READ);
    let none = cs.mint(Arc::new(Widget("none")), Rights::NONE);

    // Even a lookup which asks for NONE records the slot's real authority;
    // service methods, rather than callers, choose the right they require.
    let read_lease = cs.lookup_lease::<Widget>(read, Rights::NONE).unwrap();
    assert!(read_lease.authorizes(Rights::READ));
    assert!(!read_lease.authorizes(Rights::WRITE));

    let none_lease = cs.lookup_lease::<Widget>(none, Rights::NONE).unwrap();
    assert!(!none_lease.authorizes(Rights::READ));
    assert!(!none_lease.authorizes(Rights::WRITE));
}

#[test]
fn cross_space_invocation_lease_survives_only_if_already_acquired() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let root = src.mint(w, Rights::ALL);
    let granted = grant(&src, root, Rights::READ, &mut dst).unwrap();
    let lease = dst.lookup_lease::<Widget>(granted, Rights::READ).unwrap();

    src.revoke(root).unwrap();
    assert_eq!(lease.with(|widget| widget.0), "w");
    assert_eq!(
        dst.lookup_lease::<Widget>(granted, Rights::READ).err(),
        Some(CapError::Invalid)
    );
}

#[test]
fn resolved_token_apis_preserve_invalid_rights_type_error_order() {
    let (mut cs, w) = space();
    let cap = cs.mint(w, Rights::READ);

    assert_eq!(
        cs.lookup_revocable::<Gadget>(cap, Rights::WRITE).err(),
        Some(CapError::InsufficientRights)
    );
    assert_eq!(
        cs.lookup_lease::<Gadget>(cap, Rights::WRITE).err(),
        Some(CapError::InsufficientRights)
    );
    assert_eq!(
        cs.lookup_revocable::<Gadget>(cap, Rights::READ).err(),
        Some(CapError::WrongType)
    );
    assert_eq!(
        cs.lookup_lease::<Gadget>(cap, Rights::READ).err(),
        Some(CapError::WrongType)
    );

    cs.revoke_slot(cap.slot());
    assert_eq!(
        cs.lookup_revocable::<Gadget>(cap, Rights::WRITE).err(),
        Some(CapError::Invalid)
    );
    assert_eq!(
        cs.lookup_lease::<Gadget>(cap, Rights::WRITE).err(),
        Some(CapError::Invalid)
    );
}

#[test]
fn resolved_tokens_own_exactly_one_object_reference_and_release_it_on_drop() {
    let (mut cs, w) = space();
    let cap = cs.mint(w.clone(), Rights::ALL);
    let baseline = Arc::strong_count(&w);

    let token = cs.lookup_revocable::<Widget>(cap, Rights::READ).unwrap();
    assert_eq!(Arc::strong_count(&w), baseline + 1);
    let token_copy = token.clone();
    assert_eq!(Arc::strong_count(&w), baseline + 2);
    drop(token_copy);
    drop(token);
    assert_eq!(Arc::strong_count(&w), baseline);

    let lease = cs.lookup_lease::<Widget>(cap, Rights::READ).unwrap();
    assert_eq!(Arc::strong_count(&w), baseline + 1);
    drop(lease);
    assert_eq!(Arc::strong_count(&w), baseline);
}

#[test]
fn resolved_tokens_keep_the_resource_alive_only_until_their_drop() {
    let (mut revocable_space, revocable_object) = space();
    let revocable_weak = Arc::downgrade(&revocable_object);
    let cap = revocable_space.mint(revocable_object.clone(), Rights::ALL);
    let token = revocable_space
        .lookup_revocable::<Widget>(cap, Rights::READ)
        .unwrap();
    drop(revocable_object);
    drop(revocable_space);
    assert!(revocable_weak.upgrade().is_some());
    drop(token);
    assert!(revocable_weak.upgrade().is_none());

    let (mut lease_space, lease_object) = space();
    let lease_weak = Arc::downgrade(&lease_object);
    let cap = lease_space.mint(lease_object.clone(), Rights::ALL);
    let lease = lease_space
        .lookup_lease::<Widget>(cap, Rights::READ)
        .unwrap();
    drop(lease_object);
    drop(lease_space);
    assert!(lease_weak.upgrade().is_some());
    drop(lease);
    assert!(lease_weak.upgrade().is_none());
}

// --- Cross-space grant ---

#[test]
fn grant_moves_authority_between_spaces_with_attenuation() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let c = src.mint(w, Rights::ALL);

    let given = grant(&src, c, Rights::READ, &mut dst).unwrap();
    assert!(dst.lookup(given, Rights::READ).is_ok());
    assert_eq!(
        dst.lookup(given, Rights::WRITE).err(),
        Some(CapError::InsufficientRights)
    );
}

#[test]
fn grant_requires_grant_and_refuses_amplification() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");

    let no_grant = src.mint(w.clone(), Rights::READ);
    assert_eq!(
        grant(&src, no_grant, Rights::READ, &mut dst).err(),
        Some(CapError::InsufficientRights)
    );

    let partial = src.mint(w, Rights::READ.union(Rights::GRANT));
    assert_eq!(
        grant(&src, partial, Rights::WRITE, &mut dst).err(),
        Some(CapError::Amplification)
    );
}

#[test]
fn a_handle_is_meaningless_in_another_space() {
    let (mut a, w) = space();
    let mut b = CSpace::new("b");
    let ca = a.mint(w.clone(), Rights::ALL);
    b.mint(Arc::new(Gadget), Rights::ALL);
    // Same slot number, different space: resolving there must not yield a's object.
    assert_eq!(
        b.lookup_as::<Widget>(ca, Rights::READ).err(),
        Some(CapError::WrongType)
    );
}

/// ROADMAP 1.8. Revoking the source of a cross-space grant kills the copy,
/// even though the revoker cannot reach — and does not know about — the space
/// the copy ended up in.
#[test]
fn revoke_reaches_copies_in_other_spaces() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let c = src.mint(w, Rights::ALL);
    let given = grant(&src, c, Rights::READ, &mut dst).unwrap();
    assert!(dst.lookup(given, Rights::READ).is_ok());

    src.revoke(c).unwrap();
    assert_eq!(
        dst.lookup(given, Rights::READ).err(),
        Some(CapError::Invalid),
        "the copy died with its ancestor"
    );
}

#[test]
fn revocation_cascades_through_a_chain_of_spaces() {
    let (mut a, w) = space();
    let mut b = CSpace::new("b");
    let mut c = CSpace::new("c");

    let root = a.mint(w, Rights::ALL);
    let in_b = grant(&a, root, Rights::READ.union(Rights::GRANT), &mut b).unwrap();
    let in_c = grant(&b, in_b, Rights::READ, &mut c).unwrap();
    assert!(c.lookup(in_c, Rights::READ).is_ok());

    // Cut the chain at the middle link: c dies, a survives.
    b.revoke_slot(in_b.slot());
    assert_eq!(c.lookup(in_c, Rights::READ).err(), Some(CapError::Invalid));
    assert!(a.lookup(root, Rights::READ).is_ok());
}

#[test]
fn revoking_a_grant_does_not_touch_the_source() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let c = src.mint(w, Rights::ALL);
    let given = grant(&src, c, Rights::READ, &mut dst).unwrap();

    dst.revoke_slot(given.slot());
    assert_eq!(
        dst.lookup(given, Rights::READ).err(),
        Some(CapError::Invalid)
    );
    assert!(
        src.lookup(c, Rights::READ).is_ok(),
        "authority flows down, not up"
    );
}

#[test]
fn a_dead_cap_disappears_from_the_listing_after_collection() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let c = src.mint(w, Rights::ALL);
    grant(&src, c, Rights::READ, &mut dst).unwrap();

    src.revoke(c).unwrap();
    // `dst` was never consulted during the revoke, so its slot is stale until
    // it sweeps -- but the cap must already be invisible and unusable.
    assert!(dst.list().is_empty(), "a dead cap is not listed");
    assert_eq!(dst.collect(), 1, "sweeping frees the slot");
    assert_eq!(dst.collect(), 0, "and is idempotent");
}

#[test]
fn a_slot_freed_by_cascade_is_safely_reused() {
    let (mut src, w) = space();
    let mut dst = CSpace::new("dst");
    let c = src.mint(w.clone(), Rights::ALL);
    let given = grant(&src, c, Rights::READ, &mut dst).unwrap();

    src.revoke(c).unwrap();
    dst.collect();
    let fresh = dst.mint(w, Rights::ALL);
    assert_eq!(fresh.slot(), given.slot(), "the slot came back round");
    assert_eq!(
        dst.lookup(given, Rights::READ).err(),
        Some(CapError::Invalid),
        "and the old handle still does not resolve"
    );
}

#[test]
fn resetting_a_space_never_revives_an_old_incarnation_handle() {
    let (mut cs, w) = space();
    let stale = cs.mint(w.clone(), Rights::WRITE);

    assert_eq!(cs.reset(), 1);
    let fresh = cs.mint(w, Rights::WRITE);

    assert_eq!(fresh.slot(), stale.slot(), "reset may reuse the table slot");
    assert_eq!(
        cs.lookup(stale, Rights::WRITE).err(),
        Some(CapError::Invalid),
        "the retained slot generation prevents cross-incarnation ABA"
    );
    assert!(cs.lookup(fresh, Rights::WRITE).is_ok());
}

#[test]
fn async_publication_requires_the_same_cspace_incarnation() {
    let mut cs = CSpace::new("publish-target");
    let expected = cs.incarnation();
    cs.reset();
    assert_eq!(cs.incarnation(), expected + 1);

    let stale = cs.mint_if_incarnation(expected, Arc::new(Widget("stale")), Rights::READ);
    assert_eq!(stale, None);
    assert!(cs.list().is_empty());

    let current = cs
        .mint_if_incarnation(cs.incarnation(), Arc::new(Widget("current")), Rights::READ)
        .unwrap();
    assert_eq!(
        cs.lookup_as::<Widget>(current, Rights::READ).unwrap().0,
        "current"
    );
}

// --- Rights algebra ---

#[test]
fn rights_algebra() {
    assert!(Rights::ALL.contains(Rights::READ));
    assert!(Rights::READ.union(Rights::WRITE).contains(Rights::WRITE));
    assert!(!Rights::READ.contains(Rights::WRITE));
    assert!(Rights::NONE.contains(Rights::NONE));
    assert_eq!(Rights::ALL.intersect(Rights::READ), Rights::READ);
    assert_eq!(Rights::READ.intersect(Rights::WRITE), Rights::NONE);
}

#[test]
fn rights_render_as_a_stable_string() {
    // `caps` output is a UI; its column format is asserted.
    assert_eq!(format!("{}", Rights::ALL), "rwsvgx");
    assert_eq!(format!("{}", Rights::NONE), "------");
    assert_eq!(format!("{}", Rights::WRITE), "-w----");
    assert_eq!(format!("{}", Rights::RECV), "---v--");
    assert_eq!(format!("{}", Rights::READ.union(Rights::REVOKE)), "r----x");
}

#[test]
fn listing_reports_live_slots_only() {
    let (mut cs, w) = space();
    let a = cs.mint(w.clone(), Rights::ALL);
    cs.mint(w, Rights::READ);
    assert_eq!(cs.list().len(), 2);
    cs.revoke_slot(a.slot());
    assert_eq!(cs.list().len(), 1);
}

#[test]
fn an_empty_or_out_of_range_handle_is_invalid() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::ALL);
    cs.revoke_slot(c.slot());
    assert_eq!(cs.lookup(c, Rights::READ).err(), Some(CapError::Invalid));
    assert_eq!(cs.rights_of(c).err(), Some(CapError::Invalid));
}

/// "Revoke that component" means all of its authority, not one handle.
#[test]
fn revoke_all_empties_a_space_and_reaches_its_grants() {
    let (mut src, w) = space();
    let mut victim = CSpace::new("victim");
    let a = src.mint(w.clone(), Rights::ALL);
    let b = src.mint(w.clone(), Rights::ALL);
    let ca = grant(&src, a, Rights::READ, &mut victim).unwrap();
    let cb = grant(&src, b, Rights::WRITE, &mut victim).unwrap();
    let mut onward = CSpace::new("onward");
    victim.mint(w, Rights::READ); // an unrelated cap the victim minted itself

    assert_eq!(victim.revoke_all(), 3);
    assert!(victim.list().is_empty());
    assert_eq!(
        victim.lookup(ca, Rights::READ).err(),
        Some(CapError::Invalid)
    );
    assert_eq!(
        victim.lookup(cb, Rights::WRITE).err(),
        Some(CapError::Invalid)
    );

    // The source keeps its own authority; revocation flows down, never up.
    assert!(src.lookup(a, Rights::READ).is_ok());
    assert!(grant(&src, a, Rights::READ, &mut onward).is_ok());
}

// --- ROADMAP M4.3: durable CSpace installation and lifecycle ---

#[test]
fn committed_root_and_child_install_with_exact_identity_and_attenuation() {
    let space_id = stable(101, SpaceId::new);
    let kind = ResourceKind::new(7).unwrap();
    let root_rights = DurableRights::READ
        .union(DurableRights::GRANT)
        .union(DurableRights::REVOKE);
    let mut cs = CSpace::new_persistent("durable", space_id);
    let incarnation = cs.incarnation();

    let root_reservation = cs.reserve_persistent_slot(incarnation).unwrap();
    assert_eq!(root_reservation.target().slot, 0);
    assert_eq!(root_reservation.target().generation, 0);
    let root_record = durable_grant(110, 111, None, 112, space_id, 0, 0, root_rights, kind).grant;
    let (root_cap, root) = cs
        .install_reserved_root(&root_reservation, &root_record, Arc::new(Widget("durable")))
        .unwrap();

    let child_reservation = cs.reserve_persistent_slot(incarnation).unwrap();
    assert_eq!(child_reservation.target().slot, 1);
    let child_record = durable_grant(
        113,
        114,
        Some(111),
        112,
        space_id,
        1,
        0,
        DurableRights::READ,
        kind,
    )
    .grant;
    let (child_cap, child) = cs
        .install_reserved_child(&child_reservation, &root, &child_record)
        .unwrap();
    let child_token = cs
        .lookup_persistent_revocable::<Widget>(child_cap, Rights::READ)
        .unwrap();

    assert_eq!(child.identity().rights(), Rights::READ);
    assert_eq!(child.identity().target(), child_record.target);
    assert_eq!(child_token.try_with(|widget| widget.0), Ok("durable"));
    assert_eq!(
        cs.lookup_persistent_identity::<Widget>(child.identity(), Rights::READ)
            .unwrap()
            .with(|widget| widget.0),
        "durable"
    );
    assert_eq!(
        cs.derive(root_cap, Rights::READ).err(),
        Some(CapError::PersistentLifecycleRequired)
    );
    assert_eq!(
        cs.revoke(child_cap).err(),
        Some(CapError::PersistentLifecycleRequired)
    );
    assert_eq!(cs.revoke_slot(child_cap.slot()), 0);
    assert_eq!(cs.revoke_all(), 0);
    assert_eq!(
        cs.reset_exact(cs.identity(), incarnation),
        Err(CSpaceResetError::PersistentLifecycleRequired)
    );
    assert_eq!(cs.reset(), 0);
    assert_eq!(cs.incarnation(), incarnation);
    assert_eq!(cs.list().len(), 2);
    let mut other = CSpace::new("ordinary-destination");
    assert_eq!(
        grant(&cs, root_cap, Rights::READ, &mut other).err(),
        Some(CapError::PersistentLifecycleRequired)
    );
    assert_eq!(
        cs.complete_persistent_revoke(&root, child.identity())
            .unwrap(),
        1
    );
    assert_eq!(
        cs.lookup_persistent_identity::<Widget>(child.identity(), Rights::READ)
            .err(),
        Some(CapError::Invalid)
    );
    assert_eq!(
        child_token.try_with(|widget| widget.0),
        Err(CapError::Invalid),
        "a previously resolved durable token must revalidate revocation"
    );
    let reused = cs.reserve_persistent_slot(incarnation).unwrap();
    assert_eq!(reused.target().slot, 1);
    assert_eq!(reused.target().generation, 1);
    cs.cancel_persistent_slot(&reused).unwrap();
}

#[test]
fn recovered_graph_restores_typed_root_and_child_in_one_publish() {
    let space_id = stable(201, SpaceId::new);
    let object_id = stable(202, ObjectId::new);
    let kind = ResourceKind::new(8).unwrap();
    let root_rights = DurableRights::READ
        .union(DurableRights::GRANT)
        .union(DurableRights::REVOKE);
    let root = durable_grant(210, 211, None, 202, space_id, 0, 4, root_rights, kind);
    let child = durable_grant(
        212,
        213,
        Some(211),
        202,
        space_id,
        1,
        7,
        DurableRights::READ,
        kind,
    );
    let slots = [
        RecoveredSlot {
            space: space_id,
            slot: 0,
            max_generation: 4,
            live_derivation: Some(root.grant.derivation_id),
        },
        RecoveredSlot {
            space: space_id,
            slot: 1,
            max_generation: 7,
            live_derivation: Some(child.grant.derivation_id),
        },
    ];
    let object = Arc::new(Widget("restored"));
    let resources = [PersistentResourceWitness::new(object_id, kind, object)];
    let mut cs = CSpace::new_persistent("restored", space_id);
    let identities = cs
        .install_recovered_graph(
            cs.incarnation(),
            &slots,
            &[root.clone(), child.clone()],
            &resources,
        )
        .unwrap();

    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0].generation(), 4);
    assert_eq!(identities[1].generation(), 7);
    assert_eq!(identities[1].rights(), Rights::READ);
    let witness = cs
        .persistent_witness_for_identity::<Widget>(identities[1], Rights::READ)
        .unwrap();
    assert_eq!(witness.identity(), identities[1]);
    assert_eq!(
        cs.lookup_persistent_identity::<Widget>(identities[1], Rights::READ)
            .unwrap()
            .with(|widget| widget.0),
        "restored"
    );
}

#[test]
fn recovered_dead_slot_is_reserved_at_strictly_next_generation() {
    let space_id = stable(301, SpaceId::new);
    let object_id = stable(302, ObjectId::new);
    let kind = ResourceKind::new(9).unwrap();
    let root = durable_grant(
        310,
        311,
        None,
        302,
        space_id,
        0,
        5,
        DurableRights::ALL,
        kind,
    );
    let slots = [
        RecoveredSlot {
            space: space_id,
            slot: 0,
            max_generation: 5,
            live_derivation: Some(root.grant.derivation_id),
        },
        RecoveredSlot {
            space: space_id,
            slot: 1,
            max_generation: 8,
            live_derivation: None,
        },
    ];
    let resources = [PersistentResourceWitness::new(
        object_id,
        kind,
        Arc::new(Widget("root")),
    )];
    let mut cs = CSpace::new_persistent("reuse", space_id);
    cs.install_recovered_graph(cs.incarnation(), &slots, &[root], &resources)
        .unwrap();

    let reservation = cs.reserve_persistent_slot(cs.incarnation()).unwrap();
    assert_eq!(reservation.target().slot, 1);
    assert_eq!(reservation.target().generation, 9);
}

#[test]
fn failed_recovery_install_never_publishes_a_partial_graph() {
    let space_id = stable(401, SpaceId::new);
    let object_id = stable(402, ObjectId::new);
    let kind = ResourceKind::new(10).unwrap();
    let root = durable_grant(
        410,
        411,
        None,
        402,
        space_id,
        0,
        0,
        DurableRights::READ.union(DurableRights::GRANT),
        kind,
    );
    let amplified = durable_grant(
        412,
        413,
        Some(411),
        402,
        space_id,
        1,
        0,
        DurableRights::WRITE,
        kind,
    );
    let slots = [
        RecoveredSlot {
            space: space_id,
            slot: 0,
            max_generation: 0,
            live_derivation: Some(root.grant.derivation_id),
        },
        RecoveredSlot {
            space: space_id,
            slot: 1,
            max_generation: 0,
            live_derivation: Some(amplified.grant.derivation_id),
        },
    ];
    let resources = [PersistentResourceWitness::new(
        object_id,
        kind,
        Arc::new(Widget("never-published")),
    )];
    let mut cs = CSpace::new_persistent("atomic", space_id);

    assert_eq!(
        cs.install_recovered_graph(cs.incarnation(), &slots, &[root, amplified], &resources,)
            .err(),
        Some(PersistentInstallError::RightsAmplification)
    );
    assert!(cs.list().is_empty());
    let reservation = cs.reserve_persistent_slot(cs.incarnation()).unwrap();
    assert_eq!(reservation.target().slot, 0);
    assert_eq!(reservation.target().generation, 0);
}

#[test]
fn recovery_refuses_generation_rollback_and_ephemeral_identity() {
    let space_id = stable(501, SpaceId::new);
    let object_id = stable(502, ObjectId::new);
    let kind = ResourceKind::new(11).unwrap();
    let root = durable_grant(
        510,
        511,
        None,
        502,
        space_id,
        0,
        0,
        DurableRights::ALL,
        kind,
    );
    let slots = [RecoveredSlot {
        space: space_id,
        slot: 0,
        max_generation: 0,
        live_derivation: Some(root.grant.derivation_id),
    }];
    let resources = [PersistentResourceWitness::new(
        object_id,
        kind,
        Arc::new(Widget("rollback")),
    )];
    let mut cs = CSpace::new_persistent("rollback", space_id);
    let ephemeral = cs.mint(Arc::new(Widget("ephemeral")), Rights::ALL);
    assert_eq!(
        cs.persistent_witness::<Widget>(ephemeral, Rights::READ)
            .err(),
        Some(CapError::NotPersistent)
    );
    assert_eq!(
        cs.lookup_persistent_revocable::<Widget>(ephemeral, Rights::READ)
            .err(),
        Some(CapError::NotPersistent)
    );
    assert_eq!(cs.revoke_slot(ephemeral.slot()), 1);

    assert_eq!(
        cs.install_recovered_graph(cs.incarnation(), &slots, &[root], &resources)
            .err(),
        Some(PersistentInstallError::GenerationRegression)
    );
    assert!(cs.list().is_empty());
}

#[test]
fn recovery_rejects_duplicate_and_out_of_range_metadata() {
    let space_id = stable(601, SpaceId::new);
    let dead = RecoveredSlot {
        space: space_id,
        slot: 0,
        max_generation: 3,
        live_derivation: None,
    };
    let mut duplicate = CSpace::new_persistent("duplicate", space_id);
    assert_eq!(
        duplicate
            .install_recovered_graph(duplicate.incarnation(), &[dead, dead], &[], &[])
            .err(),
        Some(PersistentInstallError::DuplicateSlot)
    );
    assert!(duplicate.list().is_empty());

    let mut out_of_range = CSpace::new_persistent("out-of-range", space_id);
    let invalid = RecoveredSlot {
        slot: MAX_PERSISTENT_SLOTS,
        ..dead
    };
    assert_eq!(
        out_of_range
            .install_recovered_graph(out_of_range.incarnation(), &[invalid], &[], &[])
            .err(),
        Some(PersistentInstallError::SlotOutOfRange)
    );

    let object_id = stable(602, ObjectId::new);
    let kind = ResourceKind::new(12).unwrap();
    let resources = [
        PersistentResourceWitness::new(object_id, kind, Arc::new(Widget("first"))),
        PersistentResourceWitness::new(object_id, kind, Arc::new(Widget("second"))),
    ];
    let mut duplicate_resource = CSpace::new_persistent("duplicate-resource", space_id);
    assert_eq!(
        duplicate_resource
            .install_recovered_graph(duplicate_resource.incarnation(), &[], &[], &resources)
            .err(),
        Some(PersistentInstallError::DuplicateResource)
    );
}

#[test]
fn persistent_fault_quarantine_hides_authority_and_blocks_lifecycle_operations() {
    let space_id = stable(701, SpaceId::new);
    let kind = ResourceKind::new(13).unwrap();
    let mut cs = CSpace::new_persistent("quarantine", space_id);
    let incarnation = cs.incarnation();

    let reservation = cs.reserve_persistent_slot(incarnation).unwrap();
    let retained_for_ledger = reservation;
    let root_record = durable_grant(
        710,
        711,
        None,
        712,
        space_id,
        0,
        0,
        DurableRights::ALL,
        kind,
    )
    .grant;
    let (root_cap, root) = cs
        .install_reserved_root(&reservation, &root_record, Arc::new(Widget("quarantined")))
        .unwrap();
    assert_eq!(
        cs.cancel_persistent_slot(&retained_for_ledger).err(),
        Some(PersistentInstallError::ReservationMismatch),
        "copying the opaque reservation cannot consume it twice"
    );

    let pending_child = cs.reserve_persistent_slot(incarnation).unwrap();
    let child_record = durable_grant(
        713,
        714,
        Some(711),
        712,
        space_id,
        1,
        0,
        DurableRights::READ,
        kind,
    )
    .grant;

    // Keep only a Weak outside the CSpace for this independent root. If
    // quarantine were to invalidate the slot, its Resource destructor would
    // run inside fault cleanup and this counter would change immediately.
    let drops = Arc::new(AtomicUsize::new(0));
    let drop_tracked = Arc::new(DropTrackedWidget {
        drops: drops.clone(),
    });
    let drop_tracked_weak = Arc::downgrade(&drop_tracked);
    let tracked_reservation = cs.reserve_persistent_slot(incarnation).unwrap();
    assert_eq!(tracked_reservation.target().slot, 2);
    let tracked_record = durable_grant(
        715,
        716,
        None,
        717,
        space_id,
        2,
        0,
        DurableRights::READ,
        ResourceKind::new(14).unwrap(),
    )
    .grant;
    let (_, tracked_witness) = cs
        .install_reserved_root(&tracked_reservation, &tracked_record, drop_tracked)
        .unwrap();
    drop(tracked_witness);
    assert!(drop_tracked_weak.upgrade().is_some());

    let root_identity = root.identity();
    let revocable = cs
        .lookup_revocable::<Widget>(root_cap, Rights::READ)
        .unwrap();
    let active_lease = cs.lookup_lease::<Widget>(root_cap, Rights::READ).unwrap();
    assert_eq!(cs.list().len(), 2);

    assert_eq!(cs.quarantine_persistent(), Ok(2));
    assert!(cs.is_persistent_quarantined());
    assert!(cs.list().is_empty());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(
        drop_tracked_weak.upgrade().is_some(),
        "quarantine must retain slot entries instead of running Resource::drop"
    );
    assert_eq!(
        cs.lookup(root_cap, Rights::READ).err(),
        Some(CapError::PersistentQuarantined)
    );
    assert_eq!(active_lease.with(|widget| widget.0), "quarantined");
    assert_eq!(
        cs.lookup_lease::<Widget>(root_cap, Rights::READ).err(),
        Some(CapError::PersistentQuarantined),
        "quarantine blocks every new invocation lease"
    );
    assert_eq!(
        cs.lookup_persistent_identity::<Widget>(root_identity, Rights::READ)
            .err(),
        Some(CapError::PersistentQuarantined)
    );
    assert_eq!(
        cs.persistent_witness::<Widget>(root_cap, Rights::READ)
            .err(),
        Some(CapError::PersistentQuarantined)
    );
    assert_eq!(
        cs.persistent_witness_for_identity::<Widget>(root_identity, Rights::READ)
            .err(),
        Some(CapError::PersistentQuarantined)
    );
    assert_eq!(
        cs.reserve_persistent_slot(incarnation).err(),
        Some(PersistentInstallError::PersistentQuarantined)
    );
    assert_eq!(
        cs.install_reserved_child(&pending_child, &root, &child_record)
            .err(),
        Some(PersistentInstallError::PersistentQuarantined)
    );
    assert_eq!(
        cs.cancel_persistent_slot(&pending_child).err(),
        Some(PersistentInstallError::PersistentQuarantined)
    );
    assert_eq!(
        cs.install_recovered_graph(incarnation, &[], &[], &[]).err(),
        Some(PersistentInstallError::PersistentQuarantined)
    );
    assert_eq!(
        cs.complete_persistent_revoke(&root, root_identity).err(),
        Some(CapError::PersistentQuarantined)
    );
    assert_eq!(
        revocable.try_with(|widget| widget.0),
        Err(CapError::Invalid),
        "quarantine kills authority already resolved as a revocable token"
    );
    assert_eq!(cs.quarantine_persistent(), Ok(0));
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    drop(cs);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(drop_tracked_weak.upgrade().is_none());

    let mut restarted = CSpace::new_persistent("restarted", space_id);
    assert!(!restarted.is_persistent_quarantined());
    assert!(restarted
        .reserve_persistent_slot(restarted.incarnation())
        .is_ok());
}

#[test]
fn ordinary_space_cannot_enter_persistent_quarantine() {
    let (mut cs, widget) = space();
    let cap = cs.mint(widget, Rights::READ);

    assert_eq!(
        cs.quarantine_persistent().err(),
        Some(PersistentInstallError::NotPersistentSpace)
    );
    assert!(!cs.is_persistent_quarantined());
    assert!(cs.lookup(cap, Rights::READ).is_ok());
}
