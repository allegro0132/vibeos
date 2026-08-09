//! The capability system is the security core. It gets the densest tests in the
//! tree: every invariant in BLUEPRINT.md §3 has a case here, and every
//! `CapError` variant has a case that produces it.

use std::any::Any;
use std::sync::Arc;

use vibeos_core::cap::{grant, CSpace, CapError, Resource, Rights};

struct Widget(&'static str);
struct Gadget;

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

// --- Invariant 3: rights are checked at use ---

#[test]
fn lookup_requires_the_named_right() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ.union(Rights::WRITE));
    assert!(cs.lookup(c, Rights::READ).is_ok());
    assert!(cs.lookup(c, Rights::WRITE).is_ok());
    assert!(cs.lookup(c, Rights::READ.union(Rights::WRITE)).is_ok());
    assert_eq!(cs.lookup(c, Rights::SEND).err(), Some(CapError::InsufficientRights));
}

#[test]
fn holding_a_handle_is_not_permission() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::NONE);
    // The handle resolves to a live slot, and still authorises nothing.
    assert!(cs.rights_of(c).is_ok());
    for r in [Rights::READ, Rights::WRITE, Rights::SEND, Rights::RECV, Rights::GRANT] {
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
    assert_eq!(cs.derive(c, Rights::WRITE).err(), Some(CapError::Amplification));
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
    assert_eq!(cs.lookup(weak, Rights::WRITE).err(), Some(CapError::InsufficientRights));
    // ...and the parent is untouched.
    assert!(cs.lookup(c, Rights::WRITE).is_ok());
}

#[test]
fn derived_caps_cannot_re_widen_through_a_chain() {
    let (mut cs, w) = space();
    let root = cs.mint(w, Rights::ALL);
    let mid = cs.derive(root, Rights::READ.union(Rights::GRANT)).unwrap();
    let leaf = cs.derive(mid, Rights::READ).unwrap();
    assert_eq!(cs.derive(mid, Rights::WRITE).err(), Some(CapError::Amplification));
    assert_eq!(cs.derive(leaf, Rights::READ).err(), Some(CapError::InsufficientRights));
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

    assert_eq!(cs.revoke(a).err(), Some(CapError::InsufficientRights), "a has no REVOKE");
    assert_eq!(cs.revoke_slot(a.slot()), 2, "a and its descendant b");
    assert_eq!(cs.lookup(a, Rights::READ).err(), Some(CapError::Invalid));
    assert_eq!(cs.lookup(b, Rights::READ).err(), Some(CapError::Invalid));
    assert!(cs.lookup(c, Rights::WRITE).is_ok(), "a sibling branch survives");
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
    assert_eq!(cs.lookup_as::<Gadget>(c, Rights::READ).err(), Some(CapError::WrongType));
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
    assert_eq!(cs.lookup_as::<Gadget>(c, Rights::WRITE).err(), Some(CapError::InsufficientRights));
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
    assert_eq!(dst.lookup(given, Rights::WRITE).err(), Some(CapError::InsufficientRights));
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
    assert_eq!(b.lookup_as::<Widget>(ca, Rights::READ).err(), Some(CapError::WrongType));
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
    assert_eq!(dst.lookup(given, Rights::READ).err(), Some(CapError::Invalid));
    assert!(src.lookup(c, Rights::READ).is_ok(), "authority flows down, not up");
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
    assert_eq!(victim.lookup(ca, Rights::READ).err(), Some(CapError::Invalid));
    assert_eq!(victim.lookup(cb, Rights::WRITE).err(), Some(CapError::Invalid));

    // The source keeps its own authority; revocation flows down, never up.
    assert!(src.lookup(a, Rights::READ).is_ok());
    assert!(grant(&src, a, Rights::READ, &mut onward).is_ok());
}
