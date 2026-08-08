//! The capability system is the security core. It gets the densest tests in the
//! tree: every invariant in BLUEPRINT.md §3 has a case here, and every
//! `CapError` variant has a case that produces it.

use std::any::Any;
use std::sync::Arc;

use vibeos_core::cap::{grant, CSpace, CapError, Resource, Rights};

struct Widget(&'static str);
struct Gadget;

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
fn typed_lookup_checks_rights_before_type() {
    let (mut cs, w) = space();
    let c = cs.mint(w, Rights::READ);
    // Wrong type *and* missing rights: rights win, so a caller cannot use type
    // confusion to learn what a resource is without authority over it.
    assert_eq!(cs.lookup_as::<Gadget>(c, Rights::WRITE).err(), Some(CapError::InsufficientRights));
}

#[test]
fn typed_lookup_preserves_the_arc() {
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
