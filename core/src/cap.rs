//! Capabilities: the only way to name anything in VibeOS.
//!
//! There is no global namespace, no path lookup, no uid, no root. A task can
//! act on a resource only by presenting a `Cap` it holds in its own `CSpace`,
//! and every operation names the rights it needs. `Cap` has private fields, so
//! safe code cannot mint one — it can only receive one from someone who already
//! had it, and only ever with a subset of that holder's rights.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::heap::{self, OwnerId};

/// Capability tables and derivation nodes are supervisor metadata. They can be
/// mutated while a caller holds a CSpace lock, so their growth must not consume
/// the currently-polled component's quota and fault past that shared lock.
fn system_allocation<T>(f: impl FnOnce() -> T) -> T {
    let mut scope = heap::enter_owner(OwnerId::SYSTEM);
    let value = f();
    scope.restore();
    value
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const SEND: Rights = Rights(1 << 2);
    pub const RECV: Rights = Rights(1 << 3);
    /// May copy this cap into another CSpace (never with more rights).
    pub const GRANT: Rights = Rights(1 << 4);
    /// May destroy this cap and every cap derived from it.
    pub const REVOKE: Rights = Rights(1 << 5);

    pub const ALL: Rights = Rights(0b11_1111);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
    #[allow(dead_code)] // API surface: used when merging rights masks
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }
}

/// Renders as the same `rwsvgx` string as `Display`, so a failed assertion in a
/// test names the rights instead of a bitmask.
impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(Rights, char); 6] = [
            (Rights::READ, 'r'),
            (Rights::WRITE, 'w'),
            (Rights::SEND, 's'),
            (Rights::RECV, 'v'),
            (Rights::GRANT, 'g'),
            (Rights::REVOKE, 'x'),
        ];
        for (bit, ch) in NAMES {
            f.write_str(if self.contains(bit) {
                match ch {
                    'r' => "r",
                    'w' => "w",
                    's' => "s",
                    'v' => "v",
                    'g' => "g",
                    _ => "x",
                }
            } else {
                "-"
            })?;
        }
        Ok(())
    }
}

/// A node in the derivation graph.
///
/// Every capability points at one. A cap is live only if its own node is alive
/// *and* every ancestor is — which is what makes revocation reach copies that
/// have travelled into other spaces. The graph is held together by `Arc`, so
/// there is no registry to keep in sync and no requirement that the revoker be
/// able to reach the spaces holding the copies.
struct Derivation {
    alive: AtomicBool,
    parent: Option<Arc<Derivation>>,
}

impl Derivation {
    fn root() -> Arc<Self> {
        Arc::new(Self { alive: AtomicBool::new(true), parent: None })
    }

    fn child(parent: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self { alive: AtomicBool::new(true), parent: Some(parent.clone()) })
    }

    fn is_alive(&self) -> bool {
        let mut node = self;
        loop {
            if !node.alive.load(Ordering::Acquire) {
                return false;
            }
            match &node.parent {
                Some(p) => node = p,
                None => return true,
            }
        }
    }

    fn kill(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

/// An opaque handle. Meaningless outside the `CSpace` that issued it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    slot: u32,
    /// 64 bits so exhausting it is unreachable; a slot that somehow did exhaust
    /// it is retired rather than reused (see `alloc_slot`).
    generation: u64,
}

impl Cap {
    #[allow(dead_code)] // API surface: slot identity for external cap tables
    pub fn slot(self) -> u32 {
        self.slot
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cap:{}.{}", self.slot, self.generation)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// The slot is empty, or the generation is stale (it was revoked).
    Invalid,
    /// The cap is live but does not carry the rights this operation needs.
    InsufficientRights,
    /// Attempted to derive a cap with rights the parent does not hold.
    Amplification,
    /// The object behind the cap is not of the requested type.
    WrongType,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CapError::Invalid => "invalid or revoked capability",
            CapError::InsufficientRights => "insufficient rights",
            CapError::Amplification => "rights amplification refused",
            CapError::WrongType => "capability names the wrong resource type",
        })
    }
}

pub trait Resource: Any + Send + Sync {
    fn kind(&self) -> &'static str;
    fn describe(&self) -> String {
        String::from(self.kind())
    }
    fn as_any(&self) -> &dyn Any;
}

struct Slot {
    generation: u64,
    entry: Option<Entry>,
}

struct Entry {
    obj: Arc<dyn Resource>,
    rights: Rights,
    node: Arc<Derivation>,
}

/// A task's capability space. Owning one *is* the task's entire authority.
pub struct CSpace {
    pub name: String,
    slots: Vec<Slot>,
}

impl CSpace {
    pub fn new(name: &str) -> Self {
        system_allocation(|| Self {
            name: String::from(name),
            slots: Vec::new(),
        })
    }

    fn alloc_slot(&mut self) -> u32 {
        // A slot whose generation saturated is retired forever rather than
        // reused, so a stale handle can never alias a fresh one.
        if let Some(i) = self
            .slots
            .iter()
            .position(|s| s.entry.is_none() && s.generation != u64::MAX)
        {
            return i as u32;
        }
        system_allocation(|| self.slots.push(Slot { generation: 0, entry: None }));
        (self.slots.len() - 1) as u32
    }

    fn invalidate(slot: &mut Slot) {
        slot.entry = None;
        slot.generation = slot.generation.saturating_add(1);
    }

    /// Mint a fresh capability for a resource. This is the root of authority —
    /// only the code that creates a resource can do it.
    pub fn mint(&mut self, obj: Arc<dyn Resource>, rights: Rights) -> Cap {
        let slot = self.alloc_slot();
        let node = system_allocation(Derivation::root);
        self.slots[slot as usize].entry = Some(Entry { obj, rights, node });
        Cap { slot, generation: self.slots[slot as usize].generation }
    }

    fn entry(&self, cap: Cap) -> Result<&Entry, CapError> {
        let slot = self.slots.get(cap.slot as usize).ok_or(CapError::Invalid)?;
        if slot.generation != cap.generation {
            return Err(CapError::Invalid);
        }
        let entry = slot.entry.as_ref().ok_or(CapError::Invalid)?;
        // An ancestor revoked in another space kills this cap too; the slot
        // here simply has not been swept yet.
        if !entry.node.is_alive() {
            return Err(CapError::Invalid);
        }
        Ok(entry)
    }

    pub fn rights_of(&self, cap: Cap) -> Result<Rights, CapError> {
        Ok(self.entry(cap)?.rights)
    }

    /// Resolve a cap, enforcing that it carries `need`. Every operation in the
    /// system goes through here.
    pub fn lookup(&self, cap: Cap, need: Rights) -> Result<Arc<dyn Resource>, CapError> {
        let e = self.entry(cap)?;
        if !e.rights.contains(need) {
            return Err(CapError::InsufficientRights);
        }
        Ok(e.obj.clone())
    }

    /// Typed resolve: rights check plus a downcast to the concrete resource.
    pub fn lookup_as<T: Resource>(&self, cap: Cap, need: Rights) -> Result<Arc<T>, CapError> {
        let obj = self.lookup(cap, need)?;
        if obj.as_any().is::<T>() {
            // Safety: the `Any` check above proves the concrete type matches.
            Ok(unsafe { Arc::from_raw(Arc::into_raw(obj) as *const T) })
        } else {
            Err(CapError::WrongType)
        }
    }

    /// Attenuate: produce a new cap on the same object with a *subset* of the
    /// parent's rights. There is deliberately no way to widen rights.
    pub fn derive(&mut self, cap: Cap, rights: Rights) -> Result<Cap, CapError> {
        let e = self.entry(cap)?;
        if !e.rights.contains(Rights::GRANT) {
            return Err(CapError::InsufficientRights);
        }
        if !e.rights.contains(rights) {
            return Err(CapError::Amplification);
        }
        let obj = e.obj.clone();
        let node = system_allocation(|| Derivation::child(&e.node));
        let slot = self.alloc_slot();
        self.slots[slot as usize].entry = Some(Entry { obj, rights, node });
        Ok(Cap { slot, generation: self.slots[slot as usize].generation })
    }

    /// Destroy a cap and everything derived from it. Bumping the slot
    /// generation is what makes outstanding copies of the handle go stale.
    /// Destroy a cap and everything derived from it, in every space.
    pub fn revoke(&mut self, cap: Cap) -> Result<usize, CapError> {
        let e = self.entry(cap)?;
        if !e.rights.contains(Rights::REVOKE) {
            return Err(CapError::InsufficientRights);
        }
        e.node.kill();
        Ok(self.collect())
    }

    /// Administrative revoke, used by a holder of a cap on *this whole space*.
    /// Authority lives in the space cap, so no per-cap right is required here.
    pub fn revoke_slot(&mut self, slot: u32) -> usize {
        let Some(node) = self
            .slots
            .get(slot as usize)
            .and_then(|s| s.entry.as_ref())
            .map(|e| e.node.clone())
        else {
            return 0;
        };
        node.kill();
        self.collect()
    }

    /// Revoke everything in this space. What an operator means by "revoke that
    /// component": not one handle, but all of its authority.
    pub fn revoke_all(&mut self) -> usize {
        for slot in &self.slots {
            if let Some(e) = &slot.entry {
                e.node.kill();
            }
        }
        self.collect()
    }

    /// Retire every capability in preparation for a fresh component
    /// incarnation.
    ///
    /// Vacant slots are deliberately retained with their incremented
    /// generations. Replacing the table with `CSpace::new` would let an old
    /// `Cap { slot, generation }` alias the first grant in the new incarnation.
    pub fn reset(&mut self) -> usize {
        self.revoke_all()
    }

    /// Drop every slot whose derivation is dead; returns how many went.
    ///
    /// Killing a node takes effect immediately for lookups everywhere; this is
    /// the local bookkeeping that frees slots and updates `list`.
    pub fn collect(&mut self) -> usize {
        let mut killed = 0;
        for slot in &mut self.slots {
            if slot.entry.as_ref().is_some_and(|e| !e.node.is_alive()) {
                Self::invalidate(slot);
                killed += 1;
            }
        }
        killed
    }

    pub fn list(&self) -> Vec<(Cap, &'static str, Rights, String)> {
        system_allocation(|| {
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(i, s)| {
                    let e = s.entry.as_ref().filter(|e| e.node.is_alive())?;
                    Some((
                        Cap { slot: i as u32, generation: s.generation },
                        e.obj.kind(),
                        e.rights,
                        e.obj.describe(),
                    ))
                })
                .collect()
        })
    }
}

/// Copy a capability from one space into another, attenuating on the way.
///
/// The source must hold `GRANT`, and `rights` must be a subset of what the
/// source already has — authority can only ever shrink as it travels.
pub fn grant(
    src: &CSpace,
    cap: Cap,
    rights: Rights,
    dst: &mut CSpace,
) -> Result<Cap, CapError> {
    let held = src.rights_of(cap)?;
    if !held.contains(Rights::GRANT) {
        return Err(CapError::InsufficientRights);
    }
    if !held.contains(rights) {
        return Err(CapError::Amplification);
    }
    // The copy is a *child* of the source in the derivation graph, so revoking
    // the source later reaches it even though it now lives in another space.
    let parent = src.entry(cap)?;
    let node = system_allocation(|| Derivation::child(&parent.node));
    let obj = parent.obj.clone();

    let slot = dst.alloc_slot();
    dst.slots[slot as usize].entry = Some(Entry { obj, rights, node });
    Ok(Cap { slot, generation: dst.slots[slot as usize].generation })
}
