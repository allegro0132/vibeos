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

/// An opaque handle. Meaningless outside the `CSpace` that issued it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    slot: u32,
    generation: u32,
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
    generation: u32,
    entry: Option<Entry>,
}

struct Entry {
    obj: Arc<dyn Resource>,
    rights: Rights,
    /// Slot this cap was derived from, so revoke can cascade.
    parent: Option<u32>,
}

/// A task's capability space. Owning one *is* the task's entire authority.
pub struct CSpace {
    pub name: String,
    slots: Vec<Slot>,
}

impl CSpace {
    pub fn new(name: &str) -> Self {
        Self { name: String::from(name), slots: Vec::new() }
    }

    fn alloc_slot(&mut self) -> u32 {
        if let Some(i) = self.slots.iter().position(|s| s.entry.is_none()) {
            return i as u32;
        }
        self.slots.push(Slot { generation: 0, entry: None });
        (self.slots.len() - 1) as u32
    }

    /// Mint a fresh capability for a resource. This is the root of authority —
    /// only the code that creates a resource can do it.
    pub fn mint(&mut self, obj: Arc<dyn Resource>, rights: Rights) -> Cap {
        let slot = self.alloc_slot();
        self.slots[slot as usize].entry = Some(Entry { obj, rights, parent: None });
        Cap { slot, generation: self.slots[slot as usize].generation }
    }

    fn entry(&self, cap: Cap) -> Result<&Entry, CapError> {
        let slot = self.slots.get(cap.slot as usize).ok_or(CapError::Invalid)?;
        if slot.generation != cap.generation {
            return Err(CapError::Invalid);
        }
        slot.entry.as_ref().ok_or(CapError::Invalid)
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
        let parent = cap.slot;
        let slot = self.alloc_slot();
        self.slots[slot as usize].entry = Some(Entry { obj, rights, parent: Some(parent) });
        Ok(Cap { slot, generation: self.slots[slot as usize].generation })
    }

    /// Destroy a cap and everything derived from it. Bumping the slot
    /// generation is what makes outstanding copies of the handle go stale.
    #[allow(dead_code)] // API surface: self-revoke via a cap carrying REVOKE
    pub fn revoke(&mut self, cap: Cap) -> Result<usize, CapError> {
        let e = self.entry(cap)?;
        if !e.rights.contains(Rights::REVOKE) {
            return Err(CapError::InsufficientRights);
        }
        Ok(self.revoke_slot(cap.slot))
    }

    /// Administrative revoke, used by a holder of a cap on *this whole space*.
    /// Authority lives in the space cap, so no per-cap right is required here.
    pub fn revoke_slot(&mut self, slot: u32) -> usize {
        let mut killed = 0;
        let mut frontier = alloc::vec![slot];
        while let Some(slot) = frontier.pop() {
            let children: Vec<u32> = self
                .slots
                .iter()
                .enumerate()
                .filter(|(_, s)| s.entry.as_ref().is_some_and(|e| e.parent == Some(slot)))
                .map(|(i, _)| i as u32)
                .collect();
            frontier.extend(children);
            let Some(s) = self.slots.get_mut(slot as usize) else { continue };
            if s.entry.take().is_some() {
                s.generation = s.generation.wrapping_add(1);
                killed += 1;
            }
        }
        killed
    }

    pub fn list(&self) -> Vec<(Cap, &'static str, Rights, String)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let e = s.entry.as_ref()?;
                Some((
                    Cap { slot: i as u32, generation: s.generation },
                    e.obj.kind(),
                    e.rights,
                    e.obj.describe(),
                ))
            })
            .collect()
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
    let obj = src.lookup(cap, Rights::NONE)?;
    Ok(dst.mint(obj, rights))
}
