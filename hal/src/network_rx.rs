//! Statically composed detached RX buffer contract; no dynamic module ABI.
//! Tickets are identifiers, not authority. The adapter checks its capability and
//! packet session before acquiring a firmware-owned immutable loan.
use core::ptr::NonNull;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket { pool: u64, index: usize, generation: u64 }
impl Ticket {
    /// Untrusted identifiers must be validated against live ownership metadata.
    pub const fn from_parts(pool: u64, index: usize, generation: u64) -> Self {
        Self { pool, index, generation }
    }
    pub const fn pool(self) -> u64 { self.pool }
    pub const fn index(self) -> usize { self.index }
    pub const fn generation(self) -> u64 { self.generation }
}
/// Full executor allocation identity, including the nonzero incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Owner { owner: u64, incarnation: u64 }
impl Owner {
    pub const fn new(owner: u64, incarnation: u64) -> Option<Self> {
        if incarnation == 0 { None } else { Some(Self { owner, incarnation }) }
    }
    pub const fn key(self) -> u128 { ((self.owner as u128) << 64) | self.incarnation as u128 }
    pub const fn from_key(key: u128) -> Option<Self> { Self::new((key >> 64) as u64, key as u64) }
}
/// Unique CPU ownership; never Clone/Copy. Dropping this metadata alone leaks
/// ownership safely. Normal release or exact-owner fault recovery retires it.
#[derive(Debug)]
pub struct Borrow { ticket: Ticket, owner: Owner }
impl Borrow {
    /// # Safety
    /// The backend has changed this exact live slot from Ready to Borrowed for
    /// this owner, and no other Borrow exists for the same slot/generation.
    pub unsafe fn from_owned(ticket: Ticket, owner: Owner) -> Self { Self { ticket, owner } }
    pub fn ticket(&self) -> Ticket { self.ticket }
    pub fn owner(&self) -> Owner { self.owner }
    pub fn index(&self) -> usize { self.ticket.index }
}
/// An immutable frame whose storage survives device reset until release.
/// Acquiring this before creating a protocol RX token makes consume infallible:
/// revocation blocks new loans but cannot invalidate an already admitted slice.
pub struct Loan {
    pointer: NonNull<u8>, bytes: usize, borrow: Option<Borrow>, release: unsafe fn(Borrow),
}
// Constructor promises all-core CPU visibility and immutable permanent backing.
unsafe impl Send for Loan {}
unsafe impl Sync for Loan {}
impl Loan {
    /// # Safety
    /// `pointer..pointer+bytes` is the validated, CPU-synchronized frame named by
    /// borrow, accessible on every application hart. DMA and CPUs cannot write
    /// or recycle it before release. Reset preserves live loans. release uses
    /// permanent metadata, never a mutable engine or a retired task allocation,
    /// and must not panic. Fault recovery may retire this owner only after all
    /// its references are dead and it can never resume. No other release occurs.
    pub unsafe fn new(borrow: Borrow, pointer: *const u8, bytes: usize,
        release: unsafe fn(Borrow),
    ) -> Result<Self, Borrow> {
        let Some(pointer) = NonNull::new(pointer.cast_mut()) else { return Err(borrow); };
        if !(14..=crate::MAX_PACKET_LEN).contains(&bytes) { return Err(borrow); }
        Ok(Self { pointer, bytes, borrow: Some(borrow), release })
    }
    pub fn as_bytes(&self) -> &[u8] {
        // The owned Borrow pins bytes through this reference's lifetime.
        unsafe { core::slice::from_raw_parts(self.pointer.as_ptr(), self.bytes) }
    }
}
impl Drop for Loan {
    fn drop(&mut self) {
        if let Some(borrow) = self.borrow.take() { unsafe { (self.release)(borrow); } }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub received: u64, pub acquired: u64, pub released: u64, pub full: u64, pub dropped: u64,
    pub free: usize, pub ready: usize, pub borrowed: usize,
}
/// # Safety
/// Static operations validate every ticket against permanent ownership state.
/// poll requires exclusive engine invocation; acquire/discard/recover serialize
/// only ownership metadata and must not borrow ENGINE. poll publishes validated
/// frames consistent with the device's advertised checksum policy. acquire is
/// atomic with reset: it either returns a pinned Loan or rejects without access.
/// discard never releases a Borrowed slot. recover requires the exact owner's
/// executor incarnation to be quiescent forever; capability revocation is not
/// enough. No operation can free the permanent backing allocation.
pub struct Operations {
    pub stats: fn() -> Stats,
    pub poll: unsafe fn() -> Result<Option<Ticket>, super::network::Error>,
    pub acquire: unsafe fn(Ticket, Owner) -> Result<Loan, super::network::Error>,
    pub discard: unsafe fn(Ticket) -> bool,
    pub recover: unsafe fn(Owner) -> usize,
}
