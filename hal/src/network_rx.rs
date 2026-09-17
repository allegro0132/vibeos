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
    #[cfg(feature = "rx-batch-release")]
    batch_release: Option<unsafe fn(&mut [Option<Borrow>])>,
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
        Ok(Self { pointer, bytes, borrow: Some(borrow), release,
            #[cfg(feature = "rx-batch-release")]
            batch_release: None,
        })
    }
    /// Attach an optional bulk cleanup operation for this already pinned loan.
    /// # Safety
    /// The callback must implement the same permanent-metadata release contract
    /// as `new`, for every Borrow supplied by loans bearing this callback. It
    /// must take/release every Some exactly once, leave None entries, never panic,
    /// and preserve exact-owner recovery for interrupted cleanup.
    #[cfg(feature = "rx-batch-release")]
    pub unsafe fn with_batch_release(mut self, callback: unsafe fn(&mut [Option<Borrow>])) -> Self {
        self.batch_release = Some(callback); self
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
/// Bounded, allocation-free FIFO result. None entries contain no ticket.
pub const BATCH_SIZE: usize = 8;
pub type TicketBatch = [Option<Ticket>; BATCH_SIZE];

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
    /// Optional batch poll under the same exclusive engine invocation as poll.
    /// Some entries are in wire order and all are private until return. Runtime
    /// stamps the complete result under one session-publication barrier. Err
    /// exposes no tickets; partial ownership must remain quarantined until reset.
    pub poll_batch: Option<unsafe fn() -> Result<TicketBatch, super::network::Error>>,
    pub acquire: unsafe fn(Ticket, Owner) -> Result<Loan, super::network::Error>,
    pub discard: unsafe fn(Ticket) -> bool,
    pub recover: unsafe fn(Owner) -> usize,
}

/// Bounded ownership of loans whose bytes have already been consumed. No slices
/// escape this holder. It defers cleanup only until its synchronous scope ends.
#[cfg(feature = "rx-batch-release")]
pub struct ReleaseBatch<const N: usize> { loans: [Option<Loan>; N], len: usize }
#[cfg(feature = "rx-batch-release")]
impl<const N: usize> ReleaseBatch<N> {
    pub const fn new() -> Self { Self { loans: [const { None }; N], len: 0 } }
    pub fn push(&mut self, loan: Loan) -> Result<(), Loan> {
        if self.len == N { return Err(loan); }
        self.loans[self.len] = Some(loan); self.len += 1; Ok(())
    }
}
#[cfg(feature = "rx-batch-release")]
impl<const N: usize> Drop for ReleaseBatch<N> {
    fn drop(&mut self) {
        let Some(callback) = self.loans.first().and_then(Option::as_ref).and_then(|l| l.batch_release) else { return; };
        // Mixed providers or scalar-only loans retain their own Drop callbacks.
        if !self.loans[..self.len].iter().all(|l| l.as_ref().unwrap().batch_release
            .is_some_and(|other| core::ptr::fn_addr_eq(callback, other))) { return; }
        let mut borrows: [Option<Borrow>; N] = [const { None }; N];
        for (loan, borrow) in self.loans.iter_mut().zip(borrows.iter_mut()).take(self.len) {
            *borrow = loan.take().unwrap().borrow.take();
        }
        // Consuming the Loans ended all access to the immutable payload. Their
        // scalar destructors saw None, so only this callback owns cleanup now.
        unsafe { callback(&mut borrows[..self.len]); }
    }
}
