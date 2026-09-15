//! RX buffer ownership, independent of descriptor storage and scheduler policy.
//! This module performs no MMIO or DMA access. The adapter must serialize it,
//! keep payload storage permanent, and uphold the unsafe transition contracts.
//! Free-list allocation is O(1); diagnostic/reset walks are off the packet path.
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_POOL: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Geometry,
    Exhausted,
    Full,
    Descriptor,
    Pending,
    Stale,
    Busy,
    Owner,
}
pub use vibeos_hal::network_rx::{Borrow, Ticket};
#[derive(Debug)]
pub struct Prepared {
    ticket: Ticket,
    descriptor: usize,
    replacement: usize,
}
impl Prepared {
    pub fn replacement(&self) -> usize {
        self.replacement
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Free,
    Dma,
    Detached,
    Ready,
    Borrowed(u128),
    Retired,
}
#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    prepared: bool,
    state: State,
}
#[derive(Clone, Copy)]
struct Mapping {
    index: usize,
    pending: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub free: usize,
    pub dma: usize,
    pub detached: usize,
    pub ready: usize,
    pub borrowed: usize,
    pub retired: usize,
}
pub struct Buffers<const D: usize, const N: usize> {
    id: u64,
    allocation: Option<(u64, u64)>,
    slots: [Slot; N],
    descriptors: [Option<Mapping>; D],
    free: [usize; N],
    available: usize,
}
impl<const D: usize, const N: usize> Buffers<D, N> {
    pub fn new() -> Result<Self, Error> {
        if D < 2 || D > 1024 || N <= D || N > 4096 {
            return Err(Error::Geometry);
        }
        let id = loop {
            let id = NEXT_POOL.load(Ordering::Relaxed);
            let next = id.checked_add(1).ok_or(Error::Exhausted)?;
            if NEXT_POOL
                .compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break id;
            }
        };
        Ok(Self {
            id,
            allocation: None,
            slots: [Slot {
                generation: 0,
                prepared: false,
                state: State::Free,
            }; N],
            descriptors: [None; D],
            free: core::array::from_fn(|i| N - 1 - i),
            available: N,
        })
    }
    // A metadata table cannot silently migrate to another DMA allocation,
    // including after reset while old consumer borrows remain alive.
    pub(crate) fn bind(&mut self, descriptors: u64, buffers: u64) -> Result<(), Error> {
        let allocation = (descriptors, buffers);
        if self.allocation.is_some_and(|old| old != allocation) {
            return Err(Error::Stale);
        }
        self.allocation = Some(allocation);
        Ok(())
    }
    pub(crate) fn identity(&self) -> u64 {
        self.id
    }
    pub(crate) fn reused(&self, index: usize) -> bool {
        self.slots[index].prepared
    }
    pub(crate) fn mark_prepared(&mut self, index: usize) { self.slots[index].prepared = true; }
    fn take_free(&mut self) -> Result<usize, Error> {
        while self.available != 0 {
            self.available -= 1;
            let index = self.free[self.available];
            let slot = &mut self.slots[index];
            debug_assert_eq!(slot.state, State::Free);
            let Some(generation) = slot.generation.checked_add(1) else {
                slot.state = State::Retired;
                continue;
            };
            slot.generation = generation;
            slot.state = State::Dma;
            return Ok(index);
        }
        Err(Error::Full)
    }
    fn recycle(&mut self, index: usize) {
        debug_assert!(!matches!(
            self.slots[index].state,
            State::Free | State::Retired
        ));
        self.slots[index].state = State::Free;
        self.free[self.available] = index;
        self.available += 1;
    }
    fn validate(&self, ticket: Ticket) -> Result<usize, Error> {
        if ticket.pool() != self.id || ticket.index() >= N {
            return Err(Error::Stale);
        }
        let slot = &self.slots[ticket.index()];
        if slot.generation != ticket.generation()
            || matches!(slot.state, State::Free | State::Retired)
        {
            return Err(Error::Stale);
        }
        Ok(ticket.index())
    }
    /// Reserve initial descriptor storage. Only the caller programs hardware.
    pub fn attach(&mut self, descriptor: usize) -> Result<usize, Error> {
        if descriptor >= D {
            return Err(Error::Descriptor);
        }
        if self.descriptors[descriptor].is_some() {
            return Err(Error::Busy);
        }
        let index = self.take_free()?;
        self.descriptors[descriptor] = Some(Mapping {
            index,
            pending: false,
        });
        Ok(index)
    }
    pub fn descriptor_buffer(&self, descriptor: usize) -> Option<usize> {
        self.descriptors.get(descriptor)?.map(|m| m.index)
    }
    /// Reserve a replacement before detaching the completed frame. Full leaves
    /// the original mapping and ownership unchanged; do not publish a frame.
    /// # Safety
    /// The original descriptor is CPU-owned, its frame has been validated and
    /// synchronized for CPU access. DMA cannot access it again until rearmed.
    pub unsafe fn prepare(&mut self, descriptor: usize) -> Result<Prepared, Error> {
        let old = self
            .descriptors
            .get(descriptor)
            .and_then(|m| *m)
            .ok_or(Error::Descriptor)?;
        if old.pending {
            return Err(Error::Pending);
        }
        let replacement = self.take_free()?;
        debug_assert_eq!(self.slots[old.index].state, State::Dma);
        self.slots[old.index].state = State::Detached;
        self.descriptors[descriptor] = Some(Mapping {
            index: replacement,
            pending: true,
        });
        Ok(Prepared {
            ticket: Ticket::from_parts(self.id, old.index, self.slots[old.index].generation),
            descriptor,
            replacement,
        })
    }
    /// # Safety
    /// The replacement buffer has been synchronized and its descriptor/tail
    /// published. No hardware descriptor can refer to the detached buffer.
    /// Publish the returned ticket to a queue only after this transition.
    pub unsafe fn publish(&mut self, prepared: Prepared) -> Result<Ticket, Error> {
        let index = self.validate(prepared.ticket)?;
        if self.slots[index].state != State::Detached {
            return Err(Error::Stale);
        }
        let mapping = self
            .descriptors
            .get_mut(prepared.descriptor)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)?;
        if !mapping.pending || mapping.index != prepared.replacement {
            return Err(Error::Stale);
        }
        mapping.pending = false;
        self.slots[index].state = State::Ready;
        Ok(prepared.ticket)
    }
    /// `owner` is a trusted executor incarnation identity, never client input.
    /// The adapter must validate the packet's device/stack session separately.
    pub fn borrow(&mut self, ticket: Ticket, owner: u128) -> Result<Borrow, Error> {
        let identity = vibeos_hal::network_rx::Owner::from_key(owner).ok_or(Error::Owner)?;
        let index = self.validate(ticket)?;
        if self.slots[index].state != State::Ready {
            return Err(Error::Busy);
        }
        self.slots[index].state = State::Borrowed(owner);
        Ok(unsafe { Borrow::from_owned(ticket, identity) })
    }
    /// End the immutable byte borrow before calling this method.
    pub fn release(&mut self, borrow: Borrow) -> Result<(), Error> {
        let index = self.validate(borrow.ticket())?;
        if self.slots[index].state != State::Borrowed(borrow.owner().key()) {
            return Err(Error::Stale);
        }
        self.recycle(index);
        Ok(())
    }
    /// Retire a queued/unconsumed frame. A duplicate ticket cannot free a live
    /// borrow or a newly assigned buffer generation.
    pub fn discard(&mut self, ticket: Ticket) -> Result<(), Error> {
        let index = self.validate(ticket)?;
        if self.slots[index].state != State::Ready {
            return Err(Error::Busy);
        }
        self.recycle(index);
        Ok(())
    }
    /// # Safety
    /// DMA is proven stopped/reset and its old descriptor ring will not resume.
    /// Retain all live byte borrows, even when allocating a new descriptor ring.
    /// Queued/prepared tickets become stale; restart does not relabel packets.
    pub unsafe fn reset_after_dma_stop(&mut self) {
        self.descriptors.fill(None);
        self.available = 0;
        for index in 0..N {
            if matches!(self.slots[index].state, State::Borrowed(_) | State::Retired) {
                continue;
            }
            self.slots[index].state = State::Free;
            self.free[self.available] = index;
            self.available += 1;
        }
    }
    /// # Safety
    /// This exact executor incarnation can never resume, and no byte reference
    /// from its abandoned callback remains live. A running borrower is not safe
    /// to reclaim merely because its capability or device session was revoked.
    pub unsafe fn recover_borrower(&mut self, owner: u128) -> usize {
        if owner == 0 {
            return 0;
        }
        let mut count = 0;
        for index in 0..N {
            if self.slots[index].state == State::Borrowed(owner) {
                self.recycle(index);
                count += 1;
            }
        }
        // Recover a free-list entry lost if a fault interrupted release after
        // changing slot state. DMA/Ready/live Borrowed slots are never added.
        self.available = 0;
        for index in 0..N {
            if self.slots[index].state == State::Free {
                self.free[self.available] = index; self.available += 1;
            }
        }
        count
    }
    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        for slot in &self.slots {
            match slot.state {
                State::Free => stats.free += 1,
                State::Dma => stats.dma += 1,
                State::Detached => stats.detached += 1,
                State::Ready => stats.ready += 1,
                State::Borrowed(_) => stats.borrowed += 1,
                State::Retired => stats.retired += 1,
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_generation_does_not_prove_initial_cache_preparation() {
        let mut p = Buffers::<2, 4>::new().unwrap();
        let slot = p.attach(0).unwrap();
        assert!(!p.reused(slot));
        unsafe { p.reset_after_dma_stop(); }
        assert!(!p.reused(slot), "abandoned preparation must not enable fast recycle");
        p.mark_prepared(slot);
        unsafe { p.reset_after_dma_stop(); }
        assert!(p.reused(slot));
    }
    #[test]
    fn recovery_rebuilds_a_free_entry_from_an_interrupted_release() {
        let mut p = Buffers::<2, 4>::new().unwrap(); p.attach(0).unwrap(); p.attach(1).unwrap();
        let prepared = unsafe { p.prepare(0).unwrap() };
        let ticket = unsafe { p.publish(prepared).unwrap() };
        let borrow = p.borrow(ticket, 9).unwrap();
        p.slots[ticket.index()].state = State::Free;
        core::mem::forget(borrow); // fault: the consumer can never resume
        unsafe { p.recover_borrower(9); }
        assert_eq!(p.available, 2);
        let next = unsafe { p.prepare(1).unwrap() };
        let fresh = unsafe { p.publish(next).unwrap() };
        p.discard(fresh).unwrap(); assert_eq!(p.available, 2);
    }
    #[test]
    fn exhausted_generation_is_retired_instead_of_wrapping() {
        let mut p = Buffers::<2, 3>::new().unwrap();
        p.slots[0].generation = u64::MAX;
        assert_eq!(p.attach(0), Ok(1));
        assert_eq!(p.stats().retired, 1);
        assert_eq!(p.attach(1), Ok(2));
        assert_eq!(unsafe { p.prepare(0) }.err(), Some(Error::Full));
        unsafe {
            p.reset_after_dma_stop();
        }
        assert_eq!(p.stats().retired, 1);
        assert_eq!(p.stats().free, 2);
    }
}
