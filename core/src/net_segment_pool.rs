//! Bounded runtime-owned staging for logical TCP sends crossing fault domains.
//! Buffers are never used directly by DMA. A consumer must copy into its own DMA
//! storage before returning success. Tickets carry pool, generation and session
//! identity; they own no allocation in the producer's reclaimable arena.
//! Separate slot locks allow serialization and DMA copying on different buffers
//! concurrently. Round-robin reservation avoids always contending on slot zero.
extern crate alloc;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::{heap::{self, AllocationDomain, OwnerId}, net::PacketStamp, sync::{SpinLock, SpinGuard}};
use vibeos_hal::tcp_segmentation::{TcpSegments, MAX_LOGICAL_PACKET};

pub const MAX_POOL_SLOTS: usize = 32;
static NEXT_POOL: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket { pool: u64, index: usize, generation: u64, stamp: PacketStamp }
impl Ticket { pub const fn stamp(self) -> PacketStamp { self.stamp } }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Capacity, Full, Exhausted, UntrackedDomain, Stale, NotReady, InvalidPacket }
#[derive(Clone, Copy, PartialEq, Eq)]
enum State { Free, Reserved, Writing, Ready }
struct Slot {
    bytes: Box<[u8]>, state: State, generation: u64,
    domain: Option<AllocationDomain>, consumer: Option<AllocationDomain>, stamp: Option<PacketStamp>, len: usize, mss: usize,
}
pub struct SegmentPool { id: u64, slots: Vec<SpinLock<Slot>>, cursor: AtomicUsize }
impl SegmentPool {
    /// Create once as runtime metadata, not once per component invocation.
    /// The caller's capability policy controls who may reserve from this pool.
    pub fn new(capacity: usize) -> Result<Arc<Self>, Error> {
        if !(1..=MAX_POOL_SLOTS).contains(&capacity) { return Err(Error::Capacity); }
        let id = loop {
            let old = NEXT_POOL.load(Ordering::Relaxed);
            let next = old.checked_add(1).ok_or(Error::Exhausted)?;
            if NEXT_POOL.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                break old;
            }
        };
        let mut scope = heap::enter_owner(OwnerId::SYSTEM);
        let slots = (0..capacity).map(|_| SpinLock::new_recoverable(Slot {
            bytes: vec![0; MAX_LOGICAL_PACKET].into_boxed_slice(), state: State::Free,
            generation: 0, domain: None, consumer: None, stamp: None, len: 0, mss: 0,
        })).collect();
        let pool = Arc::new(Self { id, slots, cursor: AtomicUsize::new(0) });
        scope.restore();
        Ok(pool)
    }
    /// `domain` must come from the trusted executor identity, never client data.
    pub fn reserve(&self, stamp: PacketStamp, domain: AllocationDomain) -> Result<Ticket, Error> {
        if !domain.arena.is_tracked() { return Err(Error::UntrackedDomain); }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            let mut slot = self.slots[index].lock();
            if slot.state != State::Free { continue; }
            let generation = slot.generation.checked_add(1).ok_or(Error::Exhausted)?;
            slot.state = State::Reserved; slot.generation = generation;
            slot.stamp = Some(stamp); slot.domain = Some(domain); slot.len = 0;
            return Ok(Ticket { pool: self.id, index, generation, stamp });
        }
        Err(Error::Full)
    }
    fn slot(&self, ticket: Ticket, expected: PacketStamp) -> Result<SpinGuard<'_, Slot>, Error> {
        if ticket.pool != self.id || ticket.stamp != expected { return Err(Error::Stale); }
        let slot = self.slots.get(ticket.index).ok_or(Error::Stale)?.lock();
        if slot.state == State::Free || slot.generation != ticket.generation
            || slot.stamp != Some(expected) { return Err(Error::Stale); }
        Ok(slot)
    }
    /// Serialize in preallocated storage. Invalid output retires the reservation.
    /// If the producer faults inside `fill`, the slot stays Writing until recovery.
    pub fn write<R>(&self, ticket: Ticket, expected: PacketStamp, length: usize, mss: usize,
        fill: impl FnOnce(&mut [u8]) -> R) -> Result<R, Error> {
        let mut guard = self.slot(ticket, expected)?;
        let slot = &mut *guard;
        if slot.state != State::Reserved { return Err(Error::NotReady); }
        if !(55..=MAX_LOGICAL_PACKET).contains(&length) {
            Self::free(slot); return Err(Error::InvalidPacket);
        }
        slot.state = State::Writing;
        slot.bytes[..length].fill(0);
        let result = fill(&mut slot.bytes[..length]);
        if TcpSegments::new(&slot.bytes[..length], mss).is_err() {
            Self::free(slot); return Err(Error::InvalidPacket);
        }
        slot.len = length; slot.mss = mss; slot.state = State::Ready;
        Ok(result)
    }
    /// Keep a whole request on consumer backpressure. Success releases the slot
    /// under the same guard; duplicate/stale tickets cannot consume new contents.
    /// The callback must not retain the request after returning (including DMA).
    pub fn try_consume<R, E>(&self, ticket: Ticket, expected: PacketStamp,
        consume: impl FnOnce(TcpSegments<'_>) -> Result<R, E>) -> Result<Result<R, E>, Error> {
        let mut guard = self.slot(ticket, expected)?;
        let slot = &mut *guard;
        if slot.state != State::Ready { return Err(Error::NotReady); }
        let request = TcpSegments::new(&slot.bytes[..slot.len], slot.mss).expect("validated pool request");
        slot.consumer = Some(heap::current_domain());
        let result = consume(request);
        slot.consumer = None;
        if result.is_ok() { Self::free(slot); }
        Ok(result)
    }
    pub fn cancel(&self, ticket: Ticket, expected: PacketStamp) -> Result<(), Error> {
        let mut slot = self.slot(ticket, expected)?;
        Self::free(&mut slot); Ok(())
    }
    fn free(slot: &mut Slot) {
        slot.state = State::Free; slot.domain = None; slot.consumer = None; slot.stamp = None; slot.len = 0;
    }
    pub fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.lock().state != State::Free).count()
    }
    /// Retire a device binding. The caller stops admission under its session
    /// barrier; stale queued tickets cannot read slots reused by a later binding.
    pub fn invalidate_all(&self) -> usize {
        let mut count = 0;
        for slot in &self.slots {
            let mut slot = slot.lock();
            if slot.state != State::Free { count += 1; Self::free(&mut slot); }
        }
        count
    }
    /// Cancel all reservations/queued tickets belonging to this exact incarnation.
    pub fn invalidate_domain(&self, domain: AllocationDomain) -> usize {
        let mut count = 0;
        for slot in &self.slots {
            let mut slot = slot.lock();
            if slot.domain == Some(domain) || slot.consumer == Some(domain) { Self::free(&mut slot); count += 1; }
        }
        count
    }
    /// Recover the lock as well as reservations abandoned by a producer/consumer.
    /// # Safety
    /// Every task in `domain` must be terminal and unable to resume. For another
    /// hart, the caller must acquire its quiescence acknowledgement first.
    /// Invoke before releasing that domain's arena or admitting its replacement.
    pub unsafe fn recover_faulted_domain(&self, domain: AllocationDomain) -> usize {
        let mut count = 0;
        for slot in &self.slots {
            let abandoned = unsafe { slot.recover_after_fault(domain) };
            let mut slot = slot.lock();
            // An abandoned operation can fault before recording its domain or
            // after submitting DMA. Invalidate conservatively; never reuse its
            // ticket to infer whether transmission completed.
            if abandoned || slot.domain == Some(domain) || slot.consumer == Some(domain) {
                if slot.state != State::Free { count += 1; }
                Self::free(&mut slot);
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhausted_generation_never_reserves_or_wraps() {
        let pool = SegmentPool::new(1).unwrap();
        pool.slots[0].lock().generation = u64::MAX;
        let stamp = PacketStamp::new(1, 1).unwrap();
        let domain = AllocationDomain::new(OwnerId::new(9), heap::ArenaId::new(1));
        assert_eq!(pool.reserve(stamp, domain), Err(Error::Exhausted));
        assert_eq!(pool.in_use(), 0);
    }
    #[test]
    fn abandoned_slot_guard_is_recovered_before_buffer_reuse() {
        let pool = SegmentPool::new(1).unwrap();
        let stamp = PacketStamp::new(1, 1).unwrap();
        let producer = AllocationDomain::new(OwnerId::new(19), heap::ArenaId::new(1));
        let consumer = AllocationDomain::new(OwnerId::new(20), heap::ArenaId::new(2));
        let ticket = pool.reserve(stamp, producer).unwrap();
        // Model a fault after acquiring the slot but before recording consumer
        // identity. Target faults skip Drop; forgetting the guard reproduces it.
        let mut scope = unsafe { heap::enter_domain(consumer) };
        let guard = pool.slots[0].lock();
        core::mem::forget(guard);
        scope.restore();
        // This test's modeled consumer is terminal and cannot resume its guard.
        assert_eq!(unsafe { pool.recover_faulted_domain(consumer) }, 1);
        assert_eq!(pool.cancel(ticket, stamp), Err(Error::Stale));
        let next = pool.reserve(stamp, producer).unwrap();
        pool.cancel(next, stamp).unwrap();
    }

}
