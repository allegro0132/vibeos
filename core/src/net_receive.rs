//! Capability-addressed RX ticket queue. Device/stack stamps stay in runtime
//! policy; firmware owns DMA storage and pins an admitted immutable loan.
extern crate alloc;
use alloc::sync::Arc;
use core::any::Any;
use crate::{cap::Resource, chan::Endpoint, heap::{self, AllocationDomain, OwnerId},
    net::{PacketStamp, PacketStampMismatch}};
pub use vibeos_hal::network_rx::{Borrow, Loan, Operations, Owner, Ticket};
pub use vibeos_hal::network::Error as DeviceError;
#[cfg(feature = "rx-batch-release")]
pub use vibeos_hal::network_rx::ReleaseBatch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stamped { ticket: Ticket, stamp: PacketStamp }
impl Stamped {
    pub const fn new(ticket: Ticket, stamp: PacketStamp) -> Self { Self { ticket, stamp } }
    pub const fn stamp(self) -> PacketStamp { self.stamp }
    pub const fn ticket(self) -> Ticket { self.ticket }
}
#[cfg(feature = "rx-publish-batch")]
const _: () = assert!(vibeos_hal::network_rx::BATCH_SIZE <= 32);

/// Runtime-owned pending batch. Construct under the session publication
/// barrier; remaining tickets keep that original stamp across later rebinding.
/// The producer must drain/discard it, or retire its device after owner failure.
/// This owns ticket bookkeeping only, never payload references or DMA authority.
pub struct StampedBatch {
    #[cfg(not(feature = "rx-publish-batch"))]
    tickets: vibeos_hal::network_rx::TicketBatch,
    #[cfg(feature = "rx-publish-batch")]
    frames: [Option<Stamped>; vibeos_hal::network_rx::BATCH_SIZE],
    #[cfg(feature = "rx-publish-batch")]
    end: usize,
    // Captured at publication, never refreshed when a pending ticket is popped.
    // All pending entries retain their original publication stamp.
    stamp: Option<PacketStamp>,
    next: usize,
}
impl StampedBatch {
    pub const fn empty() -> Self {
        Self {
            #[cfg(not(feature = "rx-publish-batch"))]
            tickets: [None; vibeos_hal::network_rx::BATCH_SIZE],
            #[cfg(feature = "rx-publish-batch")]
            frames: [None; vibeos_hal::network_rx::BATCH_SIZE],
            #[cfg(feature = "rx-publish-batch")]
            end: 0,
            stamp: None, next: vibeos_hal::network_rx::BATCH_SIZE,
        }
    }
    pub fn new(tickets: vibeos_hal::network_rx::TicketBatch, stamp: PacketStamp) -> Self {
        #[cfg(not(feature = "rx-publish-batch"))]
        { Self { tickets, stamp: Some(stamp), next: 0 } }
        #[cfg(feature = "rx-publish-batch")]
        {
            let mut batch = Self::empty(); batch.stamp = Some(stamp); batch.next = 0;
            for ticket in tickets.into_iter().flatten() {
                batch.frames[batch.end] = Some(Stamped::new(ticket, stamp)); batch.end += 1;
            }
            batch
        }
    }
    pub fn pop(&mut self) -> Option<Stamped> {
        #[cfg(feature = "rx-publish-batch")]
        {
            if self.next >= self.end { return None; }
            let index = self.next; self.next += 1; self.frames[index].take()
        }
        #[cfg(not(feature = "rx-publish-batch"))]
        {
            let stamp = self.stamp?;
            while self.next < self.tickets.len() {
                let index = self.next; self.next += 1;
                if let Some(ticket) = self.tickets[index].take() { return Some(Stamped::new(ticket, stamp)); }
            }
            None
        }
    }
    #[cfg(feature = "rx-publish-batch")]
    pub fn remaining(&self) -> usize { self.end.saturating_sub(self.next) }
    #[cfg(feature = "rx-publish-batch")]
    pub fn stamp(&self) -> Option<PacketStamp> { self.stamp }

}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity, UntrackedOwner, Session(PacketStampMismatch), Device(vibeos_hal::network::Error),
}
pub struct ReceiveEndpoint { queue: Arc<Endpoint<Stamped>>, operations: &'static Operations }
impl ReceiveEndpoint {
    /// # Safety
    /// The supervisor selects valid static operations for this DMA device.
    /// Their complete HAL contract must hold for every operation and reset.
    pub unsafe fn new(name: &str, depth: usize, operations: &'static Operations) -> Result<Arc<Self>, Error> {
        if depth == 0 { return Err(Error::Capacity); }
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let endpoint = Arc::new(Self { queue: Endpoint::new(name, depth), operations });
        system.restore(); Ok(endpoint)
    }
    pub fn try_send(&self, frame: Stamped) -> Result<(), Stamped> { self.queue.try_send(frame) }
    /// Caller holds live send authority and the session publication barrier.
    /// Accepted prefix moves into the queue; unsent suffix retains its stamp.
    #[cfg(feature = "rx-publish-batch")]
    pub fn try_send_batch(&self, batch: &mut StampedBatch, limit: usize) -> usize {
        if batch.remaining() == 0 { return 0; }
        let sent = self.queue.try_send_batch(&mut batch.frames[batch.next..batch.end], limit);
        batch.next += sent;
        sent
    }
    pub fn message_event(&self) -> crate::chan::MessageEvent { self.queue.message_event() }
    pub fn has_message(&self) -> bool { self.queue.has_message() }
    pub fn discard(&self, frame: Stamped) -> bool { unsafe { (self.operations.discard)(frame.ticket) } }
    /// Invoke only inside live receive authority, using the supervisor-derived
    /// allocation domain. The returned loan retains already-admitted ownership;
    /// dropping it is cleanup, not a new capability invocation.
    pub fn try_receive(&self, expected: PacketStamp, domain: AllocationDomain) -> Result<Option<Loan>, Error> {
        #[cfg(feature = "rx-queue-profile")]
        let sample = queue_profile::begin();
        #[cfg(feature = "rx-queue-profile")]
        let mut queue_ticks = 0;
        let result = (|| {
            let owner = Owner::new(domain.owner.get(), domain.arena.get()).ok_or(Error::UntrackedOwner)?;
            #[cfg(feature = "rx-queue-profile")]
            let queue_start = sample.as_ref().map(|_| crate::arch::time());
            let frame = self.queue.try_recv();
            #[cfg(feature = "rx-queue-profile")]
            if let Some(start) = queue_start { queue_ticks = crate::arch::time().wrapping_sub(start); }
            let Some(frame) = frame else { return Ok(None); };
            if frame.stamp != expected {
                self.discard(frame);
                return Err(Error::Session(PacketStampMismatch { expected, observed: frame.stamp }));
            }
            match unsafe { (self.operations.acquire)(frame.ticket, owner) } {
                Ok(loan) => Ok(Some(loan)),
                Err(error) => { self.discard(frame); Err(Error::Device(error)) }
            }
        })();
        #[cfg(feature = "rx-queue-profile")]
        queue_profile::finish(sample, queue_ticks, &result);
        result
    }

    /// Caller holds the session publication barrier; producers cannot refill
    /// this queue during retirement. In-flight loans remain pinned separately.
    pub fn retire_queued(&self) -> usize {
        let mut count = 0;
        while let Some(frame) = self.queue.try_recv() { self.discard(frame); count += 1; }
        count
    }
    /// # Safety
    /// The exact allocation incarnation is quiescent and can never resume.
    /// Ordinary cancellation/revocation must release loans normally instead.
    pub unsafe fn recover(&self, domain: AllocationDomain) -> usize {
        let Some(owner) = Owner::new(domain.owner.get(), domain.arena.get()) else { return 0; };
        unsafe { (self.operations.recover)(owner) }
    }
}
impl Resource for ReceiveEndpoint {
    fn kind(&self) -> &'static str { "detached-receive-endpoint" }
    fn as_any(&self) -> &dyn Any { self }
}

/// Diagnostic only: separate queue dequeue from the complete loan admission.
/// Rows are success, empty, rejection; samples are systematic, not exclusive CPU.
#[cfg(feature = "rx-queue-profile")]
pub mod queue_profile {
    use super::{Error, Loan};
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
    const INTERVAL: u64 = 127;
    #[repr(align(64))]
    struct Counters { calls: AtomicU64, rows: [[AtomicU64; 3]; 3] }
    static COUNTERS: [Counters; crate::exec::MAX_HARTS] = [const { Counters {
        calls: AtomicU64::new(0), rows: [const { [const { AtomicU64::new(0) }; 3] }; 3],
    } }; crate::exec::MAX_HARTS];
    pub(super) fn begin() -> Option<(usize, u64)> {
        let hart = crate::ipi::current_logical_hart()?.index();
        let count = COUNTERS[hart].calls.fetch_add(1, Relaxed);
        (count % INTERVAL == 0).then(|| (hart, crate::arch::time()))
    }
    pub(super) fn finish(sample: Option<(usize, u64)>, queue: u64, result: &Result<Option<Loan>, Error>) {
        let Some((hart, start)) = sample else { return; };
        let total = crate::arch::time().wrapping_sub(start);
        let row = match result { Ok(Some(_)) => 0, Ok(None) => 1, Err(_) => 2 };
        for (counter, value) in COUNTERS[hart].rows[row].iter().zip([1, queue, total]) {
            counter.fetch_add(value, Relaxed);
        }
    }
    pub fn snapshot(hart: usize) -> Option<(u64, [[u64; 3]; 3])> {
        let counters = COUNTERS.get(hart)?;
        Some((counters.calls.load(Relaxed), core::array::from_fn(|row|
            core::array::from_fn(|column| counters.rows[row][column].load(Relaxed)))))
    }
}
