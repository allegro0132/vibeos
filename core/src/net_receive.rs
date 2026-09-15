//! Capability-addressed RX ticket queue. Device/stack stamps stay in runtime
//! policy; firmware owns DMA storage and pins an admitted immutable loan.
extern crate alloc;
use alloc::sync::Arc;
use core::any::Any;
use crate::{cap::Resource, chan::Endpoint, heap::{self, AllocationDomain, OwnerId},
    net::{PacketStamp, PacketStampMismatch}};
pub use vibeos_hal::network_rx::{Borrow, Loan, Operations, Owner, Ticket};
pub use vibeos_hal::network::Error as DeviceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stamped { ticket: Ticket, stamp: PacketStamp }
impl Stamped {
    pub const fn new(ticket: Ticket, stamp: PacketStamp) -> Self { Self { ticket, stamp } }
    pub const fn stamp(self) -> PacketStamp { self.stamp }
    pub const fn ticket(self) -> Ticket { self.ticket }
}
/// Runtime-owned pending batch. Construct under the session publication
/// barrier; remaining tickets keep that original stamp across later rebinding.
/// The producer must drain/discard it, or retire its device after owner failure.
/// This owns ticket bookkeeping only, never payload references or DMA authority.
pub struct StampedBatch {
    frames: [Option<Stamped>; vibeos_hal::network_rx::BATCH_SIZE],
    next: usize,
}
impl StampedBatch {
    pub const fn empty() -> Self {
        Self { frames: [None; vibeos_hal::network_rx::BATCH_SIZE], next: vibeos_hal::network_rx::BATCH_SIZE }
    }
    pub fn new(tickets: vibeos_hal::network_rx::TicketBatch, stamp: PacketStamp) -> Self {
        Self { frames: tickets.map(|ticket| ticket.map(|ticket| Stamped::new(ticket, stamp))), next: 0 }
    }
    pub fn pop(&mut self) -> Option<Stamped> {
        while self.next < self.frames.len() {
            let index = self.next;
            self.next += 1;
            if let Some(frame) = self.frames[index].take() { return Some(frame); }
        }
        None
    }
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
    pub fn message_event(&self) -> crate::chan::MessageEvent { self.queue.message_event() }
    pub fn has_message(&self) -> bool { self.queue.has_message() }
    pub fn discard(&self, frame: Stamped) -> bool { unsafe { (self.operations.discard)(frame.ticket) } }
    /// Invoke only inside live receive authority, using the supervisor-derived
    /// allocation domain. The returned loan retains already-admitted ownership;
    /// dropping it is cleanup, not a new capability invocation.
    pub fn try_receive(&self, expected: PacketStamp, domain: AllocationDomain) -> Result<Option<Loan>, Error> {
        let owner = Owner::new(domain.owner.get(), domain.arena.get()).ok_or(Error::UntrackedOwner)?;
        let Some(frame) = self.queue.try_recv() else { return Ok(None); };
        if frame.stamp != expected {
            self.discard(frame);
            return Err(Error::Session(PacketStampMismatch { expected, observed: frame.stamp }));
        }
        match unsafe { (self.operations.acquire)(frame.ticket, owner) } {
            Ok(loan) => Ok(Some(loan)),
            Err(error) => { self.discard(frame); Err(Error::Device(error)) }
        }
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
