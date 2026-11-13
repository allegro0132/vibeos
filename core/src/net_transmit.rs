//! One ordered capability queue for wire frames and pooled logical TCP sends.
//! Legacy raw packet endpoints remain a separate, unchanged resource type.
extern crate alloc;
use alloc::sync::Arc;
use core::any::Any;
use crate::{cap::Resource, chan::Endpoint, heap::{self, AllocationDomain, OwnerId},
    net::{PacketStamp, StampedPacket}, net_segment_pool::{SegmentPool, Ticket, Error}};

#[derive(Debug)]
pub enum Transmit { Frame(StampedPacket), Segments(Ticket) }
pub struct TransmitEndpoint {
    queue: Arc<Endpoint<Transmit>>,
    pool: Arc<SegmentPool>,
}
impl TransmitEndpoint {
    /// Runtime construction. One queue preserves order across both message kinds;
    /// the buffer count separately bounds large-send memory and backpressure.
    pub fn new(name: &str, queue_depth: usize, buffer_count: usize) -> Result<Arc<Self>, Error> {
        if queue_depth == 0 { return Err(Error::Capacity); }
        let pool = SegmentPool::new(buffer_count)?;
        let mut scope = heap::enter_owner(OwnerId::SYSTEM);
        let endpoint = Arc::new(Self { queue: Endpoint::new(name, queue_depth), pool });
        scope.restore(); Ok(endpoint)
    }
    pub fn pool(&self) -> &SegmentPool { &self.pool }
    pub fn try_send(&self, message: Transmit) -> Result<(), Transmit> { self.queue.try_send(message) }
    pub fn message_event(&self) -> crate::chan::MessageEvent { self.queue.message_event() }
    pub fn has_message(&self) -> bool { self.queue.has_message() }
    pub fn try_recv(&self) -> Option<Transmit> { self.queue.try_recv() }
    /// Validate a reservation before placing its allocation-free ticket on the
    /// ordered queue. Full returns the same ticket; the sender retains ownership.
    pub fn publish(&self, ticket: Ticket, stamp: PacketStamp) -> Result<Result<(), Ticket>, Error> {
        let _ = self.pool.try_consume(ticket, stamp, |_| Err::<(),_>(()))?;
        match self.queue.try_send(Transmit::Segments(ticket)) {
            Ok(()) => Ok(Ok(())),
            Err(Transmit::Segments(ticket)) => Ok(Err(ticket)),
            Err(Transmit::Frame(_)) => unreachable!(),
        }
    }
    /// # Safety
    /// Same quiescence requirements as SegmentPool::recover_faulted_domain.
    /// Queue tickets can remain queued: generation validation retires them without
    /// touching reused bytes. This only recovers pool operations; integration
    /// must also retire pending consumer state under the device session barrier.
    pub unsafe fn recover_faulted_domain(&self, domain: AllocationDomain) -> usize {
        unsafe { self.pool.recover_faulted_domain(domain) }
    }
}
impl Resource for TransmitEndpoint {
    fn kind(&self) -> &'static str { "segmented-transmit-endpoint" }
    fn as_any(&self) -> &dyn Any { self }
}
