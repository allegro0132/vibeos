//! A detached RX queue has one consumer and never touches TX or another RX ring.
use crate::{Io, Received, Error, RX_RING, BUFFER, RX, DONE, LAST, rx_offload};
pub(crate) struct Queue { queue: usize, head: usize, buffers: [usize; RX_RING], headroom: usize }
impl Queue {
    pub(crate) fn new(queue:usize,head:usize,buffers:[usize;RX_RING],headroom:usize)->Self { Self {queue,head,buffers,headroom} }
    pub fn index(&self)->usize {self.queue}
    /// Backend access must belong to the original permanent arena. A false
    /// callback leaves this descriptor CPU-owned; no other queue may consume it.
    fn receive(&mut self, io:&mut impl Io, accept:impl FnOnce(Received,&[u8])->bool)->Result<Option<bool>,Error> {
        let d=RX+(self.queue*RX_RING+self.head)*32;
        let status=io.word(d+4);
        if status&DONE==0 {return Ok(None);}
        io.barrier();
        let len=((status>>8)&65535) as usize;
        let valid=(14..=BUFFER-self.headroom).contains(&len) && status&LAST!=0;
        if valid {
            let mut packet=Received::decode(len,io.word(d+16));
            packet.offload=rx_offload::Metadata::decode(io.word(d+8),io.word(d+24),self.queue as u8);
            let bytes=unsafe {io.buffer_mut(self.buffers[self.head])};
            if !accept(packet,&bytes[self.headroom..self.headroom+len]) {return Ok(Some(false));}
        }
        io.set_word(d,io.dma_address() as u32+(self.buffers[self.head]+self.headroom) as u32);
        for offset in (8..32).step_by(4) {io.set_word(d+offset,0);}
        io.barrier();io.set_word(d+4,((BUFFER-self.headroom) as u32)<<8);
        self.head=(self.head+1)%RX_RING;
        rx_offload::record_queue(self.queue);
        if valid {Ok(Some(true))}else{Err(Error::Malformed)}
    }
    /// Return a contiguous, bounded prefix to DMA with one CPU-index write.
    /// Malformed descriptors are recycled. A deferred frame stays at head.
    pub(crate) fn drain(&mut self, io: &mut impl Io, budget: usize, mut accept: impl FnMut(Received, &[u8]) -> bool) -> usize {
        let mut count = 0;
        while count < budget.min(RX_RING / 2) {
            match self.receive(io, &mut accept) {
                Ok(Some(true)) | Err(Error::Malformed) => count += 1,
                _ => break,
            }
        }
        if count != 0 {
            self.publish(io);
        }
        count
    }
    fn publish(&self, io: &mut impl Io) {
        io.barrier();
        io.set_reg(0x6908 + self.queue * 16, ((self.head + RX_RING - 1) % RX_RING) as u32);
    }
}
#[cfg(all(target_arch="aarch64",target_os="none"))]
pub struct Owner { queue:Queue, io:crate::Mmio }
#[cfg(all(target_arch="aarch64",target_os="none"))]
impl Owner {
    pub fn index(&self)->usize {self.queue.index()}
    pub fn receive(&mut self, accept: impl FnOnce(Received, &[u8]) -> bool) -> Result<Option<bool>, Error> {
        let result = self.queue.receive(&mut self.io, accept);
        if matches!(result, Ok(Some(true)) | Err(Error::Malformed)) {
            self.queue.publish(&mut self.io);
        }
        result
    }
    pub fn drain(&mut self, budget: usize, accept: impl FnMut(Received, &[u8]) -> bool) -> usize {
        self.queue.drain(&mut self.io, budget, accept)
    }
}
#[cfg(all(target_arch="aarch64",target_os="none"))]
impl crate::Nic<crate::Mmio> {
    pub fn split_rx(&mut self,queue:usize)->Result<Owner,Error> {
        let queue=self.detach_rx(queue)?;
        // The private Queue restricts this backend to disjoint RX descriptors,
        // private buffers and one queue doorbell. It exposes no MMIO/TX access.
        let io=unsafe {crate::Mmio::new(self.io.arena,self.io.clock)};
        Ok(Owner {queue,io})
    }
}
