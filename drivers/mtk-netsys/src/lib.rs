#![no_std]
//! MT7988 NETSYS v3 PDMA ring ownership. Initial board contract inherits the
//! bootloader's clocks and calibrated PHYs; the board owns switch isolation.
//! Register/descriptor layout reference: U-Boot drivers/net/mtk_eth.

#[cfg(feature = "ppe-32k")]
extern crate alloc;
#[cfg(any(test, feature = "qdma-test"))]
pub mod qdma;
pub mod mdio;
pub mod offload;
pub mod rx_offload;
#[cfg(feature="rx-multicore")]
pub mod rx_queue;
pub mod ppe;
pub mod mxl862xx;
pub mod mxl_tag;
mod mxl_vlan;

// Inclusive CPU costs in architectural timer ticks, not DMA flight latency.
static TX_COST:[core::sync::atomic::AtomicU64;3]=[const{core::sync::atomic::AtomicU64::new(0)};3];
fn tx_clock()->u64 {
    #[cfg(all(target_arch="aarch64",target_os="none"))] {let t;unsafe{core::arch::asm!("mrs {t}, cntpct_el0",t=out(reg)t,options(nomem,nostack,preserves_flags));}t}
    #[cfg(not(all(target_arch="aarch64",target_os="none")))] {0}
}
fn tx_cost(index:usize,start:u64){TX_COST[index].fetch_add(tx_clock().wrapping_sub(start),core::sync::atomic::Ordering::Relaxed);}
/// DMA copy, preparation/descriptor writes, QDMA completion polling. The
/// submission cost includes copy/prepare; callers must not add nested totals.
pub fn tx_costs()->[u64;3]{core::array::from_fn(|i|TX_COST[i].load(core::sync::atomic::Ordering::Relaxed))}

/// NETSYS v3 PSE port numbers: GMAC2 uses GDM3/FPORT 15, not 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxPort {
    Internal,
    /// Internal switch with its four-byte CPU port tag in the frame: the
    /// caller selects destination ports, the switch removes the tag.
    InternalTagged,
    /// Independent GMAC1/GDM2 path; no MxL CPU tag.
    Wan,
    ExternalTagged,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    pub length: usize,
    pub source_port: u8,
    descriptor_word5: u32,
    pub offload: rx_offload::Metadata,
}
impl Received {
    fn decode(length: usize, word5: u32) -> Self {
        Self { length, source_port: ((word5 >> 26) & 15) as u8, descriptor_word5: word5, offload: rx_offload::Metadata::decode(0,0,0) }
    }
    /// NETSYS v3 RXD5 CPU reason. Diagnostic metadata only: it is not a
    /// validated protocol, installation ticket or authorization to forward.
    pub fn ppe_reason(self) -> u8 { ((self.descriptor_word5 >> 18) & 31) as u8 }
    /// Raw 15-bit FOE index, including sentinel 0x7fff. Never use this to
    /// dereference a table or infer which software-owned installation matched.
    pub fn foe_index(self) -> u16 { (self.descriptor_word5 & 0x7fff) as u16 }
}

/// Decision made while software exclusively owns an RX buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAction {
    /// Leave this head descriptor CPU-owned for another processing path.
    /// The callback must leave the received bytes unchanged when deferring.
    /// No RX/TX indices, descriptor ownership or buffer mappings advance.
    Defer,
    Drop,
    Transmit { port: TxPort, length: usize },
    /// RX-only: transmit from byte four of the same owned buffer. Used after
    /// removing a CPU tag by moving only the Ethernet MAC addresses forward.
    /// `length` excludes the skipped four bytes; initialize all output bytes.
    TransmitShifted { port: TxPort, length: usize },
    /// Only for receive_with_headroom: offset is relative to the whole pool
    /// buffer, aligned to four bytes with a complete inner Ethernet header
    /// inside the received extent. Output and Ethernet padding must fit the pool.
    TransmitFrom { port: TxPort, length: usize, offset: usize },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Processed {
    pub received: Received,
    pub transmitted: bool,
}

// Independent RX consumers share a core with TLS work; absorb scheduling bursts.
// Poll budgets remain bounded independently of descriptor capacity.
pub const RING: usize = 32;
const _: () = assert!(RING <= u32::BITS as usize);
pub const RX_RING: usize = if cfg!(feature = "rx-multicore") { 128 } else { 32 };
pub const BUFFER: usize = 2048;
pub const RX_QUEUES: usize = if cfg!(feature = "rx-multicore") { 5 } else if cfg!(feature = "rx-rss") { 4 } else { 1 };
const RX_TOTAL: usize = RX_QUEUES * RX_RING;
const LARGE_POOL: usize = POOL + (RING + RX_TOTAL) * BUFFER;
/// Largest plain IPv6 TSO request staged within a single aligned DMA page.
pub const IPV6_TSO_WINDOW: usize = 4096;
const _: () = assert!(2 * IPV6_TSO_WINDOW - 1 <= TX_LARGE);
pub const TX_LARGE: usize = 16384 + 16;
pub const ARENA_SIZE: usize = LARGE_POOL + if cfg!(feature="tx-offload") { RING * TX_LARGE } else { 0 };
const RX: usize = RING * 32;
const POOL: usize = ((RING + RX_TOTAL) * 32 + BUFFER - 1) & !(BUFFER - 1);
const DONE: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const CFG: usize = 0x6a04;

/// Register offsets are relative to FE. DMA offsets are relative to the
/// exclusively owned arena. Barrier orders CPU/DMA ownership and MMIO.
pub trait Io {
    /// DMA base of this backend's exclusively owned arena.
    fn dma_address(&self) -> u64;
    fn reg(&self, offset: usize) -> u32;
    fn set_reg(&mut self, offset: usize, value: u32);
    fn word(&self, offset: usize) -> u32;
    fn set_word(&mut self, offset: usize, value: u32);
    fn byte(&self, offset: usize) -> u8;
    fn set_byte(&mut self, offset: usize, value: u8);
    /// # Safety
    /// The caller has acquired exclusive CPU ownership of this whole buffer,
    /// and must end the borrow before publishing it to DMA. Implementations
    /// return exactly BUFFER initialized bytes at the specified pool offset.
    unsafe fn buffer_mut(&mut self, offset: usize) -> &mut [u8];
    /// Exclusive permanent large TX slot; never shared with RX.
    unsafe fn large_tx_mut(&mut self, _slot:usize)-> &mut [u8] { panic!("large TX unavailable") }
    fn barrier(&self);
    fn now(&self) -> u64;
    fn poll_transmit(&mut self) -> Result<(), Error> { Ok(()) }
    fn notify_transmit(&mut self, end: usize) -> Result<(), Error> {
        self.set_reg(0x6808, end as u32); Ok(())
    }
    /// Only QDMA backends may accept NETSYS v3 TX offload metadata.
    fn tx_offload_supported(&self) -> bool { false }
    fn pdma_enable(&self) -> u32 { 0x45 }
    fn start_transmit(&mut self) -> Result<(), Error> { Ok(()) }
    fn prepare_transmit(&mut self) -> Result<(), Error> { Ok(()) }
    fn stop_transmit(&mut self, _timeout: u64) -> Result<(), Error> { Err(Error::NotReady) }

}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Address,
    Busy,
    Length,
    Malformed,
    NotReady,
    Timeout,
}

/// Submission identity; success only transfers ownership, not completion.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct TxReceipt { slot:usize, generation:u64 }
pub mod packet_copy;
pub struct Nic<I: Io> {
    tx_generation:[u64;RING],
    outstanding_tx: core::sync::atomic::AtomicU32,
    io: I,
    tx: usize,
    rx: usize,
    ready: bool,
    tx_buffers: [usize; RING],
    rx_buffers: [usize; RX_TOTAL],
    rx_heads: [usize; RX_QUEUES],
    rss: bool,
    detached: u8,
    software_tail: usize,
    rx_headroom: usize,
}
/// A synchronous RX/TX burst. Drop publishes all completed descriptors before
/// the NIC can be used again. Never hold this across a wait or scheduler yield.
#[must_use]
pub struct ReceiveBatch<'a, I: Io> {
    nic: &'a mut Nic<I>,
    pending: Notifications,
    count: usize,
}
#[derive(Default)]
struct Notifications { tx: bool, rx: [Option<usize>; RX_QUEUES] }
impl<I: Io> ReceiveBatch<'_, I> {
    /// Reserve opportunity under the sole NIC owner. No other submission may
    /// intervene before the caller's submit_tracked. Busy avoids GSO advancement.
    pub fn tx_available(&mut self)->Result<bool,Error> {
        if !self.nic.ready {return Err(Error::NotReady);}
        if self.nic.io.word(self.nic.tx*32+4)&DONE!=0 {return Ok(true);}
        self.nic.publish_notifications(&mut self.pending);self.count=0;
        self.nic.poll_transmit()?;
        Ok(self.nic.io.word(self.nic.tx*32+4)&DONE!=0)
    }

    /// Submit a fully staged frame. Completion is checked on Nic after this
    /// batch publishes; the caller retains its owner token until then.
    pub fn submit_tracked(&mut self, port:TxPort, packet:&[u8], options:Option<offload::TxOffload>) -> Result<TxReceipt,Error> {
        let result=self.nic.stage_tracked(port,packet,options);
        if result.is_ok() {self.pending.tx=true;self.count+=1;}
        if self.count>=RING/2 || result.is_err() {self.nic.publish_notifications(&mut self.pending);self.count=0;}
        result
    }

    /// Submit one verified Ethernet/IP frame to the QDMA PPE1 forwarding port.
    /// The route owner must retain the exclusive table until QDMA release and PPE drain.
    pub unsafe fn reinject_ppe1(&mut self, frame: &[u8], timeout: u64) -> Result<(), Error> {
        if !self.nic.io.tx_offload_supported() { return Err(Error::NotReady); }
        if !(14..=1514).contains(&frame.len()) || timeout == 0 { return Err(Error::Length); }
        self.nic.publish_notifications(&mut self.pending);
        self.count = 0;
        let receipt = self.nic.stage_packet(TxPort::Internal, frame, None, true)?;
        self.nic.notify_transmit()?;
        let start = self.nic.io.now();
        loop {
            self.nic.poll_transmit()?;
            if self.nic.tx_completed(receipt) { return Ok(()); }
            if self.nic.io.now().wrapping_sub(start) >= timeout { return Err(Error::Timeout); }
        }
    }

    /// Process a CPU-owned RSS exception without injecting it into a fake DMA
    /// RX ring. Busy is checked before the callback; on Pending the caller
    /// retains this buffer. Forwarded output is copied once to permanent TX.
    pub fn receive_external(&mut self, packet:Received, offset:usize, buffer:&mut [u8],
        process:impl FnOnce(Received,usize,&mut [u8])->RxAction)->Result<Option<Processed>,Error> {
        if offset.checked_add(packet.length).is_none_or(|end|end>buffer.len()) || packet.length<14 {return Err(Error::Length);}
        if !self.tx_available()? {return Err(Error::Busy);}
        let action=process(packet,offset,buffer);
        let (port,length,start)=match action {
            RxAction::Defer=>return Ok(None),
            RxAction::Drop=>return Ok(Some(Processed{received:packet,transmitted:false})),
            RxAction::Transmit{port,length}=>(port,length,offset),
            RxAction::TransmitShifted{port,length}=>(port,length,offset+4),
            RxAction::TransmitFrom{port,length,offset}=>(port,length,offset),
        };
        let (min,max)=match port {TxPort::Internal=>(14,1514),TxPort::InternalTagged=>(18,1518),TxPort::Wan=>(14,1518),TxPort::ExternalTagged=>(18,1522)};
        if !(min..=max).contains(&length) || start%4!=0 {return Err(Error::Length);}
        let bytes=buffer.get(start..start+length).ok_or(Error::Length)?;
        self.submit_tracked(port,bytes,None)?;
        Ok(Some(Processed{received:packet,transmitted:true}))
    }

    /// Queue producer output with the same ownership rules as Nic::transmit_with.
    /// Publish at half-ring, on backpressure/error, or when this guard drops.
    pub fn transmit_with(&mut self, produce: impl FnOnce(&mut [u8]) -> RxAction) -> Result<bool,Error> {
        let result=self.nic.transmit_deferred(produce,&mut self.pending);
        self.count+=1;
        if self.count>=RING/2 || !matches!(result,Ok(true)) {
            self.nic.publish_notifications(&mut self.pending);
            self.count=0;
        }
        result
    }
    pub fn receive_in_place(
        &mut self, process: impl FnOnce(Received, &mut [u8]) -> RxAction,
    ) -> Result<Option<Processed>, Error> {
        let result = self.nic.receive_deferred(process, &mut self.pending, false);
        self.finish(result)
    }
    /// Expose the whole buffer plus the received frame's starting offset.
    /// Initialize every byte selected by TransmitFrom, including any prefix.
    pub fn receive_with_headroom(
        &mut self, process: impl FnOnce(Received, usize, &mut [u8]) -> RxAction,
    ) -> Result<Option<Processed>, Error> {
        let offset = self.nic.rx_headroom;
        let result = self.nic.receive_deferred(|packet, buffer| process(packet, offset, buffer), &mut self.pending, true);
        self.finish(result)
    }
    fn finish(&mut self, result: Result<Option<Processed>, Error>) -> Result<Option<Processed>, Error> {
        self.count += 1;
        // Publish before wrapping a full ring, and on empty/defer/backpressure.
        if self.count >= RING / 2 || !matches!(result, Ok(Some(_))) {
            self.nic.publish_notifications(&mut self.pending);
            self.count = 0;
        }
        result
    }
}
impl<I: Io> Drop for ReceiveBatch<'_, I> {
    fn drop(&mut self) { self.nic.publish_notifications(&mut self.pending); }
}
impl<I: Io> Nic<I> {
    /// True only after the QDMA bridge has observed its release endpoint and
    /// descriptor ownership (or the slot was necessarily completed and reused).
    pub fn tx_completed(&self, receipt:TxReceipt)->bool {
        self.tx_generation[receipt.slot]>receipt.generation ||
            (self.tx_generation[receipt.slot]==receipt.generation && self.io.word(receipt.slot*32+4)&DONE!=0)
    }
    fn stage_tracked(&mut self,port:TxPort,packet:&[u8],options:Option<offload::TxOffload>)->Result<TxReceipt,Error> {
        self.stage_packet(port, packet, options, false)
    }
    fn stage_packet(&mut self,port:TxPort,packet:&[u8],options:Option<offload::TxOffload>,reinject:bool)->Result<TxReceipt,Error> {
        if !self.ready {return Err(Error::NotReady);}
        let large=packet.len()>BUFFER;
        if !(14..=TX_LARGE).contains(&packet.len()) || (large && options.is_none()) {return Err(Error::Length);}
        if options.is_some() && !self.io.tx_offload_supported() {return Err(Error::NotReady);}
        let slot=self.tx;let d=slot*32;
        if self.io.word(d+4)&DONE==0 {self.poll_transmit()?;if self.io.word(d+4)&DONE==0 {return Err(Error::Busy);}}
        self.io.barrier();
        let slot_base=if large {LARGE_POOL+slot*TX_LARGE}else{self.tx_buffers[slot]};
        // Keep bounded IPv6 TSO reads inside one physical page. Each ring slot
        // owns TX_LARGE bytes, including the alignment padding.
        let page_offset = if large && packet.len() <= IPV6_TSO_WINDOW
            && options.is_some_and(|o| o.tso_mss.is_some()) && packet.get(12..14) == Some(&[0x86, 0xdd]) {
            (self.io.dma_address() as usize + slot_base).wrapping_neg() & (IPV6_TSO_WINDOW - 1)
        } else { 0 };
        let buffer=slot_base+page_offset;
        let mut length=packet.len().max(if options.is_none() && matches!(port,TxPort::InternalTagged|TxPort::ExternalTagged){64}else{60});
        let start=tx_clock();
        let prepared;
        // Parse the cacheable producer view. TSO only needs one two-byte MSS
        // write after copying; rereading headers from Normal-NC DMA is costly.
        let explicit = options.map(|o| o.validate(packet, port)).transpose()?;
        let meta=unsafe {
            let out=if large {&mut self.io.large_tx_mut(slot)[page_offset..]}else{self.io.buffer_mut(buffer)};
            packet_copy::copy(&mut out[..packet.len()],packet);out[packet.len()..length].fill(0);
            tx_cost(0,start);prepared=tx_clock();
            match explicit {
                Some((metadata, field)) => {
                    if let Some((offset, mss)) = field {
                        out[offset..offset + 2].copy_from_slice(&mss.to_be_bytes());
                    }
                    Some(metadata)
                }
                None if reinject => None,
                None=>{
                #[cfg(feature="tx-offload")]
                {let prepared=offload::prepare_ordinary(&mut out[..length],port);if let Some((n,_))=prepared {length=n;}prepared.map(|(_,m)|m)}
                #[cfg(not(feature="tx-offload"))]
                {None}
            }}
        };
        let generation=self.tx_generation[slot].checked_add(1).ok_or(Error::Malformed)?;
        self.tx_generation[slot]=generation;
        self.io.set_word(d,self.io.dma_address() as u32+buffer as u32);
        self.io.set_word(d+16,if reinject {4<<16} else {match port {TxPort::Internal|TxPort::InternalTagged=>1<<16,TxPort::Wan=>2<<16,TxPort::ExternalTagged=>15<<16}});
        self.io.set_word(d+20,meta.map_or(0,|m|m.word5));self.io.set_word(d+24,meta.map_or(0,|m|m.word6));
        offload::record(meta);self.io.barrier();self.io.set_word(d+4,LAST|((length as u32)<<8));self.io.barrier();
        self.advance_tx();tx_cost(1,prepared);Ok(TxReceipt{slot,generation})
    }
    pub fn new(io: I) -> Self {
        Self {
            io,
            tx: 0,
            tx_generation:[0;RING],
            outstanding_tx: core::sync::atomic::AtomicU32::new(0),
            rx: 0,
            ready: false,
            tx_buffers: core::array::from_fn(|i| POOL + i * BUFFER),
            rx_buffers: core::array::from_fn(|i| POOL + (RING + i) * BUFFER),
            rx_headroom: 0,
            rx_heads: [0; RX_QUEUES],
            rss: false,
            detached: 0,
            software_tail: 0,
        }
    }
    /// Reserve four bytes before every received frame for a CPU switch tag.
    /// Legacy receive APIs still expose Ethernet at slice offset zero.
    pub fn new_with_rx_headroom(io: I) -> Self {
        let mut nic = Self::new(io);
        nic.rx_headroom = 4;
        nic
    }
    /// Configure before initialization. Each ring has a separate descriptor
    /// head and doorbell; this owner currently polls them fairly on one CPU.
    /// The proxy workers retain their existing per-connection CPU affinity.
    #[cfg(feature = "rx-rss")]
    pub fn with_rss(mut self) -> Self { self.rss = true; self }
    fn receive_queues(&self) -> usize { if self.rss { RX_QUEUES } else { 1 } }
    fn select_receive(&mut self) {
        // A deferred head stays selected until consumed, preserving the
        // caller's pause-before-mutation contract across fast/slow paths.
        if self.detached & (1 << (self.rx / RX_RING)) == 0 && self.io.word(RX + self.rx * 32 + 4) & DONE != 0 { return; }
        let first = self.rx / RX_RING;
        for step in 0..self.receive_queues() {
            let queue = (first + step) % self.receive_queues();
            if self.detached & (1 << queue) != 0 { continue; }
            let index = queue * RX_RING + self.rx_heads[queue];
            if self.io.word(RX + index * 32 + 4) & DONE != 0 { self.rx = index; return; }
        }
        self.rx = self.rx_heads[0];
    }
    /// Permanently transfer one hardware RX queue. Its buffers may no longer
    /// participate in this NIC's TX exchange. Reinitialization is forbidden.
    #[cfg(feature="rx-multicore")]
    pub(crate) fn detach_rx(&mut self, queue: usize) -> Result<rx_queue::Queue, Error> {
        if !self.ready || !self.rss || !(1..4).contains(&queue) || self.detached & (1 << queue) != 0 {
            return Err(Error::NotReady);
        }
        self.detached |= 1 << queue;
        self.rx = self.rx_heads[0];
        Ok(rx_queue::Queue::new(queue, self.rx_heads[queue],
            core::array::from_fn(|i| self.rx_buffers[queue * RX_RING + i]), self.rx_headroom))
    }
    /// Copy a remote consumer's unmodified exception into a CPU-only ring.
    /// Hardware ring 4 is disabled; it is never present in the RSS table.
    #[cfg(feature="rx-multicore")]
    pub fn inject_received(&mut self, packet: Received, bytes: &[u8]) -> Result<bool, Error> {
        if !self.ready || !self.rss { return Err(Error::NotReady); }
        if bytes.len() != packet.length || !(14..=BUFFER-self.rx_headroom).contains(&bytes.len()) { return Err(Error::Length); }
        let slot = 4 * RX_RING + self.software_tail;
        let descriptor = RX + slot * 32;
        if self.io.word(descriptor + 4) & DONE != 0 { return Ok(false); }
        unsafe { self.io.buffer_mut(self.rx_buffers[slot])[self.rx_headroom..self.rx_headroom+bytes.len()].copy_from_slice(bytes); }
        self.io.set_word(descriptor + 8, packet.offload.word3());
        self.io.set_word(descriptor + 16, packet.descriptor_word5);
        self.io.set_word(descriptor + 24, packet.offload.raw_word7());
        self.io.barrier();
        self.io.set_word(descriptor + 4, DONE | LAST | ((bytes.len() as u32) << 8));
        self.io.barrier();
        self.software_tail = (self.software_tail + 1) % RX_RING;
        Ok(true)
    }
    /// Arena is permanent Normal-NC memory with identical CPU/DMA addresses.
    /// Caller enables the CPU bridge only after successful initialization.
    pub fn initialize(&mut self, timeout_ticks: u64) -> Result<(), Error> {
        if self.detached != 0 { return Err(Error::Busy); }
        let physical = self.io.dma_address();
        if physical == 0
            || physical & 63 != 0
            || physical
                .checked_add(ARENA_SIZE as u64)
                .filter(|v| *v <= 1u64 << 32)
                .is_none()
        {
            return Err(Error::Address);
        }
        self.io.prepare_transmit()?;
        self.ready = false;
        self.io.set_reg(CFG, self.io.reg(CFG) & !0x45);
        self.io.barrier();
        let start = self.io.now();
        while self.io.reg(CFG) & 0xa != 0 {
            if self.io.now().wrapping_sub(start) >= timeout_ticks {
                return Err(Error::Timeout);
            }
        }
        // Preserve lower configuration bits, clear old ring mode bits.
        self.io.set_reg(CFG, self.io.reg(CFG) & 0xfeff);
        // No large-buffer receive rings are published by this driver. Never
        // inherit a bootloader's LRO aggregation mode into 2 KiB buffers.
        self.io.set_reg(0x6c08, 0);
        self.io.set_reg(0x124, self.io.reg(0x124) | 0x10);
        for offset in (0..ARENA_SIZE).step_by(4) {
            self.io.set_word(offset, 0);
        }
        for i in 0..RING {
            self.tx_buffers[i] = POOL + i * BUFFER;
            self.io
                .set_word(i * 32, physical as u32 + (POOL + i * BUFFER) as u32);
            self.io.set_word(i * 32 + 4, DONE | LAST);
            self.io.set_word(i * 32 + 16, 1 << 16); // GDM1
        }
        for i in 0..RX_TOTAL {
            self.rx_buffers[i] = POOL + (RING + i) * BUFFER;
            self.io.set_word(
                RX + i * 32,
                physical as u32 + (POOL + (RING + i) * BUFFER + self.rx_headroom) as u32,
            );
            self.io.set_word(RX + i * 32 + 4, ((BUFFER - self.rx_headroom) as u32) << 8);
        }
        self.io.barrier();
        self.io.set_reg(0x6800, physical as u32);
        self.io.set_reg(0x6804, RING as u32);
        self.io.set_reg(0x6808, 0);
        // Disable inherited RSS before publishing a new queue topology.
        rx_offload::disable_rss(&mut self.io);
        for queue in 0..RX_QUEUES {
            let base = 0x6900 + queue * 16;
            self.io.set_reg(base, physical as u32 + (RX + queue * RX_RING * 32) as u32);
            self.io.set_reg(base + 4, if queue < self.receive_queues().min(4) { RX_RING as u32 } else { 0 });
            self.io.set_reg(base + 8, RX_RING as u32 - 1);
        }
        self.io.set_reg(0x6a08, 1 | (((1 << self.receive_queues().min(4)) - 1) << 16));
        self.rx_heads = [0; RX_QUEUES];
        self.software_tail = 0;
        if self.rss { rx_offload::enable_rss(&mut self.io); }
        self.tx = 0;
        *self.outstanding_tx.get_mut() = 0;
        self.rx = 0;
        self.io.barrier();
        self.io.set_reg(CFG, self.io.reg(CFG) | self.io.pdma_enable());
        self.io.start_transmit()?;
        self.io.barrier();
        self.ready = true;
        Ok(())
    }
    /// Inspect ownership without consuming a frame, for IRQ rearm decisions.
    pub fn has_receive(&self) -> bool {
        self.ready && (0..self.receive_queues()).any(|q| self.detached & (1 << q) == 0 && self.io.word(RX + (q * RX_RING + self.rx_heads[q]) * 32 + 4) & DONE != 0)
    }

    /// Reclaim completed TX buffers before checking drain or reserving TX.
    pub fn poll_transmit(&mut self) -> Result<(), Error> {
        let start=tx_clock();let result=self.io.poll_transmit();tx_cost(2,start);
        if let Err(error) = result { self.ready=false; return Err(error); }
        Ok(())
    }
    fn advance_tx(&mut self) {
        *self.outstanding_tx.get_mut() |= 1 << self.tx;
        self.tx = (self.tx + 1) % RING;
    }
    /// All submitted TX descriptors have returned to CPU ownership. This is
    /// DMA completion, not proof that every frame has left the physical MAC.
    pub fn transmit_drained(&self) -> bool {
        if !self.ready { return false; }
        use core::sync::atomic::Ordering::Relaxed;
        let mask = self.outstanding_tx.load(Relaxed);
        if mask == 0 { return true; }
        self.io.barrier();
        let mut pending = mask;
        while pending != 0 {
            let slot = pending.trailing_zeros() as usize;
            if self.io.word(slot * 32 + 4) & DONE == 0 { break; }
            pending &= pending - 1;
        }
        // Only the exclusive producer can publish a slot again. Concurrent
        // observers can safely remove bits for completions they have seen.
        if pending != mask { self.outstanding_tx.fetch_and(!(mask ^ pending), Relaxed); }
        pending == 0
    }

    /// Terminal backend stop. No buffer release or successful-delivery promise.
    pub fn stop_transmit(&mut self, timeout: u64) -> Result<(), Error> {
        self.ready=false;
        self.io.stop_transmit(timeout)
    }

    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.transmit_to(TxPort::Internal, packet)
    }
    pub fn transmit_to(&mut self, port: TxPort, packet: &[u8]) -> Result<(), Error> {
        if !self.ready {
            return Err(Error::NotReady);
        }
        let (fport, min_frame, max_frame, padded_min) = match port {
            TxPort::Internal => (1, 14, 1514, 60),
            TxPort::InternalTagged => (1, 18, 1518, 64),
            TxPort::Wan => (2, 14, 1518, 60),
            TxPort::ExternalTagged => (15, 18, 1522, 64),
        };
        if !(min_frame..=max_frame).contains(&packet.len()) {
            return Err(Error::Length);
        }
        let descriptor = self.tx * 32;
        if self.io.word(descriptor + 4) & DONE == 0 {
            self.poll_transmit()?;
            if self.io.word(descriptor + 4) & DONE == 0 { return Err(Error::Busy); }
        }
        self.io.barrier();
        let length = packet.len().max(padded_min);
        // Restore our trusted pointer and destination on every reuse.
        self.io.set_word(
            descriptor,
            self.io.dma_address() as u32 + self.tx_buffers[self.tx] as u32,
        );
        self.io.set_word(descriptor + 16, fport << 16);
        self.io.set_word(descriptor + 20, 0);
        self.io.set_word(descriptor + 24, 0);
        for i in 0..length {
            self.io.set_byte(
                self.tx_buffers[self.tx] + i,
                packet.get(i).copied().unwrap_or(0),
            );
        }
        let length = self.prepare_tx_offload(descriptor, self.tx_buffers[self.tx], 0, length, port);
        self.io.barrier();
        self.io
            .set_word(descriptor + 4, LAST | ((length as u32) << 8));
        self.io.barrier();
        self.advance_tx();
        self.notify_transmit()?;
        Ok(())
    }
    // Called only while the caller owns both the buffer and TX shadow.
    // Software checksums remain valid on fallback. Never interpret CPU tags as VLANs.
    fn prepare_tx_offload(&mut self, descriptor: usize, buffer: usize, offset: usize, length: usize, port: TxPort) -> usize {
        #[cfg(feature = "tx-offload")]
        if self.io.tx_offload_supported() && matches!(port, TxPort::Internal | TxPort::Wan) {
            let bytes = unsafe { self.io.buffer_mut(buffer) };
            if let Some((length, meta)) = offload::prepare_ordinary(&mut bytes[offset..offset + length], port) {
                self.io.set_word(descriptor + 20, meta.word5);
                self.io.set_word(descriptor + 24, meta.word6);
                offload::record(Some(meta));
                return length;
            }
        }
        #[cfg(feature = "tx-offload")]
        offload::record(None);
        let _ = (descriptor, buffer, offset, port);
        length
    }

    /// Copy and submit an explicitly offloaded packet. TSO input is bounded by
    /// BUFFER; larger contiguous DMA packets use qdma::TxRing::submit_offloaded.
    /// Rejected requests never publish a descriptor or modify the caller's bytes.
    pub fn transmit_offloaded(
        &mut self, port: TxPort, packet: &[u8], options: offload::TxOffload,
    ) -> Result<(), Error> {
        if !self.ready || !self.io.tx_offload_supported() { return Err(Error::NotReady); }
        if packet.len() > BUFFER { return Err(Error::Length); }
        self.stage_tracked(port, packet, Some(options))?;
        self.notify_transmit()
    }

    /// Reserve a completed TX buffer before calling a synchronous producer.
    /// Busy never invokes it, so queued NAT packets can commit state exactly
    /// once. Drop leaves the descriptor CPU-owned. Initialize every output byte;
    /// this method zeroes only Ethernet padding and uses our private pool pointer.
    pub fn transmit_with(
        &mut self,
        produce: impl FnOnce(&mut [u8]) -> RxAction,
    ) -> Result<bool, Error> {
        let mut pending=Notifications::default();
        let result=self.transmit_deferred(produce,&mut pending);
        if pending.tx {self.notify_transmit()?;}
        result
    }
    fn transmit_deferred(&mut self, produce:impl FnOnce(&mut [u8])->RxAction,
        pending:&mut Notifications)->Result<bool,Error> {
        if !self.ready {
            return Err(Error::NotReady);
        }
        let descriptor = self.tx * 32;
        if self.io.word(descriptor + 4) & DONE == 0 {
            self.poll_transmit()?;
            if self.io.word(descriptor + 4) & DONE == 0 { return Err(Error::Busy); }
        }
        self.io.barrier();
        let buffer = self.tx_buffers[self.tx];
        let (port, length) = match produce(unsafe { self.io.buffer_mut(buffer) }) {
            RxAction::Transmit { port, length } => (port, length),
            RxAction::TransmitShifted { .. } | RxAction::TransmitFrom { .. } => return Err(Error::Length),
            RxAction::Drop | RxAction::Defer => return Ok(false),
        };
        let (fport, minimum, maximum, padded) = match port {
            TxPort::Internal => (1, 14, 1514, 60),
            TxPort::InternalTagged => (1, 18, 1518, 64),
            TxPort::Wan => (2, 14, 1518, 60),
            TxPort::ExternalTagged => (15, 18, 1522, 64),
        };
        if !(minimum..=maximum).contains(&length) {
            return Err(Error::Length);
        }
        let wire_length = length.max(padded);
        unsafe {
            self.io.buffer_mut(buffer)[length..wire_length].fill(0);
        }
        self.io
            .set_word(descriptor, self.io.dma_address() as u32 + buffer as u32);
        self.io.set_word(descriptor + 16, fport << 16);
        self.io.set_word(descriptor + 20, 0);
        self.io.set_word(descriptor + 24, 0);
        let wire_length = self.prepare_tx_offload(descriptor, buffer, 0, wire_length, port);
        self.io.barrier();
        self.io
            .set_word(descriptor + 4, LAST | ((wire_length as u32) << 8));
        self.io.barrier();
        self.advance_tx();
        pending.tx=true;
        Ok(true)
    }

    /// Discard a CPU-owned head frame only when a read-only predicate accepts
    /// it. A rejected frame stays at the head, unchanged, for normal handling.
    /// No TX descriptor is inspected or reserved. Malformed RX is recycled
    /// using the same bounds and private buffer mapping as normal receive.
    pub fn discard_receive_if(
        &mut self,
        discard: impl FnOnce(Received, &[u8]) -> bool,
    ) -> Result<Option<Received>, Error> {
        if !self.ready { return Err(Error::NotReady); }
        self.select_receive();
        let descriptor = RX + self.rx * 32;
        let status = self.io.word(descriptor + 4);
        if status & DONE == 0 { return Ok(None); }
        self.io.barrier();
        let length = ((status >> 8) & 0xffff) as usize;
        if !(14..=BUFFER - self.rx_headroom).contains(&length) || status & LAST == 0 {
            self.recycle_receive();
            return Err(Error::Malformed);
        }
        let mut received = Received::decode(length, self.io.word(descriptor + 16));
        received.offload = rx_offload::Metadata::decode(self.io.word(descriptor + 8), self.io.word(descriptor + 24), (self.rx / RX_RING) as u8);
        let buffer = self.rx_buffers[self.rx];
        if !discard(received, unsafe { &self.io.buffer_mut(buffer)[self.rx_headroom..self.rx_headroom + length] }) {
            return Ok(None);
        }
        self.recycle_receive();
        Ok(Some(received))
    }

    /// Process one received frame in its DMA buffer, without copying its
    /// payload. TX backpressure returns Busy *before* invoking the callback:
    /// callers may update TTL/conntrack exactly once. A full TX ring blocks
    /// this path (including Drop); use completion IRQs, not a busy poll.
    ///
    /// The callback may append at most four bytes for an MxL outer tag and
    /// must initialize every byte it transmits. Ethernet padding is zeroed
    /// here. Invalid output is dropped, never retried after mutation.
    /// Defer must leave packet bytes unchanged and returns Ok(None) with RX
    /// still ready; use has_receive() to distinguish it from an empty ring.
    /// Stop the fast-path loop on defer and hand ownership to the slow path;
    /// repeatedly retrying the same head would busy-poll.
    pub fn receive_in_place(
        &mut self,
        process: impl FnOnce(Received, &mut [u8]) -> RxAction,
    ) -> Result<Option<Processed>, Error> {
        let mut pending = Notifications::default();
        let result = self.receive_deferred(process, &mut pending, false);
        self.publish_notifications(&mut pending);
        result
    }

    /// Coalesce doorbells for up to half a ring without changing per-packet
    /// ownership barriers or the pre-mutation TX reservation contract.
    pub fn receive_batch(&mut self) -> ReceiveBatch<'_, I> {
        ReceiveBatch { nic: self, pending: Notifications::default(), count: 0 }
    }
    /// A synchronous producer burst; drop before any wait or scheduler yield.
    pub fn transmit_batch(&mut self) -> ReceiveBatch<'_,I> { self.receive_batch() }

    fn notify_transmit(&mut self) -> Result<(), Error> {
        if let Err(error)=self.io.notify_transmit(self.tx) {self.ready=false;return Err(error);}
        Ok(())
    }

    fn publish_notifications(&mut self, pending: &mut Notifications) {
        if !pending.tx && pending.rx.iter().all(Option::is_none) { return; }
        // Each pending descriptor already has its post-publication barrier in
        // receive_deferred/recycle_deferred. No DMA write follows that barrier;
        // PDMA can notify directly; QDMA publishes its separate descriptors
        // and performs its own barriers before notifying that engine.
        if pending.tx { self.notify_transmit().expect("TX publication failed; retain DMA storage"); }
        for (queue, rx) in pending.rx.iter().enumerate() { if queue < 4 { if let Some(rx) = rx { self.io.set_reg(0x6908 + queue * 16, *rx as u32); } } }
        *pending = Notifications::default();
    }

    fn receive_deferred(
        &mut self, process: impl FnOnce(Received, &mut [u8]) -> RxAction,
        pending: &mut Notifications, expose_headroom: bool,
    ) -> Result<Option<Processed>, Error> {
        if !self.ready {
            return Err(Error::NotReady);
        }
        self.select_receive();
        let descriptor = RX + self.rx * 32;
        let status = self.io.word(descriptor + 4);
        if status & DONE == 0 {
            return Ok(None);
        }
        self.io.barrier();
        let length = ((status >> 8) & 0xffff) as usize;
        if !(14..=BUFFER - self.rx_headroom).contains(&length) || status & LAST == 0 {
            self.recycle_deferred(pending);
            return Err(Error::Malformed);
        }
        let tx_descriptor = self.tx * 32;
        if self.io.word(tx_descriptor + 4) & DONE == 0 {
            self.poll_transmit()?;
            if self.io.word(tx_descriptor + 4) & DONE == 0 { return Err(Error::Busy); }
        }
        self.io.barrier();
        let mut received = Received::decode(length, self.io.word(descriptor + 16));
        received.offload = rx_offload::Metadata::decode(self.io.word(descriptor + 8), self.io.word(descriptor + 24), (self.rx / RX_RING) as u8);
        let buffer = self.rx_buffers[self.rx];
        // Both descriptors are CPU-owned; the mapping comes only from our
        // private permutation, never from device-written descriptor pointers.
        let view_offset = if expose_headroom {0} else {self.rx_headroom};
        let action = process(received, unsafe { &mut self.io.buffer_mut(buffer)[view_offset..] });
        let explicit_offset = match action {
            RxAction::TransmitFrom { offset, .. } => {
                if !expose_headroom || offset & 3 != 0 || offset > self.rx_headroom + length - 14 {
                    self.recycle_deferred(pending); return Err(Error::Length);
                }
                offset
            },
            RxAction::TransmitShifted { .. } => self.rx_headroom + 4,
            _ => self.rx_headroom,
        };
        let transmitted = match action {
            RxAction::Defer => return Ok(None),
            RxAction::Drop => false,
            RxAction::Transmit { port, length: output }
            | RxAction::TransmitShifted { port, length: output }
            | RxAction::TransmitFrom { port, length: output, .. } => {
                let offset = explicit_offset;
                let (fport, minimum, maximum, padded) = match port {
                    TxPort::Internal => (1, 14, 1514, 60),
                    TxPort::InternalTagged => (1, 18, 1518, 64),
                TxPort::InternalTagged => (1, 18, 1518, 64),
            TxPort::InternalTagged => (1, 18, 1518, 64),
                    TxPort::Wan => (2, 14, 1518, 60),
                    TxPort::ExternalTagged => (15, 18, 1522, 64),
                };
                if !(minimum..=maximum).contains(&output) || output + offset > length.saturating_add(4 + self.rx_headroom) {
                    self.recycle_deferred(pending);
                    return Err(Error::Length);
                }
                let wire_length = output.max(padded);
                if wire_length + offset > BUFFER {
                    self.recycle_deferred(pending);
                    return Err(Error::Length);
                }
                unsafe {
                    self.io.buffer_mut(buffer)[offset + output..offset + wire_length].fill(0);
                }
                let replacement = self.tx_buffers[self.tx];
                self.tx_buffers[self.tx] = buffer;
                self.rx_buffers[self.rx] = replacement;
                self.io
                    .set_word(tx_descriptor, self.io.dma_address() as u32 + buffer as u32 + offset as u32);
                self.io.set_word(tx_descriptor + 16, fport << 16);
                self.io.set_word(tx_descriptor + 20, 0);
                self.io.set_word(tx_descriptor + 24, 0);
                let wire_length = self.prepare_tx_offload(tx_descriptor, buffer, offset, wire_length, port);
                self.io.barrier();
                self.io
                    .set_word(tx_descriptor + 4, LAST | ((wire_length as u32) << 8));
                self.io.barrier();
                self.advance_tx();
                pending.tx = true;
                true
            }
        };
        self.recycle_deferred(pending);
        Ok(Some(Processed {
            received,
            transmitted,
        }))
    }

    fn recycle_receive(&mut self) {
        let mut pending = Notifications::default();
        self.recycle_deferred(&mut pending);
        self.publish_notifications(&mut pending);
    }

    fn recycle_deferred(&mut self, pending: &mut Notifications) {
        let descriptor = RX + self.rx * 32;
        self.io.set_word(
            descriptor,
            self.io.dma_address() as u32 + (self.rx_buffers[self.rx] + self.rx_headroom) as u32,
        );
        // Clear completion-only facts before returning ownership. A later
        // short/error completion must never inherit a previous checksum proof.
        for offset in (8..32).step_by(4) { self.io.set_word(descriptor + offset, 0); }
        self.io.barrier();
        self.io.set_word(descriptor + 4, ((BUFFER - self.rx_headroom) as u32) << 8);
        self.io.barrier();
        let queue = self.rx / RX_RING;
        pending.rx[queue] = Some(self.rx % RX_RING);
        self.rx_heads[queue] = (self.rx % RX_RING + 1) % RX_RING;
        if queue < 4 { rx_offload::record_queue(queue); }
        let next = (queue + 1) % self.receive_queues();
        self.rx = next * RX_RING + self.rx_heads[next];
    }

    /// Copies a single completed frame, then returns ownership to DMA even
    /// for malformed lengths. Never follows a device-written buffer pointer.
    pub fn receive(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error> {
        self.receive_from(out)
            .map(|packet| packet.map(|p| p.length))
    }
    /// Capture RXD5 source before recycling; callers must demultiplex GDMA
    /// origins before interpreting VLAN tags as switch-port identities.
    pub fn receive_from(&mut self, out: &mut [u8]) -> Result<Option<Received>, Error> {
        if !self.ready {
            return Err(Error::NotReady);
        }
        self.select_receive();
        let descriptor = RX + self.rx * 32;
        let status = self.io.word(descriptor + 4);
        if status & DONE == 0 {
            return Ok(None);
        }
        self.io.barrier();
        let length = ((status >> 8) & 0xffff) as usize;
        let mut received = Received::decode(length, self.io.word(descriptor + 16));
        received.offload = rx_offload::Metadata::decode(self.io.word(descriptor + 8), self.io.word(descriptor + 24), (self.rx / RX_RING) as u8);
        let valid = (14..=BUFFER - self.rx_headroom).contains(&length) && length <= out.len() && status & LAST != 0;
        if valid {
            for (i, b) in out[..length].iter_mut().enumerate() {
                *b = self.io.byte(self.rx_buffers[self.rx] + self.rx_headroom + i);
            }
        }
        self.recycle_receive();
        if valid {
            Ok(Some(received))
        } else {
            Err(Error::Malformed)
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub struct Mmio {
    #[cfg(feature = "qdma-test")]
    qdma: Option<qdma::engine::Engine>,
    arena: usize,
    clock: fn() -> u64,
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Mmio {
    /// # Safety
    /// Sole FE owner, mapped Device FE aperture; exclusively owned permanent
    /// Normal-NC arena of at least ARENA_SIZE bytes, no cached aliases. Arena
    /// remains reserved even if this owner is dropped or a task faults.
    pub unsafe fn new(arena: usize, clock: fn() -> u64) -> Self {
        Self { arena, clock, #[cfg(feature = "qdma-test")] qdma: None }
    }
    /// # Safety
    /// The prepared ring owns permanent NC descriptors at `base`, and its
    /// scratch allocation remains reserved. No other QDMA owner may run.
    #[cfg(feature = "qdma-test")]
    pub unsafe fn attach_qdma(&mut self, base: usize, ring: qdma::TxRing<34>) {
        assert!(self.qdma.is_none());
        self.qdma=Some(unsafe { qdma::engine::Engine::new(base,ring) });
    }

}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Io for Mmio {

    #[cfg(feature = "qdma-test")]
    fn tx_offload_supported(&self) -> bool { self.qdma.is_some() }
    #[cfg(feature = "qdma-test")]
    fn pdma_enable(&self) -> u32 { if self.qdma.is_some() {4} else {0x45} }
    #[cfg(feature = "qdma-test")]
    fn prepare_transmit(&mut self) -> Result<(), Error> {
        if self.qdma.as_ref().is_some_and(|q|q.started()) {Err(Error::Busy)} else {Ok(())}
    }
    #[cfg(feature = "qdma-test")]
    fn stop_transmit(&mut self, timeout:u64) -> Result<(),Error> {
        if let Some(q)=self.qdma.as_mut() {q.stop(timeout,self.clock)} else {Err(Error::NotReady)}
    }
    #[cfg(feature = "qdma-test")]
    fn start_transmit(&mut self) -> Result<(), Error> {
        if let Some(q)=self.qdma.as_mut() {q.start()} else {Ok(())}
    }
    #[cfg(feature = "qdma-test")]
    fn poll_transmit(&mut self) -> Result<(), Error> {
        let Some(mut q)=self.qdma.take() else {return Ok(());};
        let result=q.poll(self);self.qdma=Some(q);result
    }
    #[cfg(feature = "qdma-test")]
    fn notify_transmit(&mut self,end:usize) -> Result<(), Error> {
        let Some(mut q)=self.qdma.take() else {self.set_reg(0x6808,end as u32);return Ok(());};
        let result=unsafe {q.notify(self,end)};self.qdma=Some(q);result
    }
    fn dma_address(&self) -> u64 {
        self.arena as u64
    }
    fn reg(&self, o: usize) -> u32 {
        assert!(o < 0x14000 && o & 3 == 0);
        unsafe { core::ptr::read_volatile((0x15100000 + o) as *const u32) }
    }
    fn set_reg(&mut self, o: usize, v: u32) {
        assert!(o < 0x14000 && o & 3 == 0);
        unsafe { core::ptr::write_volatile((0x15100000 + o) as *mut u32, v) }
    }
    fn word(&self, o: usize) -> u32 {
        assert!(o < ARENA_SIZE && o & 3 == 0);
        unsafe { core::ptr::read_volatile((self.arena + o) as *const u32) }
    }
    fn set_word(&mut self, o: usize, v: u32) {
        assert!(o < ARENA_SIZE && o & 3 == 0);
        unsafe { core::ptr::write_volatile((self.arena + o) as *mut u32, v) }
    }
    fn byte(&self, o: usize) -> u8 {
        assert!(o < ARENA_SIZE);
        unsafe { core::ptr::read_volatile((self.arena + o) as *const u8) }
    }
    fn set_byte(&mut self, o: usize, v: u8) {
        assert!(o < ARENA_SIZE);
        unsafe { core::ptr::write_volatile((self.arena + o) as *mut u8, v) }
    }
    unsafe fn buffer_mut(&mut self, offset: usize) -> &mut [u8] {
        assert!((POOL..=ARENA_SIZE - BUFFER).contains(&offset) && (offset - POOL) % BUFFER == 0);
        unsafe { core::slice::from_raw_parts_mut((self.arena + offset) as *mut u8, BUFFER) }
    }
    unsafe fn large_tx_mut(&mut self,slot:usize)->&mut [u8] {
        assert!(cfg!(feature="tx-offload") && slot<RING);
        unsafe {core::slice::from_raw_parts_mut((self.arena+LARGE_POOL+slot*TX_LARGE) as *mut u8,TX_LARGE)}
    }
    fn barrier(&self) {
        unsafe {
            core::arch::asm!("dsb sy", options(nostack));
        }
    }
    fn now(&self) -> u64 {
        (self.clock)()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    struct Mock {
        physical: u64,
        offload: bool,
        regs: std::vec::Vec<u32>,
        dma: std::vec::Vec<u8>,
        ticks: Cell<u64>,
        doorbells: std::vec::Vec<(usize, u32)>,
        dma_dirty: Cell<bool>,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                physical: 0x40800000,
                offload: false,
                regs: std::vec![0; 0x14000 / 4],
                dma: std::vec![0; ARENA_SIZE],
                ticks: Cell::new(0),
                doorbells: std::vec::Vec::new(),
                dma_dirty: Cell::new(false),
            }
        }
    }
    impl Io for Mock {
        fn tx_offload_supported(&self) -> bool { self.offload }
        fn dma_address(&self) -> u64 {
            self.physical
        }
        fn reg(&self, o: usize) -> u32 {
            self.regs[o / 4]
        }
        fn set_reg(&mut self, o: usize, v: u32) {
            if matches!(o, 0x6808 | 0x6908 | 0x6918 | 0x6928 | 0x6938) {
                if self.regs[CFG / 4] & 0x45 == 0x45 {
                    assert!(!self.dma_dirty.get(), "doorbell before DMA publication barrier");
                }
                self.doorbells.push((o,v));
            }
            self.regs[o / 4] = v;
        }
        fn word(&self, o: usize) -> u32 {
            u32::from_le_bytes(self.dma[o..o + 4].try_into().unwrap())
        }
        fn set_word(&mut self, o: usize, v: u32) {
            self.dma_dirty.set(true);
            self.dma[o..o + 4].copy_from_slice(&v.to_le_bytes());
            // Model DMA observing each ownership publication, not just the
            // final ring state: no two live descriptors may share a buffer.
            if self.regs[CFG / 4] & 0x45 == 0x45 && o < POOL && o % 32 == 4 && v & DONE == 0 {
                let mut owned = std::collections::BTreeSet::new();
                for descriptor in (0..(RING + RX_TOTAL) * 32).step_by(32) {
                    if self.word(descriptor + 4) & DONE == 0 {
                        let pointer = self.word(descriptor);
                        assert!(
                            owned.insert(pointer.wrapping_sub(self.physical as u32) / BUFFER as u32),
                            "DMA buffer aliased at descriptor {descriptor:#x}"
                        );
                    }
                }
            }
        }
        fn byte(&self, o: usize) -> u8 {
            self.dma[o]
        }
        fn set_byte(&mut self, o: usize, v: u8) {
            self.dma[o] = v;
        }
        unsafe fn buffer_mut(&mut self, offset: usize) -> &mut [u8] {
            &mut self.dma[offset..offset + BUFFER]
        }
        unsafe fn large_tx_mut(&mut self,slot:usize)->&mut [u8]{let at=LARGE_POOL+slot*TX_LARGE;&mut self.dma[at..at+TX_LARGE]}
        fn barrier(&self) { self.dma_dirty.set(false); }
        fn now(&self) -> u64 {
            let t = self.ticks.get();
            self.ticks.set(t + 1);
            t
        }
    }
    #[cfg(feature = "tx-offload")]
    #[test]
    #[cfg(feature="rx-multicore")]
    fn remote_backpressure_and_corrupt_descriptor_never_cross_queue_ownership() {
        let mut n=Nic::new(Mock::new()).with_rss();n.initialize(100).unwrap();
        let mut remote=n.detach_rx(2).unwrap();let d=RX+2*RX_RING*32;
        n.io.set_word(d,0xffff_ffff);n.io.set_word(d+8,4);n.io.set_word(d+4,DONE|LAST|(60<<8));
        let mut packet=None;
        assert_eq!(remote.drain(&mut n.io, 1, |p,_|{packet=Some(p);false}), 0);
        assert_ne!(n.io.word(d+4)&DONE,0);assert_eq!(n.io.word(d+8),4);
        let packet=packet.unwrap();let bytes=[7;60];
        for _ in 0..RX_RING {assert!(n.inject_received(packet,&bytes).unwrap());}
        assert!(!n.inject_received(packet,&bytes).unwrap());
        let mut out=[0;60];for _ in 0..RX_RING {assert!(n.receive_from(&mut out).unwrap().is_some());assert_eq!(out,bytes);}
        assert!(!n.has_receive());
        assert_eq!(remote.drain(&mut n.io, 1, |_,_|true), 1);
        assert_eq!(n.io.word(d),n.io.physical as u32+n.rx_buffers[2*RX_RING] as u32);
        assert_eq!(n.io.word(d+8),0);
        assert!(n.inject_received(packet,&bytes).unwrap());
    }

    #[test]
    fn external_rx_keeps_buffer_on_backpressure_without_fake_rx_dma() {
        let mut n=Nic::new_with_rx_headroom(Mock::new());n.initialize(100).unwrap();
        let packet=Received::decode(60,2<<26);let mut frame=[7u8;68];
        let snapshot=frame;
        n.io.set_word(n.tx*32+4,0);
        let busy=n.receive_batch().receive_external(packet,8,&mut frame,|_,_,_|panic!("must reserve before invoking callback"));
        assert_eq!(busy,Err(Error::Busy));assert_eq!(frame,snapshot);
        n.io.set_word(n.tx*32+4,DONE);
        assert_eq!(n.receive_batch().receive_external(packet,8,&mut frame,|_,_,_|RxAction::Defer),Ok(None));
        assert_eq!(frame,snapshot);assert!(!n.has_receive());
        let result=n.receive_batch().receive_external(packet,8,&mut frame,|p,offset,b|{
            assert_eq!(p,packet);assert_eq!(offset,8);b[offset]=9;
            RxAction::TransmitFrom{port:TxPort::Wan,length:60,offset}
        }).unwrap().unwrap();
        assert!(result.transmitted);assert!(!n.has_receive());
        assert_eq!(n.io.dma[n.tx_buffers[0]],9);
        assert_eq!(&n.io.dma[n.tx_buffers[0]+1..n.tx_buffers[0]+60],&snapshot[9..]);
    }

    #[cfg(feature = "rx-multicore")]
    #[test]
    fn detached_batch_publishes_only_the_accepted_prefix() {
        let mut nic = Nic::new_with_rx_headroom(Mock::new()).with_rss();
        nic.initialize(100).unwrap();
        let mut queue = nic.detach_rx(1).unwrap();
        let base = RX + RX_RING * 32;
        for slot in 0..5 {
            let size = if slot == 1 { 1 } else { 60 };
            nic.io.set_word(base + slot * 32 + 4, DONE | LAST | (size << 8));
        }
        nic.io.doorbells.clear();
        let mut offered = 0;
        assert_eq!(queue.drain(&mut nic.io, 32, |_, _| {
            offered += 1;
            offered < 3
        }), 3);
        assert_eq!(nic.io.doorbells, [(0x6918, 2)]);
        assert_ne!(nic.io.word(base + 3 * 32 + 4) & DONE, 0);
        assert_eq!(queue.drain(&mut nic.io, 0, |_, _| panic!()), 0);
        assert_eq!(queue.drain(&mut nic.io, 1, |_, _| true), 1);
        assert_eq!(queue.drain(&mut nic.io, 32, |_, _| true), 1);
        assert_eq!(queue.drain(&mut nic.io, 32, |_, _| panic!()), 0);
        assert_eq!(nic.io.doorbells, [(0x6918, 2), (0x6918, 3), (0x6918, 4)]);
    }

    #[test]
    #[cfg(feature="rx-multicore")]
    fn detached_consumers_and_native_injection_keep_disjoint_ownership() {
        let mut n=Nic::new_with_rx_headroom(Mock::new()).with_rss();n.initialize(100).unwrap();
        let mut queues:[rx_queue::Queue;3]=core::array::from_fn(|i|n.detach_rx(i+1).unwrap());
        assert!(n.detach_rx(1).is_err());assert_eq!(n.initialize(100),Err(Error::Busy));
        for round in 0..RX_RING*3 {
            for (q,queue) in queues.iter_mut().enumerate() {
                let slot=(q+1)*RX_RING+round%RX_RING;let d=RX+slot*32;
                let buffer=n.rx_buffers[slot];n.io.dma[buffer+4..buffer+64].fill((q+round) as u8);
                n.io.set_word(d+16,2<<26);n.io.set_word(d+8,4);n.io.set_word(d+4,DONE|LAST|(60<<8));
                assert!(!n.has_receive(),"CPU0 must not consume a detached descriptor");
                assert_eq!(queue.drain(&mut n.io, 32, |_,_|false), 0);
                let mut saved=None;
                assert_eq!(queue.drain(&mut n.io, 32, |packet,bytes| {saved=Some((packet,bytes.to_vec()));true}), 1);
                let (packet,bytes)=saved.unwrap();assert_eq!(packet.offload.queue(),(q+1) as u8);
                assert!(n.inject_received(packet,&bytes).unwrap());assert!(n.has_receive());
                n.io.set_word(n.tx*32+4,DONE);
                n.receive_batch().receive_with_headroom(|p,offset,pool| {
                    assert_eq!(p.source_port,2);assert!(p.offload.l4_valid_bit());
                    assert_eq!(&pool[offset..offset+60],&bytes);
                    RxAction::TransmitFrom {port:TxPort::Wan,length:60,offset}
                }).unwrap();
                assert!(!n.has_receive());
                assert_eq!(n.io.word(d+8),0);
            }
        }
        assert_eq!(n.io.reg(0x6944),0,"synthetic ring must not be DMA-enabled");
        assert_eq!(n.io.reg(0x6948),(RX_RING-1) as u32,"no hardware doorbell for software exceptions");
    }

    #[test]
    #[cfg(feature = "rx-rss")]
    fn rss_wrap_preserves_buffer_ownership_and_queue_local_doorbells() {
        let mut n = Nic::new_with_rx_headroom(Mock::new()).with_rss();
        n.initialize(100).unwrap();
        for round in 0..RX_RING * 3 {
            for q in 0..RX_QUEUES.min(4) {
                let slot = q * RX_RING + round % RX_RING;
                let descriptor = RX + slot * 32;
                n.io.set_word(descriptor + 8, 4);
                n.io.set_word(descriptor + 4, DONE | LAST | (60 << 8));
            }
            for q in 0..RX_QUEUES.min(4) {
                n.io.set_word(n.tx * 32 + 4, DONE);
                let mut batch = n.receive_batch();
                assert!(batch.receive_with_headroom(|received,offset,_| {
                    assert_eq!(usize::from(received.offload.queue()),q);
                    RxAction::TransmitFrom {port:TxPort::Wan,length:60,offset}
                }).unwrap().unwrap().transmitted);
            }
            for q in 0..RX_QUEUES.min(4) { assert_eq!(n.io.reg(0x6908 + q * 16), (round % RX_RING) as u32); }
            assert!(!n.has_receive());
        }
        let mut buffers = std::vec::Vec::from(n.tx_buffers);
        buffers.extend(n.rx_buffers); buffers.sort_unstable(); buffers.dedup();
        assert_eq!(buffers.len(), RING + RX_TOTAL);
    }

    #[test]
    #[cfg(feature = "rx-rss")]
    fn rss_preserves_deferred_heads_and_publishes_each_queue() {
        let mut n = Nic::new(Mock::new()).with_rss();
        n.initialize(100).unwrap();
        assert_eq!(n.io.reg(0x7000) & 5, 1);
        assert_eq!(n.io.reg(0x7050), 0xe4e4e4e4);
        for q in 0..4 {
            let d = RX + q * RX_RING * 32;
            n.io.set_word(d + 8, 4);
            n.io.set_word(d + 24, 0xdeadbeef);
            n.io.set_word(d + 4, DONE | LAST | (60 << 8));
        }
        let mut seen = std::vec::Vec::new();
        for q in 0..4 {
            assert!(n.has_receive());
            assert_eq!(n.receive_in_place(|packet, _| {
                assert_eq!(packet.offload.queue(), q);
                assert!(packet.offload.l4_valid_bit());
                RxAction::Defer
            }), Ok(None));
            let d = RX + usize::from(q) * RX_RING * 32;
            assert_ne!(n.io.word(d + 4) & DONE, 0);
            n.receive_batch().receive_with_headroom(|packet,_,_| {
                seen.push(packet.offload.queue()); RxAction::Drop
            }).unwrap();
            assert_eq!(n.io.reg(0x6908 + usize::from(q) * 16), 0);
            assert_eq!(n.io.word(d + 8), 0);
            assert_eq!(n.io.word(d + 24), 0);
        }
        assert_eq!(seen, [0,1,2,3]);
        assert!(!n.has_receive());
        // One busy ring cannot starve an already completed different ring.
        for q in [1,3] {
            n.io.set_word(RX + (q * RX_RING + 1) * 32 + 4, DONE | LAST | (60 << 8));
        }
        let mut out = [0; 60];
        assert_eq!(n.receive_from(&mut out).unwrap().unwrap().offload.queue(), 1);
        assert_eq!(n.receive_from(&mut out).unwrap().unwrap().offload.queue(), 3);
    }

    #[test]
    fn tracked_switch_tag_short_frames_have_complete_wire_padding() {
        for port in [TxPort::InternalTagged,TxPort::ExternalTagged] {
            let mut n=Nic::new(Mock::new());n.initialize(100).unwrap();
            let r=n.transmit_batch().submit_tracked(port,&[0x55;58],None).unwrap();
            assert_eq!((n.io.word(4)>>8)&0xffff,64);
            assert_eq!(&n.io.dma[n.tx_buffers[0]+58..n.tx_buffers[0]+64],&[0;6]);
            assert!(!n.tx_completed(r));
        }
    }
    #[test]
    fn tracked_submission_is_not_completion_and_receipts_survive_wrap() {
        let mut n=Nic::new(Mock::new());n.initialize(100).unwrap();
        let packet=[0x5a;60];let mut receipts=std::vec::Vec::new();
        for _ in 0..RING {let receipt=n.transmit_batch().submit_tracked(TxPort::Wan,&packet,None).unwrap();assert!(!n.tx_completed(receipt));receipts.push(receipt);}
        assert_eq!(n.transmit_batch().submit_tracked(TxPort::Wan,&packet,None),Err(Error::Busy));
        for r in &receipts {assert!(!n.tx_completed(*r));}
        // Device release, not submission or a CPU queue pop, returns ownership.
        n.io.set_word(4,n.io.word(4)|DONE);assert!(n.tx_completed(receipts[0]));
        let newer=n.transmit_batch().submit_tracked(TxPort::Wan,&packet,None).unwrap();
        assert!(n.tx_completed(receipts[0]));assert!(!n.tx_completed(newer));
        assert!(!n.tx_completed(receipts[1]));
    }
    #[test]
    #[cfg(feature="tx-offload")]
    fn large_tso_uses_disjoint_pool_and_preserves_original_until_completion() {
        for v6 in [false,true] {
            let mut n=Nic::new(Mock::new());n.initialize(100).unwrap();n.io.offload=true;
            let original=offload::tests::tcp(v6,16000);let packet=original.clone();
            let rx=n.rx_buffers;let tx=n.tx_buffers;
            let r=n.transmit_batch().submit_tracked(TxPort::Wan,&packet,Some(offload::TxOffload{checksum:true,vlan:None,tso_mss:Some(1400)})).unwrap();
            assert_eq!(n.io.word(0),n.io.physical as u32+LARGE_POOL as u32);
            assert_eq!(n.io.word(20),0xf0000000);assert!(!n.tx_completed(r));
            assert_eq!(packet,original);assert_eq!(n.rx_buffers,rx);assert_eq!(n.tx_buffers,tx);
            assert!(ARENA_SIZE<=2*1024*1024);
            n.io.set_word(4,n.io.word(4)|DONE);assert!(n.tx_completed(r));
        }
    }
    #[test]
    #[cfg(feature="tx-offload")]
    fn ipv6_tso_page_is_inside_each_owned_slot() {
        let mut n=Nic::new(Mock::new());
        n.io.physical+=64;
        n.initialize(100).unwrap();
        n.io.offload=true;
        let packet=offload::tests::tcp(true, IPV6_TSO_WINDOW-74);
        let options=offload::TxOffload{checksum:true,vlan:None,tso_mss:Some(1440)};
        for slot in 0..RING {
            n.transmit_batch().submit_tracked(TxPort::Wan,&packet,Some(options)).unwrap();
            let addr=n.io.word(slot*32) as usize;
            let offset=addr-n.io.physical as usize;
            let base=LARGE_POOL+slot*TX_LARGE;
            assert_eq!(addr % IPV6_TSO_WINDOW,0);
            assert!(offset>=base && offset+packet.len()<=base+TX_LARGE);
            assert_eq!(&n.io.dma[offset+70..offset+72],&1440u16.to_be_bytes());
            assert_eq!(&n.io.dma[offset+72..offset+packet.len()],&packet[72..]);
        }
    }
    #[test]
    fn receive_forwarding_offloads_vlan_without_losing_buffer_ownership() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        n.io.offload = true;
        let plain = offload::tests::tcp(false, 20);
        let mut tagged = plain[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0, 0xb0, 100]);
        tagged.extend_from_slice(&plain[12..]);
        let buffer = n.rx_buffers[0];
        let replacement = n.tx_buffers[0];
        n.io.dma[buffer..buffer + tagged.len()].copy_from_slice(&tagged);
        n.io.set_word(RX + 4, DONE | LAST | ((tagged.len() as u32) << 8));
        assert!(n.receive_in_place(|_, _| RxAction::Transmit {
            port: TxPort::Wan, length: tagged.len(),
        }).unwrap().unwrap().transmitted);
        assert_eq!(n.tx_buffers[0], buffer);
        assert_eq!(n.rx_buffers[0], replacement);
        assert_eq!(n.io.word(20), 0x70000000);
        assert_eq!(n.io.word(24), 0x1b064);
        assert_eq!(n.io.word(4), LAST | ((plain.len() as u32) << 8));
        assert_eq!(&n.io.dma[buffer..buffer + plain.len()], &plain);
    }

    #[test]
    fn explicit_offload_requires_backend_and_clears_on_plain_reuse() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        let packet = offload::tests::tcp(false, 1800);
        let options = offload::TxOffload { checksum: true, vlan: Some(100), tso_mss: Some(1000) };
        assert_eq!(n.transmit_offloaded(TxPort::Wan, &packet, options), Err(Error::NotReady));
        n.io.offload = true;
        n.transmit_offloaded(TxPort::Wan, &packet, options).unwrap();
        assert_eq!(n.io.word(20), 0xf0000000);
        assert_eq!(n.io.word(24), 0x10064);
        let buffer = n.tx_buffers[0];
        assert_eq!(&n.io.dma[buffer + 50..buffer + 52], &1000u16.to_be_bytes());
        for _ in 1..RING { n.transmit(&[0; 60]).unwrap(); }
        n.io.set_word(4, DONE);
        n.transmit(&[0; 60]).unwrap();
        assert_eq!(n.io.word(20), 0);
        assert_eq!(n.io.word(24), 0);
    }

    #[cfg(feature = "tx-offload")]
    #[test]
    fn ordinary_tx_uses_offload_only_on_capable_backend() {
        for capable in [false, true] {
            let mut n = Nic::new(Mock::new());
            n.initialize(100).unwrap();
            n.io.offload = capable;
            let packet = offload::tests::tcp(false, 20);
            n.transmit_to(TxPort::Wan, &packet).unwrap();
            assert_eq!(n.io.word(20), if capable { 0x70000000 } else { 0 });
            n.transmit_with(|bytes| {
                bytes[..packet.len()].copy_from_slice(&packet);
                RxAction::Transmit { port: TxPort::Wan, length: packet.len() }
            }).unwrap();
            assert_eq!(n.io.word(32 + 20), if capable { 0x70000000 } else { 0 });
        }
    }

    #[test]
    fn producer_batch_publishes_half_rings_and_partial_work() {
        let mut n=Nic::new(Mock::new());n.initialize(100).unwrap();
        for lap in 0..3 {
            for slot in 0..RING {n.io.set_word(slot*32+4,DONE);}
            n.io.doorbells.clear();
            {
                let mut batch=n.transmit_batch();
                for slot in 0..RING {
                    assert_eq!(batch.transmit_with(|bytes| {
                        bytes[..60].fill((lap*RING+slot) as u8);
                        RxAction::Transmit {port:TxPort::Wan,length:60}
                    }),Ok(true));
                    assert_eq!(batch.nic.io.doorbells.len(),(slot+1)/(RING/2));
                }
            }
            assert_eq!(n.io.doorbells,[(0x6808,16),(0x6808,0)]);
        }
    }
    #[test]
    fn producer_batch_flushes_on_drop_defer_invalid_and_busy() {
        for stop in 0..4 {
            let mut n=Nic::new(Mock::new());n.initialize(100).unwrap();n.io.doorbells.clear();
            {
                let mut batch=n.transmit_batch();
                assert_eq!(batch.transmit_with(|b| {b[..60].fill(9);RxAction::Transmit {port:TxPort::Wan,length:60}}),Ok(true));
                assert!(batch.nic.io.doorbells.is_empty());
                match stop {
                    0=>{},
                    1=>assert_eq!(batch.transmit_with(|_|RxAction::Defer),Ok(false)),
                    2=>assert_eq!(batch.transmit_with(|_|RxAction::Transmit {port:TxPort::Wan,length:0}),Err(Error::Length)),
                    _=>{batch.nic.io.dma[36..40].copy_from_slice(&0u32.to_le_bytes());assert_eq!(batch.transmit_with(|_|panic!("busy producer")),Err(Error::Busy));}
                }
            }
            assert_eq!(n.io.doorbells,[(0x6808,1)]);
            assert_eq!(n.tx,1);
        }
    }
    #[test]
    fn receive_batch_coalesces_notifications_across_wrap_without_aliasing() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        for lap in 0..3 * RX_RING / RING {
            for slot in 0..RING {
                n.io.set_word(slot * 32 + 4, DONE);
                n.io.set_word(RX + ((lap * RING + slot) % RX_RING) * 32 + 4, DONE | LAST | (60 << 8));
                let buffer = n.rx_buffers[(lap * RING + slot) % RX_RING];
                unsafe { n.io.buffer_mut(buffer)[0] = (lap * RING + slot) as u8; }
            }
            n.io.doorbells.clear();
            {
                let mut batch = n.receive_batch();
                for slot in 0..RING {
                    assert!(batch.receive_in_place(|_, bytes| {
                        assert_eq!(bytes[0], (lap * RING + slot) as u8);
                        RxAction::Transmit {port: TxPort::Wan, length: 60}
                    }).unwrap().unwrap().transmitted);
                    // Each half ring is visible before a full-index wrap.
                    assert_eq!(batch.nic.io.doorbells.len(), (slot + 1) / (RING / 2) * 2);
                }
            }
            assert_eq!(n.io.doorbells, [(0x6808,16), (0x6908,((lap * RING + 15) % RX_RING) as u32), (0x6808,0), (0x6908,((lap * RING + 31) % RX_RING) as u32)]);
            assert_eq!((n.tx,n.rx), (0,(lap + 1) * RING % RX_RING));
        }
    }

    #[test]
    fn receive_batch_flushes_partial_work_on_drop_defer_and_backpressure() {
        for stop in 0..4 {
            let mut n = Nic::new(Mock::new());
            n.initialize(100).unwrap();
            for slot in 0..3 { n.io.set_word(RX + slot*32 + 4, DONE | LAST | (60 << 8)); }
            if stop == 2 { n.io.set_word(32 + 4, LAST); }
            if stop == 3 { n.io.set_word(RX + 32 + 4, DONE | LAST | (13 << 8)); }
            n.io.doorbells.clear();
            {
                let mut batch = n.receive_batch();
                batch.receive_in_place(|_,_| RxAction::Transmit {port:TxPort::Wan,length:60}).unwrap();
                assert!(batch.nic.io.doorbells.is_empty());
                match stop {
                    0 => {}, // Early owner exit flushes through Drop.
                    1 => assert_eq!(batch.receive_in_place(|_,_| RxAction::Defer), Ok(None)),
                    2 => assert_eq!(batch.receive_in_place(|_,_| panic!("busy")), Err(Error::Busy)),
                    3 => assert_eq!(batch.receive_in_place(|_,_| panic!("malformed")), Err(Error::Malformed)),
                    _ => unreachable!(),
                }
            }
            assert_eq!(n.io.doorbells, [(0x6808,1), (0x6908,if stop==3 {1} else {0})]);
            assert_eq!(n.tx,1);
            assert_eq!(n.rx,if stop==3 {2} else {1});
            assert!(n.has_receive());
        }
    }

    #[test]
    fn in_place_permutation_wrap_padding_and_copy_interoperation() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        for sequence in 0..RX_RING * 3 {
            let rx = n.rx;
            let tx = n.tx;
            let buffer = n.rx_buffers[rx];
            let replacement = n.tx_buffers[tx];
            n.io.dma[buffer..buffer + 64].fill(0xa5);
            n.io.set_word(RX + rx * 32, 0xdeadbeef); // not trusted
            n.io.set_word(RX + rx * 32 + 4, DONE | LAST | (60 << 8));
            n.io.set_word(RX + rx * 32 + 16, 2 << 26);
            n.io.set_word(tx * 32 + 4, DONE);
            let destination = if sequence % 2 == 0 {
                TxPort::Wan
            } else {
                TxPort::Internal
            };
            let result = n
                .receive_in_place(|packet, data| {
                    assert_eq!(
                        packet,
                        Received::decode(60, 2 << 26)
                    );
                    assert_eq!(data[0], 0xa5);
                    data[0] = sequence as u8;
                    RxAction::Transmit {
                        port: destination,
                        length: 42,
                    }
                })
                .unwrap()
                .unwrap();
            assert!(result.transmitted);
            assert_eq!(n.io.word(tx * 32), n.io.physical as u32 + buffer as u32);
            assert_eq!(
                n.io.word(RX + rx * 32),
                n.io.physical as u32 + replacement as u32
            );
            assert_eq!(n.io.word(tx * 32 + 4), LAST | (60 << 8));
            assert_eq!(
                n.io.word(tx * 32 + 16),
                (if sequence % 2 == 0 { 2 } else { 1 }) << 16
            );
            assert_eq!(n.io.dma[buffer], sequence as u8);
            assert!(n.io.dma[buffer + 42..buffer + 60]
                .iter()
                .all(|byte| *byte == 0));
            let mut all = std::vec::Vec::from(n.tx_buffers);
            all.extend(n.rx_buffers);
            all.sort_unstable();
            assert_eq!(
                all,
                (0..RING + RX_TOTAL)
                    .map(|i| POOL + i * BUFFER)
                    .collect::<std::vec::Vec<_>>()
            );
        }
        // The copying API must follow the exchanged pool too.
        assert_ne!(n.tx_buffers[0], POOL);
        n.io.set_word(4, DONE);
        n.transmit_to(TxPort::Wan, &[0x13; 60]).unwrap();
        assert_eq!(
            &n.io.dma[n.tx_buffers[0]..n.tx_buffers[0] + 60],
            &[0x13; 60]
        );
        let buffer = n.rx_buffers[0];
        n.io.dma[buffer..buffer + 60].fill(0xee);
        n.io.set_word(RX, 0xdeadbeef);
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        let mut copy = [0; BUFFER];
        assert_eq!(n.receive(&mut copy), Ok(Some(60)));
        assert_eq!(&copy[..60], &[0xee; 60]);
        assert_eq!(n.io.word(RX), n.io.physical as u32 + buffer as u32);
    }

    #[test]
    fn read_only_discard_preserves_rejected_rx_and_never_uses_tx() {
        let mut n = Nic::new(Mock::new());
        assert_eq!(n.discard_receive_if(|_, _| panic!("not ready")), Err(Error::NotReady));
        n.initialize(100).unwrap();
        assert_eq!(n.discard_receive_if(|_, _| panic!("empty")), Ok(None));
        let buffer = n.rx_buffers[0];
        n.io.dma[buffer..buffer + 60].fill(0x42);
        n.io.set_word(RX, 0xdeadbeef); // never trust the device-written pointer
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        n.io.set_word(RX + 16, 2 << 26);
        n.io.set_word(4, LAST | (60 << 8)); // TX busy must not impede discard
        assert_eq!(n.discard_receive_if(|packet, data| {
            assert_eq!(packet, Received::decode(60, 2 << 26));
            assert_eq!(data, &[0x42; 60]);
            false
        }), Ok(None));
        assert_eq!((n.rx, n.tx), (0, 0));
        assert_eq!(n.io.word(RX), 0xdeadbeef);
        assert_eq!(n.io.word(RX + 4), DONE | LAST | (60 << 8));
        assert_eq!(&n.io.dma[buffer..buffer + 60], &[0x42; 60]);
        assert_eq!(n.discard_receive_if(|_, _| true), Ok(Some(Received::decode(60, 2 << 26))));
        assert_eq!((n.rx, n.tx), (1, 0));
        assert_eq!(n.io.word(RX), n.io.physical as u32 + buffer as u32);
        assert_eq!(n.io.word(4), LAST | (60 << 8));
        n.io.set_word(RX + 32 + 4, DONE | LAST | (13 << 8));
        assert_eq!(n.discard_receive_if(|_, _| panic!("malformed")), Err(Error::Malformed));
        assert_eq!(n.rx, 2);
    }

    #[test]
    fn headroom_pool_offsets_survive_wrap_and_legacy_views() {
        let mut n = Nic::new_with_rx_headroom(Mock::new()); n.initialize(100).unwrap();
        for sequence in 0..RING*3 {
            let base = n.rx_buffers[n.rx]; let tx = n.tx;
            assert_eq!(n.io.word(RX+n.rx*32),n.io.physical as u32 + base as u32 + 4);
            assert_eq!(n.io.word(RX+n.rx*32+4),((BUFFER-4) as u32)<<8);
            n.io.set_word(tx*32+4,DONE);
            n.io.set_word(RX+n.rx*32+4,DONE|LAST|(64<<8));
            unsafe { let bytes=n.io.buffer_mut(base); bytes.fill(0xa5); bytes[4..68].fill(sequence as u8); }
            let offset = sequence%3*4;
            let length = 68-offset;
            {
                let mut batch = n.receive_batch();
                assert!(batch.receive_with_headroom(|packet,start,buffer| {
                    assert_eq!((packet.length,start),(64,4));
                    assert_eq!(&buffer[..4],&[0xa5;4]);
                    if offset==0 { buffer[..4].fill(sequence as u8); }
                    RxAction::TransmitFrom {port:TxPort::ExternalTagged,length,offset}
                }).unwrap().unwrap().transmitted);
            }
            assert_eq!(n.tx_buffers[tx],base);
            assert_eq!(n.io.word(tx*32),n.io.physical as u32+base as u32+offset as u32);
            assert!(n.io.dma[base+offset..base+68].iter().all(|&b|b==sequence as u8));
        }
        let base=n.rx_buffers[n.rx];
        unsafe { let bytes=n.io.buffer_mut(base); bytes[..4].fill(0xa5);bytes[4..64].fill(0x42); }
        n.io.set_word(RX+n.rx*32+4,DONE|LAST|(60<<8));
        let mut out=[0;60];
        assert_eq!(n.receive(&mut out),Ok(Some(60)));
        assert_eq!(out,[0x42;60]);
        let base=n.rx_buffers[n.rx];
        unsafe { n.io.buffer_mut(base)[4..64].fill(0x24); }
        n.io.set_word(RX+n.rx*32+4,DONE|LAST|(60<<8));
        assert!(n.discard_receive_if(|_,frame|frame==[0x24;60]).unwrap().is_some());
        let tx=n.tx; let base=n.rx_buffers[n.rx];
        n.io.set_word(tx*32+4,DONE);
        unsafe { n.io.buffer_mut(base)[4..64].fill(0x48); }
        n.io.set_word(RX+n.rx*32+4,DONE|LAST|(60<<8));
        n.receive_in_place(|_,frame| {
            assert_eq!(&frame[..60],&[0x48;60]);
            RxAction::Transmit {port:TxPort::Wan,length:60}
        }).unwrap();
        assert_eq!(n.io.word(tx*32),n.io.physical as u32+base as u32+4);
    }

    #[test]
    fn headroom_accepts_nested_tag_offsets_without_moving_payload() {
        for skip in [4, 8, 12, 16, 32, 128] {
            let mut n=Nic::new_with_rx_headroom(Mock::new());n.initialize(100).unwrap();
            let base=n.rx_buffers[0];let offset=4+skip;
            n.io.set_word(RX+4,DONE|LAST|(((60+skip) as u32)<<8));
            unsafe {n.io.buffer_mut(base)[offset..offset+60].fill(0x5a);}
            n.receive_batch().receive_with_headroom(|_,_,_|RxAction::TransmitFrom {port:TxPort::Wan,length:60,offset}).unwrap();
            assert_eq!(n.io.word(0),n.io.physical as u32+base as u32+offset as u32);
            assert_eq!(&n.io.dma[base+offset..base+offset+60],&[0x5a;60]);
        }
    }

    #[test]
    fn shifted_short_frame_padding_cannot_cross_pool_end() {
        for (offset,ok) in [(BUFFER-60,true),(BUFFER-56,false)] {
            let mut n=Nic::new_with_rx_headroom(Mock::new());n.initialize(100).unwrap();
            n.io.set_word(RX+4,DONE|LAST|(((BUFFER-4) as u32)<<8));
            let result=n.receive_batch().receive_with_headroom(|_,_,_|RxAction::TransmitFrom {port:TxPort::Wan,length:14,offset});
            assert_eq!(result.is_ok(),ok);
            if !ok {assert_eq!(result,Err(Error::Length));assert_eq!(n.tx,0);}
        }
    }

    #[test]
    fn headroom_rejects_invalid_ranges_and_oversized_dma_input() {
        for offset in [1,3,12,usize::MAX] {
            let mut n=Nic::new_with_rx_headroom(Mock::new());n.initialize(100).unwrap();
            n.io.set_word(RX+4,DONE|LAST|(60<<8));
            assert_eq!(n.receive_batch().receive_with_headroom(|_,_,_|RxAction::TransmitFrom {port:TxPort::Wan,length:60,offset}),Err(Error::Length));
            assert_eq!((n.rx,n.tx),(1,0));
        }
        let mut n=Nic::new_with_rx_headroom(Mock::new());n.initialize(100).unwrap();
        n.io.set_word(RX+4,DONE|LAST|((BUFFER as u32)<<8));
        assert_eq!(n.receive_in_place(|_,_|panic!("oversized")),Err(Error::Malformed));
        n.io.set_word(RX+32+4,DONE|LAST|(60<<8));
        assert_eq!(n.receive_in_place(|_,_|RxAction::TransmitFrom {port:TxPort::Wan,length:60,offset:0}),Err(Error::Length));
        assert_eq!(n.tx,0);
    }

    #[test]
    fn shifted_receive_preserves_pool_bases_across_wrap_and_producer_reuse() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        for sequence in 0..RING * 3 {
            let tx = n.tx;
            n.io.set_word(tx * 32 + 4, DONE);
            n.io.set_word(RX + n.rx * 32 + 4, DONE | LAST | (46 << 8));
            let base = n.rx_buffers[n.rx];
            unsafe { n.io.buffer_mut(base).fill(0xa5); }
            assert!(n.receive_in_place(|_, data| {
                data[4..46].fill(sequence as u8);
                RxAction::TransmitShifted { port: TxPort::Wan, length: 42 }
            }).unwrap().unwrap().transmitted);
            assert_eq!(n.tx_buffers[tx], base);
            assert_eq!(n.io.word(tx * 32), n.io.physical as u32 + base as u32 + 4);
            assert_eq!(n.io.word(tx * 32 + 4), LAST | (60 << 8));
            assert!(n.io.dma[base + 4..base + 46].iter().all(|&b| b == sequence as u8));
            assert!(n.io.dma[base + 46..base + 64].iter().all(|&b| b == 0));
            assert_eq!(&n.io.dma[base..base+4], &[0xa5;4]);
            assert_eq!(n.io.dma[base+64], 0xa5);
        }
        n.io.set_word(n.tx * 32 + 4, DONE);
        let tx = n.tx; let base = n.tx_buffers[tx];
        assert_eq!(n.transmit_with(|_| RxAction::TransmitShifted {port:TxPort::Wan,length:42}), Err(Error::Length));
        assert_eq!(n.tx, tx);
        n.transmit_with(|bytes| { bytes[..60].fill(0x42); RxAction::Transmit {port:TxPort::Wan,length:60} }).unwrap();
        assert_eq!(n.io.word(tx * 32), n.io.physical as u32 + base as u32);
    }

    #[test]
    fn shifted_receive_bounds_and_backpressure_precede_publication() {
        let mut n = Nic::new(Mock::new()); n.initialize(100).unwrap();
        n.io.set_word(RX + 4, DONE | LAST | (42 << 8));
        n.io.set_word(4, LAST);
        assert_eq!(n.receive_in_place(|_,_| panic!("blocked callback")), Err(Error::Busy));
        n.io.set_word(4, DONE);
        assert_eq!(n.receive_in_place(|_,_| RxAction::TransmitShifted {port:TxPort::Wan,length:43}), Err(Error::Length));
        assert_eq!((n.rx,n.tx), (1,0));
        n.io.set_word(RX + 32 + 4, DONE | LAST | (1518 << 8));
        assert!(n.receive_in_place(|_,_| RxAction::TransmitShifted {port:TxPort::Wan,length:1514}).unwrap().unwrap().transmitted);
        assert_eq!(n.io.word(4), LAST | (1514 << 8));
    }

    #[test]
    fn deferred_receive_preserves_ownership_and_is_processed_once_by_next_path() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        let buffer = n.rx_buffers[0];
        unsafe { n.io.buffer_mut(buffer)[..60].fill(0x5a); }
        let rx_buffers = n.rx_buffers;
        let tx_buffers = n.tx_buffers;
        let rx_status = n.io.word(RX + 4);
        let tx_status = n.io.word(4);
        assert_eq!(n.receive_in_place(|packet, data| {
            assert_eq!(packet.length, 60);
            assert!(data[..60].iter().all(|b| *b==0x5a));
            RxAction::Defer
        }), Ok(None));
        assert_eq!((n.rx, n.tx), (0, 0));
        assert_eq!(n.rx_buffers, rx_buffers);
        assert_eq!(n.tx_buffers, tx_buffers);
        assert_eq!(n.io.word(RX + 4), rx_status);
        assert_eq!(n.io.word(4), tx_status);
        assert!(n.has_receive());
        let result = n.receive_in_place(|_, data| {
            assert!(data[..60].iter().all(|b| *b==0x5a));
            data[0]=0x42;
            RxAction::Transmit {port: TxPort::Wan, length:60}
        }).unwrap().unwrap();
        assert!(result.transmitted);
        assert_eq!((n.rx, n.tx), (1, 1));
        assert!(!n.has_receive());
        assert_eq!(n.tx_buffers[0], buffer);
        assert_eq!(unsafe { n.io.buffer_mut(buffer)[0] }, 0x42);
    }

    #[test]
    fn in_place_backpressure_never_reexecutes_packet_mutation() {
        let mut n = Nic::new(Mock::new());
        assert_eq!(
            n.receive_in_place(|_, _| panic!("not ready")),
            Err(Error::NotReady)
        );
        n.initialize(100).unwrap();
        assert_eq!(n.receive_in_place(|_, _| panic!("no packet")), Ok(None));
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        n.io.set_word(4, LAST | (60 << 8));
        assert_eq!(
            n.receive_in_place(|_, _| panic!("backpressure must precede mutation")),
            Err(Error::Busy)
        );
        assert_eq!((n.tx, n.rx), (0, 0));
        assert_eq!(n.io.word(RX + 4), DONE | LAST | (60 << 8));
        n.io.set_word(4, DONE);
        assert_eq!(
            n.receive_in_place(|_, data| {
                data[0] = 42;
                RxAction::Transmit {
                    port: TxPort::Wan,
                    length: 1515,
                }
            }),
            Err(Error::Length)
        );
        assert_eq!((n.tx, n.rx), (0, 1));
        assert_eq!(n.io.word(4), DONE);
        assert_eq!(n.io.word(RX + 4), (BUFFER as u32) << 8);
        n.io.set_word(RX + 32 + 4, DONE | LAST | (65535 << 8));
        assert_eq!(
            n.receive_in_place(|_, _| panic!("malformed packet")),
            Err(Error::Malformed)
        );
        assert_eq!(n.rx, 2);
    }

    #[test]
    fn in_place_drop_and_tag_headroom() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        assert!(
            !n.receive_in_place(|_, _| RxAction::Drop)
                .unwrap()
                .unwrap()
                .transmitted
        );
        assert_eq!((n.tx, n.rx), (0, 1));
        n.io.set_word(RX + 32 + 4, DONE | LAST | (1514 << 8));
        let old = n.rx_buffers[1];
        n.receive_in_place(|_, data| {
            data[1514..1518].copy_from_slice(&[1, 2, 3, 4]);
            RxAction::Transmit {
                port: TxPort::ExternalTagged,
                length: 1518,
            }
        })
        .unwrap();
        assert_eq!(n.io.word(16), 15 << 16);
        assert_eq!(n.io.word(4), LAST | (1518 << 8));
        assert_eq!(&n.io.dma[old + 1514..old + 1518], &[1, 2, 3, 4]);
        n.io.set_word(RX + 64 + 4, DONE | LAST | (60 << 8));
        assert_eq!(
            n.receive_in_place(|_, _| RxAction::Transmit {
                port: TxPort::ExternalTagged,
                length: 65,
            }),
            Err(Error::Length)
        );
    }

    #[test]
    fn producer_tx_reserves_before_mutation_and_uses_owned_buffers() {
        let mut n = Nic::new(Mock::new());
        assert_eq!(
            n.transmit_with(|_| panic!("not ready")),
            Err(Error::NotReady)
        );
        n.initialize(100).unwrap();
        n.io.set_word(4, LAST | (60 << 8));
        assert_eq!(n.transmit_with(|_| panic!("busy")), Err(Error::Busy));
        n.io.set_word(4, DONE);
        assert_eq!(n.transmit_with(|_| RxAction::Drop), Ok(false));
        assert_eq!(n.tx, 0);
        assert_eq!(
            n.transmit_with(|_| RxAction::Transmit {
                port: TxPort::Wan,
                length: 1519
            }),
            Err(Error::Length)
        );
        assert_eq!(n.tx, 0);
        for sequence in 0..RING * 3 {
            let tx = n.tx;
            n.io.set_word(tx * 32 + 4, DONE);
            n.io.set_word(tx * 32, 0xdeadbeef);
            let buffer = n.tx_buffers[tx];
            assert_eq!(
                n.transmit_with(|data| {
                    data.fill(0xee);
                    data[..42].fill(sequence as u8);
                    RxAction::Transmit {
                        port: TxPort::Wan,
                        length: 42,
                    }
                }),
                Ok(true)
            );
            assert_eq!(n.io.word(tx * 32), n.io.physical as u32 + buffer as u32);
            assert_eq!(n.io.word(tx * 32 + 16), 2 << 16);
            assert_eq!(&n.io.dma[buffer..buffer + 42], &[sequence as u8; 42]);
            assert_eq!(&n.io.dma[buffer + 42..buffer + 60], &[0; 18]);
        }
    }

    #[test]
    fn drain_checks_all_outstanding_descriptors_without_recycling_them() {
        let mut n = Nic::new(Mock::new());
        assert!(!n.transmit_drained());
        n.initialize(100).unwrap();
        assert!(n.transmit_drained());
        for _ in 0..RING { n.transmit(&[0x42; 60]).unwrap(); }
        for slot in 0..RING {
            assert!(!n.transmit_drained());
            n.io.set_word(slot * 32 + 4, DONE);
        }
        assert!(n.transmit_drained());
        n.transmit(&[0x43; 60]).unwrap();
        assert!(!n.transmit_drained());
        n.io.set_word(4, DONE);
        assert!(n.transmit_drained());
        let receipt = n.transmit_batch().submit_tracked(TxPort::Wan, &[0x44; 60], None).unwrap();
        n.transmit_with(|_| RxAction::Transmit { port: TxPort::Wan, length: 60 }).unwrap();
        n.io.set_word((receipt.slot + 1) * 32 + 4, DONE);
        assert!(!n.transmit_drained(), "a later completion cannot retire the earlier slot");
        n.io.set_word(receipt.slot * 32 + 4, DONE);
        assert!(n.transmit_drained());
    }
    #[test]
    fn tx_ownership_padding_and_wrap() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        for _ in 0..RING {
            n.transmit(&[0x42; 42]).unwrap();
        }
        assert_eq!(n.io.reg(0x6808), 0);
        assert_eq!(n.transmit(&[1; 60]), Err(Error::Busy));
        assert_eq!(&n.io.dma[POOL..POOL + 42], &[0x42; 42]);
        assert_eq!(&n.io.dma[POOL + 42..POOL + 60], &[0; 18]);
        assert_eq!(n.io.word(4), LAST | (60 << 8));
        n.io.set_word(4, DONE);
        n.transmit(&[2; 1514]).unwrap();
        assert_eq!(n.io.reg(0x6808), 1);
        assert_eq!(n.transmit(&[0; 1515]), Err(Error::Length));
    }
    #[test]
    fn rx_recycles_bad_frames_and_wraps() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        let mut out = [0; BUFFER];
        assert!(!n.has_receive());
        assert_eq!(n.receive(&mut out), Ok(None));
        for i in 0..RX_RING {
            n.io.set_word(RX + i * 32, 0xdeadbeef); // ignored, fixed backing allocation
            n.io.set_word(RX + i * 32 + 4, DONE | LAST | (60 << 8));
            n.io.set_byte(POOL + (RING + i) * BUFFER, i as u8);
            assert!(n.has_receive());
            assert_eq!(n.receive(&mut out), Ok(Some(60)));
            assert_eq!(out[0], i as u8);
            assert_eq!(n.io.word(RX + i * 32 + 4), (BUFFER as u32) << 8);
        }
        assert_eq!(n.rx, 0);
        n.io.set_word(RX + 4, DONE | LAST | (0xffff << 8));
        assert_eq!(n.receive(&mut out), Err(Error::Malformed));
        assert_eq!(n.io.reg(0x6908), 0);
    }
    #[test]
    fn wan_and_lan_destinations_do_not_leak_across_ring_reuse() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        for lap in 0..3 {
            for slot in 0..RING {
                let (port, destination, minimum) = match (slot + lap) % 3 {
                    0 => (TxPort::Wan, 2, 60),
                    1 => (TxPort::ExternalTagged, 15, 64),
                    _ => (TxPort::Internal, 1, 60),
                };
                n.io.set_word(slot * 32 + 4, DONE);
                n.transmit_to(port, &[0xab; 46]).unwrap();
                assert_eq!(n.io.word(slot * 32 + 16), destination << 16);
                assert_eq!(n.io.word(slot * 32 + 4), LAST | (minimum << 8));
                assert!(n.io.dma
                    [POOL + slot * BUFFER + 46..POOL + slot * BUFFER + minimum as usize]
                    .iter()
                    .all(|b| *b == 0));
            }
        }
        assert_eq!(n.transmit_to(TxPort::Wan, &[0; 1519]), Err(Error::Length));
        n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
        n.io.set_word(RX + 16, 2 << 26);
        assert_eq!(
            n.receive_from(&mut [0; BUFFER]),
            Ok(Some(Received::decode(60, 2 << 26)))
        );
    }

    #[test]
    fn ppe_metadata_survives_all_receive_paths_and_defer() {
        for reason in 0..32u32 {
            for index in [0, 0x1234, 0x3fff, 0x7fff] {
                let mut n = Nic::new_with_rx_headroom(Mock::new()); n.initialize(100).unwrap();
                let word = (15 << 26) | (reason << 18) | index | (7 << 15) | (7 << 23) | (3 << 30);
                let expected = Received::decode(60, word);
                assert_eq!((expected.ppe_reason(), expected.foe_index(), expected.source_port), (reason as u8, index as u16, 15));
                n.io.set_word(RX + 4, DONE | LAST | (60 << 8));
                n.io.set_word(RX + 16, word);
                assert_eq!(n.discard_receive_if(|packet, _| { assert_eq!(packet, expected); false }), Ok(None));
                assert_eq!(n.receive_in_place(|packet, _| { assert_eq!(packet, expected); RxAction::Defer }), Ok(None));
                assert_eq!(n.receive_batch().receive_with_headroom(|packet, offset, _| {
                    assert_eq!((packet, offset), (expected, 4)); RxAction::Defer
                }), Ok(None));
                assert_eq!(n.rx, 0);
                assert_eq!(n.receive_from(&mut [0; BUFFER]), Ok(Some(expected)));
                assert_eq!(n.rx, 1);
            }
        }
    }

    #[test]
    fn external_tagged_route_padding_and_receive_origin() {
        let mut n = Nic::new(Mock::new());
        n.initialize(100).unwrap();
        n.transmit_to(TxPort::ExternalTagged, &[7; 46]).unwrap();
        assert_eq!(n.io.word(16), 15 << 16);
        assert_eq!(n.io.word(4), LAST | (64 << 8));
        assert_eq!(&n.io.dma[POOL + 46..POOL + 64], &[0; 18]);
        n.transmit_to(TxPort::ExternalTagged, &[8; 1522]).unwrap();
        assert_eq!(
            n.transmit_to(TxPort::ExternalTagged, &[0; 1523]),
            Err(Error::Length)
        );
        // A later internal frame must not inherit a previous ring destination.
        n.tx = 0;
        n.io.set_word(4, DONE);
        n.transmit(&[9; 60]).unwrap();
        assert_eq!(n.io.word(16), 1 << 16);
        n.io.set_word(RX + 4, DONE | LAST | (1518 << 8));
        n.io.set_word(RX + 16, (15 << 26) | 0x12345);
        assert_eq!(
            n.receive_from(&mut [0; BUFFER]),
            Ok(Some(Received::decode(1518, (15 << 26) | 0x12345)))
        );
        assert_eq!(n.io.word(RX + 4), (BUFFER as u32) << 8);
    }
    #[test]
    fn busy_hardware_never_overwrites_dma() {
        let mut io = Mock::new();
        io.set_reg(CFG, 0xa);
        io.set_word(0, 0x1234);
        let mut n = Nic::new(io);
        assert_eq!(n.initialize(10), Err(Error::Timeout));
        assert_eq!(n.io.word(0), 0x1234);
        assert_eq!(n.transmit(&[0; 60]), Err(Error::NotReady));
        n.io.physical = 0xfffff000;
        assert_eq!(n.initialize(10), Err(Error::Address));
    }
}
