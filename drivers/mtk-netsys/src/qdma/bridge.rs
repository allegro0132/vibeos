//! Keep the existing private RX/TX buffer permutation while QDMA owns TX.
//! PDMA TX descriptors are software shadows only: its TX engine MUST stay off.
use super::{Completion, Io as QueueIo, TxRing};
use crate::{Error, Io, TxPort, RING};

/// PDMA descriptor shadows are separate from the QDMA engine that tracks them.
/// Borrow just these words when publishing or reclaiming a batch.
pub trait ShadowIo {
    fn read_shadow(&self, offset: usize) -> u32;
    fn write_shadow(&mut self, offset: usize, value: u32);
    fn order_shadows(&self);
}

impl<T: Io> ShadowIo for T {
    fn read_shadow(&self, offset: usize) -> u32 { self.word(offset) }
    fn write_shadow(&mut self, offset: usize, value: u32) { self.set_word(offset, value); }
    fn order_shadows(&self) { self.barrier(); }
}

#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "qdma-test"))]
pub(crate) struct TxShadows([u32; RING * 8]);

#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "qdma-test"))]
impl TxShadows {
    pub(crate) fn new() -> Self { Self([0; RING * 8]) }
}

#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "qdma-test"))]
impl ShadowIo for TxShadows {
    fn read_shadow(&self, offset: usize) -> u32 {
        assert_eq!(offset & 3, 0);
        self.0[offset / 4]
    }
    fn write_shadow(&mut self, offset: usize, value: u32) {
        assert_eq!(offset & 3, 0);
        self.0[offset / 4] = value;
    }
    fn order_shadows(&self) {
        // Retain the ordering between QDMA's observed release and the point
        // at which its buffer can be reused by software.
        unsafe { core::arch::asm!("dsb sy", options(nostack)); }
    }
}

pub struct Bridge {
    ring: TxRing<34>,
    inflight: [Option<Completion>; RING],
    // Private mapping, never populated from DMA-written packet addresses.
    owners: [Option<usize>; 34],
    queued: usize,
    poisoned: bool,
}
impl Bridge {
    /// The ring must be newly prepared and never submitted; PDMA TX is stopped.
    pub fn new(ring: TxRing<34>) -> Self {
        assert_eq!(ring.outstanding(), 0);
        Self {
            ring,
            inflight: [None; RING],
            owners: [None; 34],
            queued: 0,
            poisoned: false,
        }
    }
    /// # Safety
    /// Shadows/buffers follow Nic's ownership protocol, and QDMA and PDMA RX
    /// own disjoint permanent storage. At most RING-1 shadows have been staged
    /// since the last notification (Nic publishes every half-ring).
    pub unsafe fn notify(
        &mut self,
        queue: &mut impl QueueIo,
        dma: &mut impl ShadowIo,
        end: usize,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Malformed);
        }
        let result = unsafe { self.notify_inner(queue, dma, end) };
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    unsafe fn notify_inner(
        &mut self,
        queue: &mut impl QueueIo,
        dma: &mut impl ShadowIo,
        end: usize,
    ) -> Result<(), Error> {
        if end >= RING {
            return Err(Error::Malformed);
        }
        while self.queued != end {
            let slot = self.queued;
            let status = dma.read_shadow(slot * 32 + 4);
            if self.inflight[slot].is_some() || status & 0xc0000000 != 0x40000000 {
                return Err(Error::Malformed);
            }
            let address = dma.read_shadow(slot * 32);
            let length = ((status >> 8) & 0xffff) as u16;
            let destination = dma.read_shadow(slot * 32 + 16) >> 16;
            let descriptor = if destination == 4 {
                if dma.read_shadow(slot * 32 + 20) != 0 || dma.read_shadow(slot * 32 + 24) != 0 {
                    return Err(Error::Malformed);
                }
                unsafe { self.ring.stage_ppe1(queue, address as u64, length as usize) }
            } else {
                let port = match destination {
                    1 => TxPort::Internal,
                    2 => TxPort::Wan,
                    15 => TxPort::ExternalTagged,
                    _ => return Err(Error::Malformed),
                };
                let word5 = dma.read_shadow(slot * 32 + 20);
                let word6 = dma.read_shadow(slot * 32 + 24);
                let mxl_tso = port == TxPort::ExternalTagged && word5 == 0xf0000000
                    && word6 >> 16 == 1 && crate::offload::mxl_tso_tag(word6 as u16);
                if word5 & !0xf0000000 != 0 || word6 & !0x1ffff != 0
                    || (word5 | word6 != 0 && !matches!(port, TxPort::Internal | TxPort::Wan) && !mxl_tso) {
                    return Err(Error::Malformed);
                }
                let metadata = (word5 | word6 != 0).then_some(crate::offload::Prepared {
                    length: length as usize, port, word5, word6,
                });
                unsafe {
                    self.ring.stage_offloaded(queue, address as u64, length as usize, port, metadata)
                }
            }.map_err(|_| Error::Malformed)?;
            if self.owners[descriptor].is_some() {
                return Err(Error::Malformed);
            }
            self.owners[descriptor] = Some(slot);
            self.inflight[slot] = Some(Completion { address, length });
            self.queued = (slot + 1) % RING;
        }
        self.ring.publish(queue).map_err(|_| Error::Malformed)
    }
    pub fn poll(&mut self, queue: &mut impl QueueIo, dma: &mut impl ShadowIo) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Malformed);
        }
        let result = self.poll_inner(queue, dma);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn poll_inner(&mut self, queue: &mut impl QueueIo, dma: &mut impl ShadowIo) -> Result<(), Error> {
        let mut completed = [None; RING];
        let count = self.ring.reclaim_batch(queue, &mut completed).map_err(|_| Error::Malformed)?;
        for &(descriptor, done) in completed[..count].iter().flatten() {
            let slot = self.owners[descriptor].ok_or(Error::Malformed)?;
            let status = dma.read_shadow(slot * 32 + 4);
            if self.inflight[slot] != Some(done) || status & (1 << 31) != 0 {
                return Err(Error::Malformed);
            }
            // Match trusted submission records, never a hardware-written buffer
            // pointer. The QDMA descriptor remains its release anchor.
            dma.order_shadows();
            dma.write_shadow(slot * 32 + 4, status | (1 << 31));
            self.inflight[slot] = None;
            self.owners[descriptor] = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: u32 = 0x42000000;
    struct Q {
        words: [[u32; 8]; 34],
        regs: [u32; 6],
        anchor: usize,
        doorbells: usize,
        acknowledgments: usize,
    }
    impl Q {
        fn new() -> Self {
            Self {
                words: [[0; 8]; 34],
                regs: [0; 6],
                anchor: 33,
                doorbells: 0,
                acknowledgments: 0,
            }
        }
        fn done(&mut self, slot: usize) {
            self.words[self.anchor][1] = BASE + slot as u32 * 32;
            self.words[slot][2] |= 1 << 31;
            self.anchor = slot;
            self.regs[5] = BASE + slot as u32 * 32;
        }
    }
    impl QueueIo for Q {
        fn read(&self, s: usize, w: usize) -> u32 {
            self.words[s][w]
        }
        fn write(&mut self, s: usize, w: usize, v: u32) {
            self.words[s][w] = v;
        }
        fn reg(&self, o: usize) -> u32 {
            self.regs[(o - 0x4700) / 4]
        }
        fn set_reg(&mut self, o: usize, v: u32) {
            if o == 0x4700 {
                self.doorbells += 1;
            }
            if o == 0x4710 { self.acknowledgments += 1; }
            self.regs[(o - 0x4700) / 4] = v;
        }
        fn barrier(&self) {}
    }
    struct D {
        words: [u32; RING * 8],
    }
    impl D {
        fn stage(&mut self, slot: usize, offset: u32) {
            assert_ne!(
                self.words[slot * 8 + 1] & (1 << 31),
                0,
                "must reclaim before reusing shadow"
            );
            self.words[slot * 8] = 0x43000000 + slot as u32 * 2048 + offset;
            self.words[slot * 8 + 1] = (1 << 30) | (1514 << 8);
            self.words[slot * 8 + 4] = 2 << 16;
        }
    }
    impl Io for D {
        fn dma_address(&self) -> u64 {
            0x43000000
        }
        fn reg(&self, _: usize) -> u32 {
            panic!("no PDMA doorbells in bridge")
        }
        fn set_reg(&mut self, _: usize, _: u32) {
            panic!("no PDMA doorbells in bridge")
        }
        fn word(&self, o: usize) -> u32 {
            self.words[o / 4]
        }
        fn set_word(&mut self, o: usize, v: u32) {
            self.words[o / 4] = v;
        }
        fn byte(&self, _: usize) -> u8 {
            panic!("bridge must not touch payload")
        }
        fn set_byte(&mut self, _: usize, _: u8) {
            panic!("bridge must not touch payload")
        }
        unsafe fn buffer_mut(&mut self, _: usize) -> &mut [u8] {
            panic!("bridge must not touch payload")
        }
        fn barrier(&self) {}
        fn now(&self) -> u64 {
            0
        }
    }
    fn setup() -> (Bridge, Q, D) {
        let mut q = Q::new();
        let ring = unsafe { TxRing::initialize(&mut q, BASE as u64) }.unwrap();
        let mut d = D {
            words: [0; RING * 8],
        };
        for slot in 0..RING {
            d.words[slot * 8 + 1] = 0xc0000000;
        }
        (Bridge::new(ring), q, d)
    }
    #[test]
    fn forwards_offload_words_without_confusing_destination() {
        let (mut b, mut q, mut d) = setup();
        d.stage(0, 0);
        d.words[1] = (1 << 30) | (2048 << 8);
        d.words[5] = 0xf0000000;
        d.words[6] = 0x1b064;
        unsafe { b.notify(&mut q, &mut d, 1).unwrap(); }
        assert_eq!(q.words[0][3], (1 << 30) | (2 << 8));
        assert_eq!(q.words[0][4], 0xf0000000);
        assert_eq!(q.words[0][5], 0x1b064);
        q.done(0);
        b.poll(&mut q, &mut d).unwrap();
        assert_ne!(d.words[1] & (1 << 31), 0);
    }

    #[test]
    fn qdma_return_uses_ppe1_without_checksum_or_tag_insertion() {
        let (mut bridge, mut queue, mut dma) = setup();
        dma.stage(0, 0);
        dma.words[4] = 4 << 16;
        unsafe { bridge.notify(&mut queue, &mut dma, 1).unwrap(); }
        assert_eq!(queue.words[0][3], (1 << 30) | (4 << 8));
        assert_eq!(&queue.words[0][4..8], &[0; 4]);
        queue.done(0);
        bridge.poll(&mut queue, &mut dma).unwrap();
        assert_ne!(dma.words[1] & (1 << 31), 0);
    }

    #[test]
    fn two_half_ring_batches_publish_twice_and_reclaim_every_shadow() {
        let (mut b, mut q, mut d) = setup();
        for slot in 0..16 {
            d.stage(slot, 4);
        }
        unsafe {
            b.notify(&mut q, &mut d, 16).unwrap();
        }
        assert_eq!(q.doorbells, 2); // initialization plus one batch
        assert_eq!(q.regs[0], BASE + 16 * 32);
        for slot in 16..32 {
            d.stage(slot, 8);
        }
        unsafe {
            b.notify(&mut q, &mut d, 0).unwrap();
        }
        assert_eq!(q.doorbells, 3);
        assert_eq!(b.ring.outstanding(), 32);
        unsafe {
            b.notify(&mut q, &mut d, 0).unwrap();
        }
        assert_eq!(q.doorbells, 3); // no empty notification
        for slot in (0..32).rev() {
            q.done(slot);
        }
        b.poll(&mut q, &mut d).unwrap();
        assert!(b.inflight.iter().all(Option::is_none));
        assert_eq!(q.acknowledgments, 2); // initialization plus one 32-packet batch
        b.poll(&mut q, &mut d).unwrap();
        assert_eq!(q.acknowledgments, 2);
        assert!((0..RING).all(|slot| d.words[slot * 8 + 1] & (1 << 31) != 0));
    }

    #[test]
    fn bad_mid_batch_shadow_keeps_unpublished_prefix_reserved() {
        let (mut b, mut q, mut d) = setup();
        d.stage(0, 0);
        d.stage(1, 0);
        d.words[1 * 8 + 4] = 3 << 16;
        assert_eq!(
            unsafe { b.notify(&mut q, &mut d, 2) },
            Err(Error::Malformed)
        );
        assert_eq!(q.doorbells, 1);
        assert_eq!(q.regs[0], BASE);
        assert_eq!(b.ring.outstanding(), 1);
        assert_eq!(b.poll(&mut q, &mut d), Err(Error::Malformed));
        assert_eq!(d.words[1] & (1 << 31), 0);
    }

    #[test]
    fn shadows_wait_for_release_chain_and_reclaim_out_of_order() {
        let (mut b, mut q, mut d) = setup();
        for slot in 0..4 {
            d.stage(slot, 4);
        }
        unsafe { b.notify(&mut q, &mut d, 4) }.unwrap();
        for slot in 0..4 {
            q.words[slot][2] |= 1 << 31;
        }
        b.poll(&mut q, &mut d).unwrap();
        assert!((0..4).all(|i| d.words[i * 8 + 1] & (1 << 31) == 0));
        for slot in [2, 0, 3, 1] {
            q.done(slot);
            b.poll(&mut q, &mut d).unwrap();
            assert_ne!(d.words[slot * 8 + 1] & (1 << 31), 0);
        }
        assert!(b.inflight.iter().all(Option::is_none));
    }
    #[test]
    fn every_shadow_recycles_across_distinct_queue_wraps() {
        let (mut b, mut q, mut d) = setup();
        for round in 0..100 {
            let mut queue_slots = [0; RING];
            for slot in 0..RING {
                queue_slots[slot] = ((q.regs[0] - BASE) / 32) as usize;
                d.stage(slot, (round % 3) * 4);
                unsafe { b.notify(&mut q, &mut d, (slot + 1) % RING) }.unwrap();
                assert_eq!(q.words[queue_slots[slot]][0], d.words[slot * 8]);
            }
            assert_eq!(b.ring.outstanding(), 32);
            // Reverse completion order forces different software/QDMA indices.
            for slot in queue_slots.into_iter().rev() {
                q.done(slot);
            }
            b.poll(&mut q, &mut d).unwrap();
            assert_eq!(b.ring.outstanding(), 0);
            assert!((0..RING).all(|slot| d.words[slot * 8 + 1] & (1 << 31) != 0));
        }
    }
    #[test]
    fn missing_or_wrong_private_owner_poison_without_releasing_shadow() {
        for wrong in [None, Some(1)] {
            let (mut b, mut q, mut d) = setup();
            d.stage(0, 0);
            d.stage(1, 0);
            unsafe { b.notify(&mut q, &mut d, 2) }.unwrap();
            b.owners[0] = wrong;
            q.done(0);
            assert_eq!(b.poll(&mut q, &mut d), Err(Error::Malformed));
            assert!((0..2).all(|i| d.words[i * 8 + 1] & (1 << 31) == 0));
            assert!(b.inflight[0].is_some() && b.inflight[1].is_some());
            assert_eq!(b.poll(&mut q, &mut d), Err(Error::Malformed));
        }
    }

    #[test]
    fn completion_uses_private_record_despite_dma_buffer_word_changes() {
        let (mut b, mut q, mut d) = setup();
        d.stage(0, 0);
        d.stage(1, 0);
        unsafe { b.notify(&mut q, &mut d, 2) }.unwrap();
        // Hardware descriptor contents cannot redirect the completed owner.
        q.words[0][0] = d.words[8];
        q.words[0][2] = (1 << 30) | (60 << 8);
        q.done(0);
        b.poll(&mut q, &mut d).unwrap();
        assert_ne!(d.words[1] & (1 << 31), 0);
        assert_eq!(d.words[9] & (1 << 31), 0);
        assert!(b.owners[0].is_none() && b.owners[1] == Some(1));
    }

    #[test]
    fn invalid_shadow_or_release_stops_without_freeing_buffers() {
        let (mut b, mut q, mut d) = setup();
        d.stage(0, 0);
        unsafe { b.notify(&mut q, &mut d, 1) }.unwrap();
        q.regs[5] = BASE + 1;
        assert_eq!(b.poll(&mut q, &mut d), Err(Error::Malformed));
        assert_eq!(d.words[1] & (1 << 31), 0);
        d.stage(1, 0);
        assert_eq!(
            unsafe { b.notify(&mut q, &mut d, 2) },
            Err(Error::Malformed)
        );
        let (mut b, mut q, mut d) = setup();
        d.stage(0, 0);
        d.words[4] = 3 << 16;
        assert_eq!(
            unsafe { b.notify(&mut q, &mut d, 1) },
            Err(Error::Malformed)
        );
        assert_eq!(b.ring.outstanding(), 0);
    }
}
