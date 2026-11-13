//! Experimental NETSYS v3 QDMA TX ownership; gated by the board test feature.
//!
//! Layout/protocol reference: Linux v6.12 mtk_eth_soc.c, mtk_tx_alloc,
//! mtk_tx_set_dma_desc_v2 and mtk_poll_tx_qdma. No checksum/VLAN/TSO offload.
//! Unlike PDMA, a release chain can have a different order from submission.
//! Both the forward tail and the last release descriptor remain reserved.

use crate::TxPort;

pub mod bridge;
pub mod control;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod engine;
pub mod setup;

const STRIDE: u32 = 32;
const CPU: u32 = 1 << 31;
const LAST: u32 = 1 << 30;
const CTX: usize = 0x4700;
const DTX: usize = 0x4704;
const CRX: usize = 0x4710;
const DRX: usize = 0x4714;

/// Backend exclusively owns N coherent, 32-byte descriptors. All accesses
/// must be volatile; barrier orders buffer/descriptor accesses and MMIO.
/// Queue initialization does not configure clocks, free queue or scheduler.
pub trait Io {
    fn read(&self, slot: usize, word: usize) -> u32;
    fn write(&mut self, slot: usize, word: usize, value: u32);
    fn reg(&self, offset: usize) -> u32;
    fn set_reg(&mut self, offset: usize, value: u32);
    fn barrier(&self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Address,
    Length,
    Full,
    Corrupt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Tail,
    Flight,
    Staged,
    Release,
}

/// A returned buffer is no longer referenced by an outstanding submission.
/// The descriptor itself stays reserved as the release-chain anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub address: u32,
    pub length: u16,
}

pub struct TxRing<const N: usize> {
    base: u32,
    states: [State; N],
    buffers: [Option<Completion>; N],
    free: [usize; N],
    head: usize,
    free_count: usize,
    tail: usize,
    release: usize,
    pending: usize,
    staged: usize,
    poisoned: bool,
}

impl<const N: usize> TxRing<N> {
    /// # Safety
    /// QDMA TX must be stopped and quiescent. The backend must exclusively
    /// own N descriptors at `base` for this ring's entire lifetime. Subsequent
    /// calls must access the same descriptor allocation and engine under sole
    /// ownership; a replacement backend object must preserve those mappings.
    /// No other actor may publish/reclaim TX.
    pub unsafe fn initialize(io: &mut impl Io, base: u64) -> Result<Self, Error> {
        if N < 3
            || base & 31 != 0
            || (N as u64)
                .checked_mul(32)
                .and_then(|bytes| base.checked_add(bytes))
                .filter(|end| *end <= (1u64 << 32))
                .is_none()
        {
            return Err(Error::Address);
        }
        let base = base as u32;
        for slot in 0..N {
            for word in 0..8 {
                io.write(slot, word, 0);
            }
            io.write(slot, 1, base + ((slot + 1) % N) as u32 * STRIDE);
            io.write(slot, 2, CPU | LAST);
        }
        io.barrier();
        io.set_reg(CTX, base);
        io.set_reg(DTX, base);
        let release = base + (N - 1) as u32 * STRIDE;
        io.set_reg(CRX, release);
        io.set_reg(DRX, release);
        let mut states = [State::Free; N];
        states[0] = State::Tail;
        states[N - 1] = State::Release;
        Ok(Self {
            base,
            states,
            buffers: [None; N],
            free: core::array::from_fn(|i| (i + 1) % N),
            head: 0,
            free_count: N - 2,
            tail: 0,
            release: N - 1,
            pending: 0,
            staged: 0,
            poisoned: false,
        })
    }

    fn pointer(&self, slot: usize) -> u32 {
        self.base + slot as u32 * STRIDE
    }
    fn slot(&self, pointer: u32) -> Result<usize, Error> {
        let offset = pointer.checked_sub(self.base).ok_or(Error::Corrupt)?;
        if offset % STRIDE != 0 || offset as usize / 32 >= N {
            return Err(Error::Corrupt);
        }
        Ok(offset as usize / 32)
    }
    pub fn outstanding(&self) -> usize {
        self.pending
    }

    /// # Safety
    /// `address..address+length` must be a permanent, initialized, DMA-readable
    /// buffer with no overlap with descriptors or any outstanding submission.
    /// Do not mutate/reuse it before reclaim returns its Completion. Padding
    /// and the MxL CPU tag must already be present; this API never edits bytes.
    pub unsafe fn submit(
        &mut self,
        io: &mut impl Io,
        address: u64,
        length: usize,
        port: TxPort,
    ) -> Result<(), Error> {
        unsafe {
            self.stage(io, address, length, port)?;
        }
        self.publish(io)
    }

    /// Reserve and fill a descriptor without advancing the hardware endpoint.
    /// The buffer is reserved until completion even before publish is called.
    /// Returns the software-selected descriptor slot for private owner mapping.
    /// Safety requirements are identical to submit; callers must publish before
    /// waiting for DMA, and retain all reservations on an error.
    pub(crate) unsafe fn stage(
        &mut self,
        io: &mut impl Io,
        address: u64,
        length: usize,
        port: TxPort,
    ) -> Result<usize, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let (min, max, fport) = match port {
            TxPort::Internal => (60, 1514, 1),
            TxPort::Wan => (60, 1514, 2),
            TxPort::ExternalTagged => (64, 1518, 15),
        };
        if !(min..=max).contains(&length) {
            return Err(Error::Length);
        }
        if address
            .checked_add(length as u64)
            .filter(|end| *end <= 1u64 << 32)
            .is_none()
        {
            return Err(Error::Address);
        }
        if self.free_count == 0 {
            return Err(Error::Full);
        }
        let next = self.free[self.head];
        let slot = self.tail;
        debug_assert_eq!(self.states[next], State::Free);
        debug_assert_eq!(self.states[slot], State::Tail);
        // A fresh terminal descriptor must be CPU-owned before the chain is
        // extended. Never follow hardware-written links to find free storage.
        for word in 0..8 {
            io.write(next, word, 0);
        }
        io.write(next, 2, CPU | LAST);
        io.write(slot, 0, address as u32);
        io.write(slot, 1, self.pointer(next));
        io.write(slot, 3, (1 << 30) | (fport << 8)); // SWC, queue 0
        for word in 4..8 {
            io.write(slot, word, 0);
        }
        io.barrier();
        io.write(slot, 2, LAST | ((length as u32) << 8));
        self.states[slot] = State::Staged;
        self.buffers[slot] = Some(Completion {
            address: address as u32,
            length: length as u16,
        });
        self.states[next] = State::Tail;
        self.tail = next;
        self.head = (self.head + 1) % N;
        self.free_count -= 1;
        self.pending += 1;
        self.staged += 1;
        Ok(slot)
    }

    /// Publish one nonempty batch. This does not relax the ownership barrier
    /// before each descriptor becomes device-owned; it coalesces the final
    /// publication barrier and context-pointer write.
    pub(crate) fn publish(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        if self.staged == 0 {
            return Ok(());
        }
        for state in &mut self.states {
            if *state == State::Staged {
                *state = State::Flight;
            }
        }
        self.staged = 0;
        io.barrier();
        io.set_reg(CTX, self.pointer(self.tail));
        Ok(())
    }

    /// Reclaim at most one buffer. A completion bit alone is insufficient:
    /// the hardware release endpoint must advance, and its link must name a
    /// submitted descriptor. Any bad pointer/state poisons further operations.
    pub fn reclaim(&mut self, io: &mut impl Io) -> Result<Option<Completion>, Error> {
        self.reclaim_indexed(io)
            .map(|done| done.map(|(_, buffer)| buffer))
    }

    /// Validated descriptor index paired with its private submission record.
    /// No hardware buffer address is used to select the owner.
    pub(crate) fn reclaim_indexed(
        &mut self,
        io: &mut impl Io,
    ) -> Result<Option<(usize, Completion)>, Error> {
        let mut completed = [None];
        self.reclaim_batch(io, &mut completed)?;
        Ok(completed[0])
    }

    /// Snapshot one release endpoint and acknowledge once for a nonempty batch.
    /// On any malformed link no partial results escape and the owner is poisoned.
    /// The caller must retain every buffer on error, as for single reclaim.
    pub(crate) fn reclaim_batch(
        &mut self,
        io: &mut impl Io,
        completed: &mut [Option<(usize, Completion)>],
    ) -> Result<usize, Error> {
        completed.fill(None);
        if self.poisoned { return Err(Error::Corrupt); }
        if completed.is_empty() { return Ok(0); }
        let result = (|| {
            let endpoint = self.slot(io.reg(DRX))?;
            let mut count = 0;
            for entry in completed.iter_mut() {
                let Some(done) = self.reclaim_inner(io, endpoint)? else { break; };
                *entry = Some(done);
                count += 1;
            }
            Ok(count)
        })();
        match result {
            Ok(count) => {
                if count != 0 {
                    io.barrier();
                    io.set_reg(CRX, self.pointer(self.release));
                }
                Ok(count)
            },
            Err(error) => {
                self.poisoned = true;
                completed.fill(None);
                Err(error)
            },
        }
    }
    fn reclaim_inner(
        &mut self,
        io: &mut impl Io,
        endpoint: usize,
    ) -> Result<Option<(usize, Completion)>, Error> {
        if endpoint == self.release {
            return Ok(None);
        }
        if self.states[endpoint] != State::Flight {
            return Err(Error::Corrupt);
        }
        io.barrier();
        let next = self.slot(io.read(self.release, 1))?;
        if self.states[next] != State::Flight {
            return Err(Error::Corrupt);
        }
        if io.read(next, 2) & CPU == 0 {
            return Ok(None);
        }
        io.barrier();
        let completed = self.buffers[next].take().ok_or(Error::Corrupt)?;
        let old = self.release;
        self.states[old] = State::Free;
        self.free[(self.head + self.free_count) % N] = old;
        self.free_count += 1;
        self.states[next] = State::Release;
        self.release = next;
        self.pending -= 1;
        Ok(Some((next, completed)))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use std::vec::Vec;
    const BASE: u32 = 0x40b00000;
    struct Mock<const N: usize> {
        words: [[u32; 8]; N],
        regs: [u32; 6],
        dirty: Cell<bool>,
        reads: Cell<usize>,
        writes: usize,
        published: Vec<[u32; 8]>,
    }
    impl<const N: usize> Mock<N> {
        fn new() -> Self {
            Self {
                words: [[0; 8]; N],
                regs: [0; 6],
                dirty: Cell::new(false),
                reads: Cell::new(0),
                writes: 0,
                published: Vec::new(),
            }
        }
        fn complete(&mut self, from: usize, to: usize) {
            self.words[from][1] = BASE + to as u32 * 32;
            self.words[to][2] |= CPU;
            self.regs[(DRX - CTX) / 4] = BASE + to as u32 * 32;
        }
    }
    impl<const N: usize> Io for Mock<N> {
        fn read(&self, slot: usize, word: usize) -> u32 {
            self.reads.set(self.reads.get() + 1);
            self.words[slot][word]
        }
        fn write(&mut self, slot: usize, word: usize, value: u32) {
            self.dirty.set(true);
            self.writes += 1;
            self.words[slot][word] = value;
        }
        fn reg(&self, offset: usize) -> u32 {
            self.regs[(offset - CTX) / 4]
        }
        fn set_reg(&mut self, offset: usize, value: u32) {
            assert!(
                !self.dirty.get(),
                "descriptor writes must precede doorbell barrier"
            );
            if offset == CTX && self.regs[0] != 0 {
                let previous = ((self.regs[0] - BASE) / 32) as usize;
                self.published.push(self.words[previous]);
            }
            self.regs[(offset - CTX) / 4] = value;
        }
        fn barrier(&self) {
            self.dirty.set(false);
        }
    }
    fn setup<const N: usize>() -> (TxRing<N>, Mock<N>) {
        let mut io = Mock::new();
        let ring = unsafe { TxRing::initialize(&mut io, BASE as u64).unwrap() };
        (ring, io)
    }
    fn send<const N: usize>(r: &mut TxRing<N>, io: &mut Mock<N>, id: u32) {
        unsafe {
            r.submit(io, 0x42000000 + id as u64 * 2048, 1514, TxPort::Wan)
                .unwrap();
        }
    }
    #[test]
    fn reclaim_batch_respects_output_bound_and_out_of_order_chain() {
        let (mut r, mut io) = setup::<8>();
        for id in 0..4 { send(&mut r, &mut io, id); }
        for (from, to) in [(7, 2), (2, 0), (0, 3), (3, 1)] { io.complete(from, to); }
        let mut out = [None; 2];
        assert_eq!(r.reclaim_batch(&mut io, &mut out), Ok(2));
        assert_eq!(out.map(|v|v.unwrap().0), [2, 0]);
        assert_eq!(io.reg(CRX), BASE);
        assert_eq!(r.outstanding(), 2);
        assert_eq!(r.reclaim_batch(&mut io, &mut out), Ok(2));
        assert_eq!(out.map(|v|v.unwrap().0), [3, 1]);
        assert_eq!(io.reg(CRX), BASE + 32);
        assert_eq!(r.outstanding(), 0);
        assert_eq!(r.reclaim_batch(&mut io, &mut out), Ok(0));
        assert_eq!(out, [None; 2]);
    }

    #[test]
    fn corrupt_mid_batch_returns_no_buffers_and_does_not_ack_prefix() {
        let (mut r, mut io) = setup::<8>();
        for id in 0..3 { send(&mut r, &mut io, id); }
        io.complete(7, 0);
        io.complete(0, 1);
        io.complete(1, 2);
        io.words[0][1] = BASE + 1;
        let mut out = [None; 3];
        assert_eq!(r.reclaim_batch(&mut io, &mut out), Err(Error::Corrupt));
        assert_eq!(out, [None; 3]);
        assert_eq!(io.reg(CRX), BASE + 7 * 32);
        assert_eq!(r.reclaim(&mut io), Err(Error::Corrupt));
        assert_eq!(unsafe {r.submit(&mut io, 0x43000000, 60, TxPort::Wan)}, Err(Error::Corrupt));
    }

    #[test]
    fn staged_batch_has_one_publication_and_keeps_buffers_reserved() {
        let (mut r, mut io) = setup::<8>();
        for id in 0..4 {
            unsafe {
                r.stage(&mut io, 0x42000000 + id * 2048, 1514, TxPort::Wan)
                    .unwrap();
            }
        }
        assert_eq!(io.reg(CTX), BASE);
        assert!(io.published.is_empty());
        assert_eq!(r.outstanding(), 4);
        assert_eq!(r.reclaim(&mut io), Ok(None));
        r.publish(&mut io).unwrap();
        assert_eq!(io.reg(CTX), BASE + 4 * 32);
        assert_eq!(io.published.len(), 1);
        r.publish(&mut io).unwrap();
        assert_eq!(io.published.len(), 1);
        for slot in 0..4 {
            io.complete(r.release, slot);
            assert_eq!(
                r.reclaim(&mut io).unwrap().unwrap().address,
                0x42000000 + slot as u32 * 2048
            );
        }
    }

    #[test]
    fn unpublished_descriptor_is_not_a_valid_completion_endpoint() {
        let (mut r, mut io) = setup::<8>();
        unsafe {
            r.stage(&mut io, 0x42000000, 60, TxPort::Wan).unwrap();
        }
        io.complete(7, 0);
        assert_eq!(r.reclaim(&mut io), Err(Error::Corrupt));
        assert_eq!(r.publish(&mut io), Err(Error::Corrupt));
        assert_eq!(r.outstanding(), 1);
        assert!(io.published.is_empty());
    }

    #[test]
    fn v3_descriptor_has_no_unrequested_offloads() {
        let (mut r, mut io) = setup::<8>();
        send(&mut r, &mut io, 0);
        assert_eq!(
            io.published[0],
            [
                0x42000000,
                BASE + 32,
                LAST | (1514 << 8),
                (1 << 30) | (2 << 8),
                0,
                0,
                0,
                0
            ]
        );
        unsafe {
            r.submit(&mut io, 0x42000804, 1518, TxPort::ExternalTagged)
                .unwrap();
        }
        assert_eq!(io.published[1][0], 0x42000804);
        assert_eq!(io.published[1][3], (1 << 30) | (15 << 8));
        assert_eq!(r.outstanding(), 2);
    }
    #[test]
    fn release_endpoint_and_owner_are_both_required() {
        let (mut r, mut io) = setup::<4>();
        send(&mut r, &mut io, 0);
        io.words[0][2] |= CPU;
        assert_eq!(r.reclaim(&mut io), Ok(None)); // ownership without endpoint
        io.complete(3, 0);
        io.words[0][2] &= !CPU;
        assert_eq!(r.reclaim(&mut io), Ok(None)); // endpoint before ownership
        io.words[0][2] |= CPU;
        assert_eq!(
            r.reclaim(&mut io),
            Ok(Some(Completion {
                address: 0x42000000,
                length: 1514
            }))
        );
        assert_eq!(r.reclaim(&mut io), Ok(None)); // no double completion
    }
    #[test]
    fn two_sentinels_survive_full_queue_and_many_wraps() {
        let (mut r, mut io) = setup::<8>();
        for round in 0..100 {
            let mut submitted = Vec::new();
            for i in 0..6 {
                submitted.push(r.tail);
                send(&mut r, &mut io, round * 6 + i);
            }
            let writes = io.writes;
            assert_eq!(
                unsafe { r.submit(&mut io, 0x43000000, 60, TxPort::Wan) },
                Err(Error::Full)
            );
            assert_eq!(writes, io.writes);
            for (i, slot) in submitted.into_iter().enumerate() {
                io.complete(r.release, slot);
                let result = r.reclaim(&mut io).unwrap().unwrap();
                assert_eq!(result.address, 0x42000000 + (round * 6 + i as u32) * 2048);
                assert_ne!(r.states[r.release], State::Free);
                assert_ne!(r.tail, r.release);
            }
            assert_eq!(r.outstanding(), 0);
            assert_eq!(r.free_count, 6);
        }
    }
    #[test]
    fn completion_order_follows_release_chain_not_submission_order() {
        let (mut r, mut io) = setup::<8>();
        for id in 0..4 {
            send(&mut r, &mut io, id);
        }
        // Model a hardware chain published as one batch, in different order.
        let order = [2, 0, 3, 1];
        let mut previous = 7;
        for slot in order {
            io.complete(previous, slot);
            previous = slot;
        }
        for slot in order {
            assert_eq!(
                r.reclaim(&mut io).unwrap().unwrap().address,
                0x42000000 + slot as u32 * 2048
            );
        }
        assert_eq!(r.reclaim(&mut io), Ok(None));
        for id in 4..10 {
            send(&mut r, &mut io, id);
        }
        assert_eq!(r.outstanding(), 6);
    }
    #[test]
    fn invalid_hardware_pointers_never_become_memory_accesses() {
        for pointer in [BASE - 32, BASE + 1, BASE + 8 * 32, u32::MAX] {
            let (mut r, mut io) = setup::<8>();
            send(&mut r, &mut io, 0);
            io.regs[5] = pointer;
            assert_eq!(r.reclaim(&mut io), Err(Error::Corrupt));
            assert_eq!(io.reads.get(), 0);
            let writes = io.writes;
            assert_eq!(
                unsafe { r.submit(&mut io, 0x42000800, 60, TxPort::Wan) },
                Err(Error::Corrupt)
            );
            assert_eq!(writes, io.writes);
        }
        for pointer in [BASE + 1, BASE + 32, BASE + 7 * 32] {
            let (mut r, mut io) = setup::<8>();
            send(&mut r, &mut io, 0);
            io.complete(7, 0);
            io.words[7][1] = pointer; // unaligned, terminal or release-anchor link
            assert_eq!(r.reclaim(&mut io), Err(Error::Corrupt));
            assert_eq!(io.reads.get(), 1);
            assert_eq!(r.outstanding(), 1);
        }
    }
    #[test]
    fn invalid_initialization_and_buffers_do_not_publish() {
        let mut io = Mock::<8>::new();
        for base in [BASE as u64 + 1, 0xffffffe0, 1u64 << 32] {
            assert!(matches!(
                unsafe { TxRing::<8>::initialize(&mut io, base) },
                Err(Error::Address)
            ));
        }
        assert_eq!(io.writes, 0);
        let (mut r, mut io) = setup::<8>();
        let writes = io.writes;
        for (address, length, port, error) in [
            (0xfffffff0u64, 60, TxPort::Wan, Error::Address),
            (0x42000000, 59, TxPort::Wan, Error::Length),
            (0x42000000, 1515, TxPort::Wan, Error::Length),
            (0x42000000, 60, TxPort::ExternalTagged, Error::Length),
        ] {
            assert_eq!(
                unsafe { r.submit(&mut io, address, length, port) },
                Err(error)
            );
        }
        assert_eq!(io.writes, writes);
        assert_eq!(r.outstanding(), 0);
    }
}
