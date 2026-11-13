//! Stop and prepare QDMA without enabling DMA. Scratch geometry follows the
//! MT7988 Linux v6.12 free queue: 4096 descriptors and 4096 2048-byte pages.
//! This is separate from the small software TX queue and must be permanently
//! reserved; the existing board's 256 KiB PDMA arena is not sufficient.

use super::{Io, TxRing};

pub const PAGES: usize = 4096;
pub const PAGE_BYTES: usize = 2048;
pub const DESCRIPTOR_BYTES: usize = PAGES * 32;
pub const SCRATCH_BYTES: usize = DESCRIPTOR_BYTES + PAGES * PAGE_BYTES;
const GLOBAL: usize = 0x4604;
const IRQ_MASK: usize = 0x461c;
const ENABLE: u32 = 0x45; // TX, RX, TX writeback
const BUSY: u32 = 0xa;

pub trait SetupIo: Io {
    /// Monotonic clock; it must continue advancing while DMA is stopped.
    fn now(&self) -> u64;
    /// Volatile write to the separately reserved Normal-NC scratch allocation.
    fn scratch_word(&mut self, byte_offset: usize, value: u32);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Address,
    Timeout,
}

/// Initialize stopped QDMA TX/release and hardware free queues. This function
/// never enables either DMA direction and does not set an RX descriptor base.
/// On timeout it keeps IRQs and DMA disabled, leaves storage/pointers intact,
/// and returns without claiming quiescence. Memory must remain reserved.
///
/// # Safety
/// The caller exclusively owns the whole QDMA engine, its IRQs, N TX
/// descriptors at `tx_base` and SCRATCH_BYTES at `scratch_base`. Both allocations
/// must be permanent Normal-NC DMA memory with no aliases/other users. Existing
/// DMA allocations must remain reserved until quiescence has been established.
/// `io` and any replacement backend must access exactly those same allocations
/// and engine for the returned ring. No IRQ or other execution context may re-enable DMA during setup.
pub unsafe fn prepare<const N: usize>(
    io: &mut impl SetupIo,
    tx_base: u64,
    scratch_base: u64,
    timeout_ticks: u64,
) -> Result<TxRing<N>, Error> {
    let tx_end = (N as u64)
        .checked_mul(32)
        .and_then(|n| tx_base.checked_add(n));
    let scratch_end = scratch_base.checked_add(SCRATCH_BYTES as u64);
    let valid = N >= 3
        && tx_base != 0
        && scratch_base != 0
        && tx_base & 31 == 0
        && scratch_base & 4095 == 0;
    let (Some(tx_end), Some(scratch_end)) = (tx_end, scratch_end) else {
        return Err(Error::Address);
    };
    if !valid
        || tx_end > 1u64 << 32
        || scratch_end > 1u64 << 32
        || (tx_base < scratch_end && scratch_base < tx_end)
    {
        return Err(Error::Address);
    }
    // Validate every range before even disabling interrupts. No scratch or
    // descriptor writes may occur until both engine busy bits have cleared.
    io.set_reg(IRQ_MASK, 0);
    io.set_reg(GLOBAL, io.reg(GLOBAL) & !ENABLE);
    io.barrier();
    let start = io.now();
    while io.reg(GLOBAL) & BUSY != 0 {
        if io.now().wrapping_sub(start) >= timeout_ticks {
            return Err(Error::Timeout);
        }
    }
    io.barrier();
    for offset in (0..SCRATCH_BYTES).step_by(4) {
        io.scratch_word(offset, 0);
    }
    for page in 0..PAGES {
        let descriptor = page * 32;
        io.scratch_word(
            descriptor,
            (scratch_base + DESCRIPTOR_BYTES as u64 + (page * PAGE_BYTES) as u64) as u32,
        );
        // Like Linux, the final link is one past the descriptor region; the
        // explicit hardware tail/count terminate the list. It is still within
        // our reservation and is not a software-followed descriptor pointer.
        io.scratch_word(
            descriptor + 4,
            (scratch_base + ((page + 1) * 32) as u64) as u32,
        );
        io.scratch_word(descriptor + 8, (PAGE_BYTES as u32) << 8);
    }
    io.barrier();
    io.set_reg(0x4720, scratch_base as u32);
    io.set_reg(0x4724, (scratch_base + ((PAGES - 1) * 32) as u64) as u32);
    io.set_reg(0x4728, ((PAGES as u32) << 16) | PAGES as u32);
    io.set_reg(0x472c, (PAGE_BYTES as u32) << 16);
    let ring = unsafe { TxRing::initialize(io, tx_base) }.map_err(|_| Error::Address)?;
    for queue in 0..16 {
        io.set_reg(0x4400 + queue * 16, 0x0404);
        // Minimum 10 Mbps, leaky bucket size bits; no maximum rate limit.
        io.set_reg(
            0x4404 + queue * 16,
            (1 << 27) | (1 << 20) | (4 << 16) | (3 << 28),
        );
    }
    io.set_reg(0x4798, 0x80008000);
    io.set_reg(0x479c, 0x80008000);
    io.set_reg(0x4610, (1 << 20) | (7 << 16) | 0x4444);
    io.set_reg(0x4644, 0);
    io.barrier();
    Ok(ring)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use std::{collections::BTreeMap, vec, vec::Vec};
    const TX: u64 = 0x40b80000;
    const SCRATCH: u64 = 0x42000000;
    struct Mock {
        regs: BTreeMap<usize, u32>,
        descriptors: [[u32; 8]; 34],
        scratch: Vec<u32>,
        dirty: Cell<bool>,
        ticks: Cell<u64>,
        stuck: bool,
        memory_writes: usize,
        register_writes: Vec<(usize, u32)>,
    }
    impl Mock {
        fn new(stuck: bool) -> Self {
            Self {
                regs: BTreeMap::from([(GLOBAL, 0x55404575)]),
                descriptors: [[0xdeadbeef; 8]; 34],
                scratch: vec![0xdeadbeef; SCRATCH_BYTES / 4],
                dirty: Cell::new(false),
                ticks: Cell::new(u64::MAX - 2),
                stuck,
                memory_writes: 0,
                register_writes: Vec::new(),
            }
        }
    }
    impl Io for Mock {
        fn read(&self, slot: usize, word: usize) -> u32 {
            self.descriptors[slot][word]
        }
        fn write(&mut self, slot: usize, word: usize, value: u32) {
            assert_eq!(self.reg(GLOBAL) & (ENABLE | BUSY), 0);
            self.memory_writes += 1;
            self.dirty.set(true);
            self.descriptors[slot][word] = value;
        }
        fn reg(&self, offset: usize) -> u32 {
            self.regs.get(&offset).copied().unwrap_or(0)
                | if offset == GLOBAL && self.stuck {
                    BUSY
                } else {
                    0
                }
        }
        fn set_reg(&mut self, offset: usize, value: u32) {
            assert!(
                !self.dirty.get(),
                "DMA pointer publication before memory barrier"
            );
            if offset == GLOBAL {
                assert_eq!(value & ENABLE, 0);
            }
            self.regs.insert(offset, value);
            self.register_writes.push((offset, value));
        }
        fn barrier(&self) {
            self.dirty.set(false);
        }
    }
    impl SetupIo for Mock {
        fn now(&self) -> u64 {
            let old = self.ticks.get();
            self.ticks.set(old.wrapping_add(1));
            old
        }
        fn scratch_word(&mut self, offset: usize, value: u32) {
            assert_eq!(self.reg(GLOBAL) & (ENABLE | BUSY), 0);
            assert_eq!(offset & 3, 0);
            self.memory_writes += 1;
            self.dirty.set(true);
            self.scratch[offset / 4] = value;
        }
    }
    #[test]
    fn prepares_all_scratch_pages_and_leaves_dma_disabled() {
        let mut io = Mock::new(false);
        let ring = unsafe { prepare::<34>(&mut io, TX, SCRATCH, 10) }.unwrap();
        assert_eq!(ring.outstanding(), 0);
        assert_eq!(io.reg(GLOBAL), 0x55404530);
        assert_eq!(io.reg(IRQ_MASK), 0);
        assert_eq!(io.reg(0x4720), SCRATCH as u32);
        assert_eq!(io.reg(0x4724), SCRATCH as u32 + 4095 * 32);
        assert_eq!(io.reg(0x4728), 0x10001000);
        assert_eq!(io.reg(0x472c), 0x08000000);
        for p in 0..PAGES {
            assert_eq!(
                &io.scratch[p * 8..p * 8 + 8],
                &[
                    SCRATCH as u32 + DESCRIPTOR_BYTES as u32 + (p * PAGE_BYTES) as u32,
                    SCRATCH as u32 + ((p + 1) * 32) as u32,
                    (PAGE_BYTES as u32) << 8,
                    0,
                    0,
                    0,
                    0,
                    0
                ]
            );
        }
        assert!(io.scratch[DESCRIPTOR_BYTES / 4..].iter().all(|v| *v == 0));
        assert_eq!(io.reg(super::super::CTX), TX as u32);
        assert_eq!(io.reg(super::super::DRX), TX as u32 + 33 * 32);
        for queue in 0..16 {
            assert_eq!(io.reg(0x4400 + queue * 16), 0x0404);
            assert_eq!(io.reg(0x4404 + queue * 16), 0x38140000);
        }
    }
    #[test]
    fn stuck_engine_keeps_storage_intact_across_clock_wrap() {
        let mut io = Mock::new(true);
        assert!(matches!(
            unsafe { prepare::<34>(&mut io, TX, SCRATCH, 8) },
            Err(Error::Timeout)
        ));
        assert_eq!(io.memory_writes, 0);
        assert_eq!(io.register_writes.len(), 2);
        assert_eq!(io.reg(GLOBAL) & ENABLE, 0);
        assert_eq!(io.reg(IRQ_MASK), 0);
        assert!(io.ticks.get() < 20);
    }
    #[test]
    fn invalid_or_overlapping_regions_have_no_side_effects() {
        for (tx, scratch) in [
            (TX + 1, SCRATCH),
            (TX, SCRATCH + 1),
            (SCRATCH, SCRATCH),
            (SCRATCH + SCRATCH_BYTES as u64 - 32, SCRATCH),
            (TX, 0xfffff000),
            (0, SCRATCH),
            (TX, 0),
        ] {
            let mut io = Mock::new(false);
            assert!(matches!(
                unsafe { prepare::<34>(&mut io, tx, scratch, 8) },
                Err(Error::Address)
            ));
            assert_eq!(io.memory_writes, 0);
            assert!(io.register_writes.is_empty());
        }
    }
}
