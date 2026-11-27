//! Replace a retired RX buffer before lending it to a TCP worker. A worker
//! publishes its slot only after the last immutable CPU borrow has ended.
use super::{BUF, COUNT, RX_BUF, TX_BUF};
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_hal::network_rx::{Borrow, Loan, Owner, Ticket};

const WORDS: usize = COUNT / 64;
const _: () =
    assert!(COUNT % 64 == 0 && COUNT <= u16::MAX as usize && RX_BUF + COUNT * BUF <= TX_BUF);
static RETURNED: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];
unsafe fn release(borrow: Borrow) {
    let slot = borrow.index();
    RETURNED[slot / 64].fetch_or(1 << (slot % 64), Ordering::Release);
}

pub(super) struct Buffers {
    slots: [u16; COUNT / 2],
    fresh: usize,
    word: usize,
    ready: u64,
    pub(super) enabled: bool,
    #[cfg(feature = "local-offload")]
    pub(super) lan_enabled: bool,
    #[cfg(feature = "local-offload")]
    pub(super) solo_returns: bool,
    pub(super) stats: [(u64, u64); 2],
    generation: u64,
}
impl Buffers {
    pub(super) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|i| i as u16),
            fresh: COUNT / 2,
            word: 0,
            ready: 0,
            enabled: false,
            #[cfg(feature = "local-offload")]
            lan_enabled: true,
            #[cfg(feature = "local-offload")]
            solo_returns: false,
            stats: [(0, 0); 2],
            generation: 0,
        }
    }
    fn spare(&mut self) -> Option<usize> {
        if self.fresh < COUNT {
            self.fresh += 1;
            return Some(self.fresh - 1);
        }
        if self.ready == 0 {
            for _ in 0..WORDS {
                self.word = (self.word + 1) % WORDS;
                self.ready = RETURNED[self.word].swap(0, Ordering::Acquire);
                if self.ready != 0 {
                    break;
                }
            }
        }
        if self.ready == 0 {
            return None;
        }
        let bit = self.ready.trailing_zeros() as usize;
        self.ready &= self.ready - 1;
        Some(self.word * 64 + bit)
    }
    pub(super) fn address(&self, descriptor: usize) -> usize {
        RX_BUF + usize::from(self.slots[descriptor / 2]) * BUF
    }
    // Called only on a fully retired, cache-synchronized descriptor pair.
    pub(super) unsafe fn detach(&mut self, descriptor: usize, bytes: usize, side: usize) -> Option<Loan> {
        let Some(spare) = self.spare() else {
            self.stats[side].1 += 1;
            return None;
        };
        let slot = core::mem::replace(&mut self.slots[descriptor / 2], spare as u16) as usize;
        self.stats[side].0 += 1;
        self.generation += 1;
        let ticket = Ticket::from_parts(RX_BUF as u64, slot, self.generation);
        let borrow = Borrow::from_owned(ticket, Owner::new(0, 1).unwrap());
        // Only the single NIC hart arms RX. Neither the replacement nor any
        // other descriptor references slot; no engine restart occurs in this
        // boot. The HAL loan may cross harts and cannot mutate the memory.
        Some(Loan::new(borrow, (RX_BUF + slot * BUF) as *const u8, bytes, release).unwrap())
    }
}
