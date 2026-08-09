//! Pure interrupt-controller helpers and allocation-free IRQ handoff cells.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// QEMU `virt` exposes 32 enable words per PLIC context.
pub const PLIC_ENABLE_WORDS: usize = 32;
pub const PLIC_MAX_IRQ: u32 = (PLIC_ENABLE_WORDS * u32::BITS as usize - 1) as u32;

/// Map a non-zero PLIC source ID to its enable-register word and bit.
pub const fn plic_enable_location(irq: u32) -> Option<(usize, u32)> {
    if irq == 0 || irq > PLIC_MAX_IRQ {
        None
    } else {
        Some(((irq / u32::BITS) as usize, irq % u32::BITS))
    }
}

/// One callback publication stored in an [`AtomicIrqHandlerSlot`].
///
/// The callback is represented as an address here so the portable crate does
/// not prescribe a kernel callback ABI. The kernel validates that its
/// function-pointer representation fits in one `usize` before converting it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrqHandlerPublication {
    pub irq: u32,
    pub callback: usize,
    pub context: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerSnapshotBusy;

/// A bounded, allocation-free callback slot with a wait-free IRQ-side read.
///
/// Writers are externally serialized and bracket the three atomic payload
/// words with an odd/even sequence. A reader samples the sequence only once at
/// each end: it returns `Busy` instead of spinning if a remote writer overlaps
/// it. Every payload word is atomic, so an overlapping sample is never a Rust
/// data race; the sequence check prevents a torn tuple from being invoked.
pub struct AtomicIrqHandlerSlot {
    sequence: AtomicUsize,
    irq: AtomicU32,
    callback: AtomicUsize,
    context: AtomicUsize,
}

impl AtomicIrqHandlerSlot {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicUsize::new(0),
            irq: AtomicU32::new(0),
            callback: AtomicUsize::new(0),
            context: AtomicUsize::new(0),
        }
    }

    /// Read one coherent publication without locking or waiting for a writer.
    pub fn try_snapshot(&self) -> Result<Option<IrqHandlerPublication>, HandlerSnapshotBusy> {
        let before = self.sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return Err(HandlerSnapshotBusy);
        }

        let irq = self.irq.load(Ordering::Relaxed);
        let callback = self.callback.load(Ordering::Relaxed);
        let context = self.context.load(Ordering::Relaxed);

        // Keep all payload reads before the validating sequence sample on
        // both the compiler and RVWMO. This is the read-side seqlock barrier.
        core::sync::atomic::fence(Ordering::Acquire);
        let after = self.sequence.load(Ordering::Relaxed);
        if before != after || after & 1 != 0 {
            return Err(HandlerSnapshotBusy);
        }
        if irq == 0 {
            Ok(None)
        } else {
            Ok(Some(IrqHandlerPublication {
                irq,
                callback,
                context,
            }))
        }
    }

    /// Replace this slot while one external writer owns it.
    ///
    /// # Safety
    ///
    /// Calls that mutate the same slot must be serialized. Readers may call
    /// [`Self::try_snapshot`] concurrently.
    pub unsafe fn publish_exclusive(&self, publication: Option<IrqHandlerPublication>) {
        let stable = self.sequence.load(Ordering::Relaxed);
        assert_eq!(stable & 1, 0, "IRQ handler slot has overlapping writers");
        let updating = stable
            .checked_add(1)
            .expect("IRQ handler publication sequence exhausted");
        let published = updating
            .checked_add(1)
            .expect("IRQ handler publication sequence exhausted");

        // AcqRel keeps the payload writes below the odd marker. The final
        // Release publishes all three words as one logical record.
        self.sequence
            .compare_exchange(stable, updating, Ordering::AcqRel, Ordering::Relaxed)
            .expect("IRQ handler slot has overlapping writers");
        let publication = publication.unwrap_or(IrqHandlerPublication {
            irq: 0,
            callback: 0,
            context: 0,
        });
        self.irq.store(publication.irq, Ordering::Relaxed);
        self.callback.store(publication.callback, Ordering::Relaxed);
        self.context.store(publication.context, Ordering::Relaxed);
        self.sequence.store(published, Ordering::Release);
    }
}

impl Default for AtomicIrqHandlerSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed-capacity byte ring for one IRQ producer and one task consumer.
///
/// One array cell is reserved to distinguish full from empty, so the usable
/// capacity is `N - 1`. The producer owns `head`, the consumer owns `tail`, and
/// the Release/Acquire handoff publishes bytes and protects a consumed cell
/// from being overwritten too early. Overflow drops the newest byte and is
/// counted; neither side blocks or allocates.
pub struct SpscByteRing<const N: usize> {
    bytes: [UnsafeCell<u8>; N],
    head: AtomicUsize,
    tail: AtomicUsize,
    dropped: AtomicU64,
}

// Safety: access to `bytes` is synchronized by the SPSC index protocol. The
// unsafe push/pop API makes the single-producer/single-consumer requirement a
// caller obligation rather than exposing an unsound safe multi-writer API.
unsafe impl<const N: usize> Sync for SpscByteRing<N> {}

impl<const N: usize> SpscByteRing<N> {
    pub const fn new() -> Self {
        assert!(N > 1, "an SPSC ring needs at least two slots");
        Self {
            bytes: [const { UnsafeCell::new(0) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    pub const fn capacity(&self) -> usize {
        N - 1
    }

    /// Push one byte from the ring's sole producer.
    ///
    /// Returns `false` after counting the byte when the ring is full.
    ///
    /// # Safety
    ///
    /// At most one execution context may call this method at a time, and it
    /// must not also act as the consumer.
    pub unsafe fn push_from_producer(&self, byte: u8) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next = next_index::<N>(head);
        if next == self.tail.load(Ordering::Acquire) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Safety: the producer exclusively owns `head`; the Acquire tail load
        // proved the consumer has released this cell before it is reused.
        unsafe { *self.bytes[head].get() = byte };
        self.head.store(next, Ordering::Release);
        true
    }

    /// Pop one byte from the ring's sole consumer.
    ///
    /// # Safety
    ///
    /// At most one execution context may call this method at a time, and it
    /// must not also act as the producer.
    pub unsafe fn pop_from_consumer(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        // Safety: the consumer exclusively owns `tail`; the Acquire head load
        // observes the producer's byte write before this read.
        let byte = unsafe { *self.bytes[tail].get() };
        self.tail.store(next_index::<N>(tail), Ordering::Release);
        Some(byte)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }

    /// Reset indices while both producer and consumer are quiescent.
    ///
    /// # Safety
    ///
    /// No push or pop may overlap this reset.
    pub unsafe fn reset_quiescent(&self) {
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
}

impl<const N: usize> Default for SpscByteRing<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
const fn next_index<const N: usize>(index: usize) -> usize {
    if index + 1 == N {
        0
    } else {
        index + 1
    }
}
