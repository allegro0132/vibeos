//! Page-exclusive backing for copy-on-write capability-table snapshots.
//!
//! The core capability model builds a complete private candidate while these
//! pages are RW-NX, seals it read-only, and only then replaces the CSpace's
//! authoritative pointer. Retired snapshots are no longer authoritative when
//! they return to RW-NX for `Slot` destruction, full-page clearing, and reuse.

use core::ptr;

use crate::mmu;
use crate::sync::SpinLock;
use vibeos_core::mmu::PAGE_SIZE;

pub const CAP_TABLE_POOL_BYTES: usize = 4 * 1024 * 1024;
const CAP_TABLE_POOL_PAGES: usize = CAP_TABLE_POOL_BYTES / PAGE_SIZE;
const FREE: u16 = 0;

const _: () = {
    assert!(PAGE_SIZE == vibeos_core::cap::CAPABILITY_TABLE_PAGE_SIZE);
    assert!(CAP_TABLE_POOL_BYTES % PAGE_SIZE == 0);
    assert!(CAP_TABLE_POOL_PAGES < u16::MAX as usize);
};

extern "C" {
    static __cap_table_pool_start: u8;
    static __cap_table_pool_end: u8;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityTablePoolStats {
    pub total_pages: usize,
    pub live_pages: usize,
    pub read_only_pages: usize,
    pub peak_pages: usize,
    pub allocations: u64,
    pub frees: u64,
    pub reuses: u64,
}

struct PoolState {
    /// Zero is free; otherwise every page in one run stores `head + 1`.
    head_for: [u16; CAP_TABLE_POOL_PAGES],
    run_pages: [u16; CAP_TABLE_POOL_PAGES],
    generations: [u64; CAP_TABLE_POOL_PAGES],
    read_only: [bool; CAP_TABLE_POOL_PAGES],
    next_generation: u64,
    live_pages: usize,
    read_only_pages: usize,
    peak_pages: usize,
    allocations: u64,
    frees: u64,
    reuses: u64,
}

impl PoolState {
    const fn new() -> Self {
        Self {
            head_for: [FREE; CAP_TABLE_POOL_PAGES],
            run_pages: [0; CAP_TABLE_POOL_PAGES],
            generations: [0; CAP_TABLE_POOL_PAGES],
            read_only: [false; CAP_TABLE_POOL_PAGES],
            next_generation: 0,
            live_pages: 0,
            read_only_pages: 0,
            peak_pages: 0,
            allocations: 0,
            frees: 0,
            reuses: 0,
        }
    }

    fn find_run(&self, pages: usize) -> Option<usize> {
        let mut start = 0usize;
        while start.checked_add(pages)? <= CAP_TABLE_POOL_PAGES {
            if let Some(occupied) = self.head_for[start..start + pages]
                .iter()
                .position(|head| *head != FREE)
            {
                start += occupied + 1;
            } else {
                return Some(start);
            }
        }
        None
    }

    fn reserve(&mut self, pages: usize) -> Option<Allocation> {
        if pages == 0 || pages > CAP_TABLE_POOL_PAGES {
            return None;
        }
        let head = self.find_run(pages)?;
        let generation = self.next_generation.checked_add(1)?;
        self.next_generation = generation;
        if self.generations[head] != 0 {
            self.reuses = self.reuses.saturating_add(1);
        }
        let encoded_head = u16::try_from(head + 1).expect("cap-table pool head fits u16");
        for slot in &mut self.head_for[head..head + pages] {
            *slot = encoded_head;
        }
        self.run_pages[head] = u16::try_from(pages).expect("cap-table pool run fits u16");
        self.generations[head] = generation;
        self.read_only[head] = false;
        self.live_pages += pages;
        self.peak_pages = self.peak_pages.max(self.live_pages);
        self.allocations = self.allocations.saturating_add(1);
        Some(Allocation {
            head,
            pages,
            generation,
        })
    }

    fn allocation(&self, start: usize, pages: usize) -> Allocation {
        let offset = start
            .checked_sub(pool_start())
            .expect("capability table begins before its dedicated pool");
        assert_eq!(
            offset % PAGE_SIZE,
            0,
            "capability table is not page aligned"
        );
        let head = offset / PAGE_SIZE;
        assert!(
            head < CAP_TABLE_POOL_PAGES,
            "capability table begins after its pool"
        );
        let allocation = Allocation {
            head,
            pages,
            generation: self.generations[head],
        };
        self.assert_live(allocation);
        allocation
    }

    fn assert_live(&self, allocation: Allocation) {
        assert_eq!(
            self.head_for[allocation.head],
            u16::try_from(allocation.head + 1).expect("cap-table pool head fits u16"),
            "capability-table allocation is no longer live"
        );
        assert_eq!(
            usize::from(self.run_pages[allocation.head]),
            allocation.pages,
            "capability-table run length changed"
        );
        assert_eq!(
            self.generations[allocation.head], allocation.generation,
            "stale capability-table allocation identity"
        );
    }

    fn release(&mut self, allocation: Allocation) {
        self.assert_live(allocation);
        assert!(
            !self.read_only[allocation.head],
            "read-only capability table released without restoring write"
        );
        for slot in &mut self.head_for[allocation.head..allocation.head + allocation.pages] {
            *slot = FREE;
        }
        self.run_pages[allocation.head] = 0;
        self.live_pages -= allocation.pages;
        self.frees = self.frees.saturating_add(1);
    }

    fn stats(&self) -> CapabilityTablePoolStats {
        CapabilityTablePoolStats {
            total_pages: CAP_TABLE_POOL_PAGES,
            live_pages: self.live_pages,
            read_only_pages: self.read_only_pages,
            peak_pages: self.peak_pages,
            allocations: self.allocations,
            frees: self.frees,
            reuses: self.reuses,
        }
    }
}

#[derive(Clone, Copy)]
struct Allocation {
    head: usize,
    pages: usize,
    generation: u64,
}

impl Allocation {
    fn start(self) -> usize {
        pool_start() + self.head * PAGE_SIZE
    }

    fn bytes(self) -> usize {
        self.pages * PAGE_SIZE
    }
}

static POOL: SpinLock<PoolState> = SpinLock::new(PoolState::new());

/// Backend hook: reserve zeroed, page-exclusive RW-NX candidate storage.
pub fn allocate_pages(pages: usize) -> *mut u8 {
    assert_eq!(pool_end() - pool_start(), CAP_TABLE_POOL_BYTES);
    let Some(allocation) = POOL.lock().reserve(pages) else {
        return ptr::null_mut();
    };
    // Safety: the allocation record exclusively owns these currently writable
    // pages and remains live until the matching release hook.
    unsafe { ptr::write_bytes(allocation.start() as *mut u8, 0, allocation.bytes()) };
    allocation.start() as *mut u8
}

/// Backend hook: change a complete live snapshot between private RW-NX and
/// published R--. Core never asks to unprotect the authoritative snapshot; the
/// false transition happens only after its replacement is already published.
pub fn set_read_only(start: usize, pages: usize, read_only: bool) {
    let mut pool = POOL.lock();
    let allocation = pool.allocation(start, pages);
    assert_ne!(
        pool.read_only[allocation.head], read_only,
        "capability-table permission transition repeated"
    );
    mmu::set_capability_table_read_only(start, pages, read_only);
    pool.read_only[allocation.head] = read_only;
    if read_only {
        pool.read_only_pages += pages;
    } else {
        pool.read_only_pages -= pages;
    }
}

/// Backend hook: clear and release an already-retired RW-NX snapshot.
///
/// # Safety
///
/// Core must have removed the snapshot from its CSpace, restored write through
/// `set_read_only`, and dropped every `Slot` stored in the run.
pub unsafe fn release_pages(start: usize, pages: usize) {
    let mut pool = POOL.lock();
    let allocation = pool.allocation(start, pages);
    assert!(!pool.read_only[allocation.head]);
    // Safety: the backend contract proves all typed values were dropped and
    // the exclusive allocation remains writable and live.
    unsafe { ptr::write_bytes(start as *mut u8, 0, allocation.bytes()) };
    pool.release(allocation);
}

pub fn pool_start() -> usize {
    core::ptr::addr_of!(__cap_table_pool_start) as usize
}

pub fn pool_end() -> usize {
    core::ptr::addr_of!(__cap_table_pool_end) as usize
}

pub fn contains(address: usize) -> bool {
    address >= pool_start() && address < pool_end()
}

pub fn stats() -> CapabilityTablePoolStats {
    POOL.lock().stats()
}
