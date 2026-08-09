//! Page-granular storage for generated RV64 code.
//!
//! The pool is outside the general heap so an executable never shares a PTE
//! with writable allocator metadata or another object.  A buffer has one of
//! two Rust-visible states: writable RW-NX while the trusted linker fills it,
//! or immutable execute-only after the all-hart permission transition.  Pages
//! stay reserved across every transition and are zeroed before their allocation
//! record becomes reusable.

use core::fmt;

use crate::heap::{self, AllocationDomain};
use crate::mmu;
use crate::sync::SpinLock;
use vibeos_core::mmu::PAGE_SIZE;

pub const CODE_POOL_BYTES: usize = 2 * 1024 * 1024;
const CODE_POOL_PAGES: usize = CODE_POOL_BYTES / PAGE_SIZE;
const FREE: u16 = 0;

extern "C" {
    static __code_pool_start: u8;
    static __code_pool_end: u8;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePoolError {
    Empty,
    LengthOverflow,
    TooLarge,
    Exhausted,
    GenerationExhausted,
}

impl fmt::Display for CodePoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "executable code is empty",
            Self::LengthOverflow => "executable code length overflow",
            Self::TooLarge => "executable code exceeds the W^X pool",
            Self::Exhausted => "executable code pool exhausted",
            Self::GenerationExhausted => "executable code allocation identity exhausted",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodePoolStats {
    pub total_pages: usize,
    pub live_pages: usize,
    pub sealed_pages: usize,
    pub peak_pages: usize,
    pub allocations: u64,
    pub frees: u64,
    pub reuses: u64,
}

struct PoolState {
    /// Zero is free; otherwise every page in a run names `head + 1`.
    head_for: [u16; CODE_POOL_PAGES],
    run_pages: [u16; CODE_POOL_PAGES],
    generations: [u64; CODE_POOL_PAGES],
    owners: [u64; CODE_POOL_PAGES],
    arenas: [u64; CODE_POOL_PAGES],
    sealed: [bool; CODE_POOL_PAGES],
    next_generation: u64,
    live_pages: usize,
    sealed_pages: usize,
    peak_pages: usize,
    allocations: u64,
    frees: u64,
    reuses: u64,
}

impl PoolState {
    const fn new() -> Self {
        Self {
            head_for: [FREE; CODE_POOL_PAGES],
            run_pages: [0; CODE_POOL_PAGES],
            generations: [0; CODE_POOL_PAGES],
            owners: [0; CODE_POOL_PAGES],
            arenas: [0; CODE_POOL_PAGES],
            sealed: [false; CODE_POOL_PAGES],
            next_generation: 0,
            live_pages: 0,
            sealed_pages: 0,
            peak_pages: 0,
            allocations: 0,
            frees: 0,
            reuses: 0,
        }
    }

    fn find_run(&self, pages: usize) -> Option<usize> {
        let mut start: usize = 0;
        while start.checked_add(pages)? <= CODE_POOL_PAGES {
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

    fn reserve(
        &mut self,
        pages: usize,
        words: usize,
        domain: AllocationDomain,
    ) -> Result<Allocation, CodePoolError> {
        let head = self.find_run(pages).ok_or(CodePoolError::Exhausted)?;
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(CodePoolError::GenerationExhausted)?;
        self.next_generation = generation;
        if self.generations[head] != 0 {
            self.reuses = self.reuses.saturating_add(1);
        }
        let encoded_head = u16::try_from(head + 1).expect("code-pool head fits u16");
        for slot in &mut self.head_for[head..head + pages] {
            *slot = encoded_head;
        }
        self.run_pages[head] = u16::try_from(pages).expect("code-pool run fits u16");
        self.generations[head] = generation;
        self.owners[head] = domain.owner.get();
        self.arenas[head] = domain.arena.get();
        self.sealed[head] = false;
        self.live_pages += pages;
        self.peak_pages = self.peak_pages.max(self.live_pages);
        self.allocations = self.allocations.saturating_add(1);
        Ok(Allocation {
            head,
            pages,
            words,
            generation,
        })
    }

    fn mark_sealed(&mut self, allocation: Allocation) {
        self.assert_live(allocation);
        assert!(
            !self.sealed[allocation.head],
            "code allocation sealed twice"
        );
        self.sealed[allocation.head] = true;
        self.sealed_pages += allocation.pages;
    }

    fn release(&mut self, allocation: Allocation, was_sealed: bool) {
        self.assert_live(allocation);
        assert_eq!(
            self.sealed[allocation.head], was_sealed,
            "code allocation permission state disagrees with its owner"
        );
        if was_sealed {
            self.sealed_pages -= allocation.pages;
        }
        for slot in &mut self.head_for[allocation.head..allocation.head + allocation.pages] {
            *slot = FREE;
        }
        self.run_pages[allocation.head] = 0;
        self.owners[allocation.head] = 0;
        self.arenas[allocation.head] = 0;
        self.sealed[allocation.head] = false;
        self.live_pages -= allocation.pages;
        self.frees = self.frees.saturating_add(1);
    }

    fn assert_live(&self, allocation: Allocation) {
        assert_eq!(
            self.head_for[allocation.head],
            u16::try_from(allocation.head + 1).expect("code-pool head fits u16"),
            "code allocation head is no longer live"
        );
        assert_eq!(
            usize::from(self.run_pages[allocation.head]),
            allocation.pages,
            "code allocation run length changed"
        );
        assert_eq!(
            self.generations[allocation.head], allocation.generation,
            "stale code allocation identity"
        );
    }

    fn allocation_for_domain(&self, domain: AllocationDomain) -> Option<(Allocation, bool)> {
        (0..CODE_POOL_PAGES).find_map(|head| {
            let is_head =
                self.head_for[head] == u16::try_from(head + 1).expect("code-pool head fits u16");
            if !is_head
                || self.owners[head] != domain.owner.get()
                || self.arenas[head] != domain.arena.get()
            {
                return None;
            }
            Some((
                Allocation {
                    head,
                    pages: usize::from(self.run_pages[head]),
                    // Recovery clears the complete page run; the logical word
                    // count is irrelevant after its task is permanently gone.
                    words: 0,
                    generation: self.generations[head],
                },
                self.sealed[head],
            ))
        })
    }

    fn stats(&self) -> CodePoolStats {
        CodePoolStats {
            total_pages: CODE_POOL_PAGES,
            live_pages: self.live_pages,
            sealed_pages: self.sealed_pages,
            peak_pages: self.peak_pages,
            allocations: self.allocations,
            frees: self.frees,
            reuses: self.reuses,
        }
    }
}

static POOL: SpinLock<PoolState> = SpinLock::new(PoolState::new());

#[derive(Clone, Copy)]
struct Allocation {
    head: usize,
    pages: usize,
    words: usize,
    generation: u64,
}

impl Allocation {
    fn start(self) -> usize {
        pool_start() + self.head * PAGE_SIZE
    }

    fn mapped_bytes(self) -> usize {
        self.pages * PAGE_SIZE
    }
}

/// Trusted-linker view of one reserved RW-NX page run.
pub struct WritableCode {
    allocation: Allocation,
    armed: bool,
}

impl WritableCode {
    pub fn allocate(words: usize) -> Result<Self, CodePoolError> {
        if words == 0 {
            return Err(CodePoolError::Empty);
        }
        let bytes = words.checked_mul(4).ok_or(CodePoolError::LengthOverflow)?;
        let pages = bytes.div_ceil(PAGE_SIZE);
        if pages > CODE_POOL_PAGES {
            return Err(CodePoolError::TooLarge);
        }
        assert_eq!(
            pool_end() - pool_start(),
            CODE_POOL_BYTES,
            "linker code-pool size disagrees with Rust"
        );
        let allocation = POOL.lock().reserve(pages, words, heap::current_domain())?;
        // A freshly reserved run is still RW-NX. Zero before exposing its
        // mutable slice, including page padding that the linker will not fill.
        zero_allocation(allocation);
        Ok(Self {
            allocation,
            armed: true,
        })
    }

    pub fn start(&self) -> usize {
        self.allocation.start()
    }

    pub fn words_mut(&mut self) -> &mut [u32] {
        // Safety: the pool allocator owns this entire page run exclusively,
        // its current PTEs are RW-NX, and `&mut self` prevents aliasing.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.allocation.start() as *mut u32,
                self.allocation.words,
            )
        }
    }

    pub fn is_zeroed(&mut self) -> bool {
        self.words_mut().iter().all(|word| *word == 0)
    }

    pub fn seal(mut self) -> ExecutableCode {
        mmu::seal_code(self.allocation.start(), self.allocation.pages);
        POOL.lock().mark_sealed(self.allocation);
        self.armed = false;
        ExecutableCode {
            allocation: self.allocation,
        }
    }
}

impl Drop for WritableCode {
    fn drop(&mut self) {
        if self.armed {
            release_allocation(self.allocation, false);
            self.armed = false;
        }
    }
}

/// Immutable execute-only code. It exposes an entry address, never a byte slice.
pub struct ExecutableCode {
    allocation: Allocation,
}

impl ExecutableCode {
    pub fn entry(&self) -> usize {
        self.allocation.start()
    }

    pub fn byte_len(&self) -> usize {
        self.allocation.words * 4
    }

    pub fn page_count(&self) -> usize {
        self.allocation.pages
    }
}

impl Drop for ExecutableCode {
    fn drop(&mut self) {
        release_allocation(self.allocation, true);
    }
}

pub fn pool_start() -> usize {
    core::ptr::addr_of!(__code_pool_start) as usize
}

pub fn pool_end() -> usize {
    core::ptr::addr_of!(__code_pool_end) as usize
}

pub fn stats() -> CodePoolStats {
    POOL.lock().stats()
}

/// Exercise the actual permission lifecycle and prove page padding is cleared
/// before the same first-fit run is exposed again.
pub fn reuse_zero_probe() -> bool {
    let before = stats().live_pages;
    let mut first = match WritableCode::allocate(PAGE_SIZE / 4) {
        Ok(buffer) => buffer,
        Err(_) => return false,
    };
    let first_start = first.start();
    first.words_mut().fill(0xa5a5_5a5a);
    drop(first.seal());

    let mut second = match WritableCode::allocate(PAGE_SIZE / 4) {
        Ok(buffer) => buffer,
        Err(_) => return false,
    };
    let ok = second.start() == first_start && second.is_zeroed();
    drop(second);
    ok && stats().live_pages == before
}

/// Expected-fatal acceptance probe: execute a valid `ret` instruction while
/// its code-pool page is still writable and explicitly non-executable.
pub fn execute_writable_probe() -> ! {
    let mut code = WritableCode::allocate(1).expect("W^X probe page must allocate");
    code.words_mut()[0] = 0x0000_8067; // ret
    let address = code.start();
    crate::println!("  W^X probe: execute writable {:#x}", address);
    // Safety: this deliberate negative test must take an instruction page
    // fault before the function can return.
    let entry: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
    unsafe { entry() };
    panic!("RW-NX code-pool page executed")
}

/// Reclaim page runs whose tracked allocation domain has reached the executor's
/// audited all-hart quiescence boundary. Longjmp skips Rust Drop, so code-pool
/// storage participates in the same raw arena recovery as heap storage.
///
/// # Safety
///
/// No task in `domain` may still execute or retain a reference to its code.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    assert!(domain.arena.is_tracked());
    loop {
        let Some((allocation, sealed)) = POOL.lock().allocation_for_domain(domain) else {
            break;
        };
        release_allocation(allocation, sealed);
    }
}

fn release_allocation(allocation: Allocation, sealed: bool) {
    if sealed {
        // Rust ownership, or the unsafe recovery quiescence proof, establishes
        // that no hart is still executing this run before execute is removed.
        mmu::unseal_code(allocation.start(), allocation.pages);
    }
    zero_allocation(allocation);
    // Reuse is published only after permissions are RW-NX and every byte in
    // the complete page run, including padding, is zero.
    POOL.lock().release(allocation, sealed);
}

fn zero_allocation(allocation: Allocation) {
    // Safety: callers retain the pool allocation bit, and either the run was
    // never sealed or `unseal_code` completed every local/remote shootdown.
    unsafe { core::ptr::write_bytes(allocation.start() as *mut u8, 0, allocation.mapped_bytes()) };
}
