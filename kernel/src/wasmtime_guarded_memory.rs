//! One fixed guest VA reservation; only committed pages consume physical RAM.
//! A shared (wasi-threads) memory never relocates: growth appends zeroed
//! chunks at the VA tail while other guest threads keep executing.
use alloc::{alloc::{alloc_zeroed, dealloc}, boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{alloc::Layout, ptr::NonNull, sync::atomic::{AtomicUsize, Ordering}};
use vibeos_wasmtime_runtime::wasmtime::{self, Config, LinearMemory, MemoryCreator, MemoryType};
const PAGE: usize = 4096;
const LIMIT: usize = 16 * 1024 * 1024;
const RESERVATION: usize = 1usize << 32;
const GUARD: usize = 65536;
use vibeos_core::heap::{self, AllocationDomain};
#[derive(Clone, Copy)]
struct Mapping { domain: AllocationDomain, base: usize, size: usize }
// This record never points to a Rust object in the reclaimable arena.
static SLOT: crate::sync::SpinLock<Option<Mapping>> = crate::sync::SpinLock::new(None);
// Admission is private to the fixed memory-only fault fixture below. No full
// Wasmtime Engine/Module task may use this raw-reclaim authorization.
static PROBE_BYTES: AtomicUsize = AtomicUsize::new(usize::MAX);
static PROBE_DOMAIN: crate::sync::SpinLock<Option<AllocationDomain>> = crate::sync::SpinLock::new(None);
pub(super) unsafe fn recover_probe(domain: AllocationDomain) -> bool {
    if *PROBE_DOMAIN.lock() != Some(domain) { return false; }
    let bytes = SLOT.lock().as_ref().filter(|m| m.domain == domain).map_or(0, |m| m.size);
    unsafe { recover(domain); }
    PROBE_BYTES.store(bytes, Ordering::Release);
    *PROBE_DOMAIN.lock() = None;
    true
}
static DROPS: AtomicUsize = AtomicUsize::new(0);
fn replace(old: usize, old_size: usize, new: usize, new_size: usize) {
    let mut slot = SLOT.lock();
    let record = slot.as_mut().expect("guest memory reservation");
    assert_eq!((record.base, record.size), (old, old_size));
    // No allocation or guest execution occurs within this PTE transaction.
    unsafe { crate::mmu::replace_wasm_memory(old, old_size, new, new_size); }
    record.base = new; record.size = new_size;
}
/// The executor has detached all tasks/registrations in this exact domain.
/// Must run before raw arena reclamation; it never invokes guest destructors.
pub(super) unsafe fn recover(domain: AllocationDomain) {
    assert!(domain.arena.is_tracked());
    let mut slot = SLOT.lock();
    let Some(record) = *slot else { return };
    if record.domain != domain { return; }
    if record.size != 0 {
        // Physical chunks are arena bytes; the caller reclaims them raw.
        unsafe { crate::mmu::unmap_wasm_memory(record.size); }
    }
    *slot = None;
}
struct Creator;
struct Memory {
    base: NonNull<u8>,
    layout: Layout,
    size: usize,
    maximum: usize,
    /// Shared memories keep every chunk ever mapped; `base`/`layout` is the
    /// first one. Private memories relocate instead and keep this empty.
    chunks: Option<Vec<(NonNull<u8>, Layout)>>,
}
// A private memory is owned by one store, which excludes concurrent growth
// and access. A shared memory is guarded by Wasmtime's shared-memory write
// lock during growth and never moves, so guest threads on other harts keep
// valid translations; only new pages are published. All harts receive TLB
// invalidations for every mapping change.
unsafe impl Send for Memory {}
unsafe impl Sync for Memory {}
pub(super) fn configure(config: &mut Config) {
    config.memory_reservation(RESERVATION as u64)
        .memory_guard_size(GUARD as u64)
        .memory_may_move(false)
        .memory_reservation_for_growth(0)
        .with_host_memory(Arc::new(Creator));
}
unsafe impl LinearMemory for Memory {
    fn byte_size(&self) -> usize { self.size }
    fn byte_capacity(&self) -> usize { RESERVATION }
    fn as_ptr(&self) -> *mut u8 { crate::mmu::WASM_MEMORY_BASE as *mut u8 }
    fn grow_to(&mut self, size: usize) -> wasmtime::Result<()> {
        if size < self.size || size > self.maximum || size % PAGE != 0 {
            wasmtime::bail!("guest memory limit exceeded");
        }
        if size == self.size { return Ok(()); }
        if let Some(chunks) = self.chunks.as_mut() {
            // Shared: append a zeroed chunk at the tail; nothing relocates.
            let layout = Layout::from_size_align(size - self.size, PAGE).unwrap();
            let chunk = NonNull::new(unsafe { alloc_zeroed(layout) })
                .ok_or_else(|| wasmtime::Error::msg("guest memory allocation failed"))?;
            {
                let mut slot = SLOT.lock();
                let record = slot.as_mut().expect("guest memory reservation");
                assert_eq!(record.size, self.size);
                unsafe { crate::mmu::append_wasm_memory(self.size, chunk.as_ptr() as usize, layout.size()); }
                record.size = size;
            }
            chunks.push((chunk, layout));
            self.size = size;
            return Ok(());
        }
        if size > self.layout.size() {
            let layout = Layout::from_size_align(size.next_power_of_two().min(LIMIT), PAGE).unwrap();
            let base = NonNull::new(unsafe { alloc_zeroed(layout) })
                .ok_or_else(|| wasmtime::Error::msg("guest memory allocation failed"))?;
            unsafe {
                core::ptr::copy_nonoverlapping(self.base.as_ptr(), base.as_ptr(), self.size);
                replace(self.base.as_ptr() as usize, self.size, base.as_ptr() as usize, size);
                dealloc(self.base.as_ptr(), self.layout);
            }
            self.base = base; self.layout = layout;
        } else {
            unsafe {
                self.base.as_ptr().add(self.size).write_bytes(0, size - self.size);
                replace(self.base.as_ptr() as usize, self.size, self.base.as_ptr() as usize, size);
            }
        }
        self.size = size;
        Ok(())
    }
}
impl Drop for Memory {
    fn drop(&mut self) {
        match self.chunks.take() {
            Some(chunks) => unsafe {
                {
                    let mut slot = SLOT.lock();
                    let record = slot.as_mut().expect("guest memory reservation");
                    assert_eq!(record.size, self.size);
                    crate::mmu::unmap_wasm_memory(self.size);
                    record.size = 0;
                }
                dealloc(self.base.as_ptr(), self.layout);
                for (chunk, layout) in chunks { dealloc(chunk.as_ptr(), layout); }
            },
            None => unsafe {
                replace(self.base.as_ptr() as usize, self.size, 0, 0);
                dealloc(self.base.as_ptr(), self.layout);
            },
        }
        *SLOT.lock() = None;
        DROPS.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe impl MemoryCreator for Creator {
    fn new_memory(&self, ty: MemoryType, minimum: usize, maximum: Option<usize>, reservation: Option<usize>, guard: usize)
        -> Result<Box<dyn LinearMemory>, String> {
        let maximum = maximum.unwrap_or(LIMIT).min(LIMIT);
        if ty.is_64() || ty.page_size() != 65536 || minimum > maximum || minimum % PAGE != 0
            || reservation != Some(RESERVATION) || guard != GUARD {
            return Err(String::from("unsupported guarded guest memory"));
        }
        // Admission already requires a declared maximum for shared memories.
        if ty.is_shared() && ty.maximum().is_none() {
            return Err(String::from("shared guest memory requires a maximum"));
        }
        let reserved = {
            let mut slot = SLOT.lock();
            if slot.is_some() { false } else {
                *slot = Some(Mapping { domain: heap::current_domain(), base: 0, size: 0 });
                true
            }
        };
        if !reserved { return Err(String::from("guarded guest memory busy")); }
        // A shared memory commits exactly its initial pages; a private one
        // rounds up so the first growth avoids a relocation.
        let initial = if ty.is_shared() { minimum.max(PAGE) } else { minimum.max(PAGE).next_power_of_two() };
        let layout = Layout::from_size_align(initial, PAGE).unwrap();
        let Some(base) = NonNull::new(unsafe { alloc_zeroed(layout) }) else {
            *SLOT.lock() = None;
            return Err(String::from("guest memory allocation failed"));
        };
        if ty.is_shared() {
            if minimum != 0 {
                let mut slot = SLOT.lock();
                let record = slot.as_mut().expect("guest memory reservation");
                unsafe { crate::mmu::append_wasm_memory(0, base.as_ptr() as usize, minimum); }
                record.base = base.as_ptr() as usize;
                record.size = minimum;
            }
            return Ok(Box::new(Memory { base, layout, size: minimum, maximum, chunks: Some(Vec::new()) }));
        }
        replace(0, 0, base.as_ptr() as usize, minimum);
        Ok(Box::new(Memory { base, layout, size: minimum, maximum, chunks: None }))
    }
}
pub(super) fn assert_idle() {
    assert!(SLOT.lock().is_none());
    for offset in (0..LIMIT).step_by(PAGE) {
        assert!(crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE + offset).is_none());
    }
    for offset in [LIMIT, RESERVATION - 1, RESERVATION, 2 * RESERVATION - 1] {
        assert!(crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE + offset).is_none());
    }
    crate::println!("  WASMTIME GUARDED MEMORY PASS idle=1 unmapped_pages=4096 reserved_gib=8 physical_limit_mib=16");
}

pub(super) fn assert_live(size: usize) {
    use vibeos_core::mmu::PagePermissions;
    assert!(SLOT.lock().is_some());
    for offset in (0..size).step_by(PAGE) {
        let mapping = crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE + offset).unwrap();
        assert!(mapping.permissions.contains(PagePermissions::READ));
        assert!(mapping.permissions.contains(PagePermissions::WRITE));
        assert!(!mapping.permissions.contains(PagePermissions::EXECUTE));
    }
    for offset in [size, LIMIT, RESERVATION - 1, RESERVATION, 2 * RESERVATION - 1] {
        assert!(crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE + offset).is_none());
    }
}

/// Only MemoryCreator objects are admitted here: no Engine, Module, TLS,
/// host callback or code registry reference is created in these child arenas.
pub(super) async fn recovery_selftest() {
    let drops = DROPS.load(Ordering::Relaxed);
    for _ in 0..16 {
        for phase in 0..3 {
            // Page alignment rounds physical backing up in the kernel heap;
            // leave enough room for the initial buffer in the growth-fault case.
            let budget = match phase { 0 => 1024, 1 => 256 * 1024, _ => 1024 * 1024 };
            let owner = crate::HEAP.create_owner(budget).unwrap();
            let arena = crate::HEAP.create_arena(owner).unwrap();
            let domain = AllocationDomain::new(owner, arena);
            { let mut registered = PROBE_DOMAIN.lock(); assert!(registered.is_none()); *registered = Some(domain); }
            PROBE_BYTES.store(usize::MAX, Ordering::Release);
            // The sole external publication is SLOT's copied domain/address
            // record; recover() removes it before the executor frees this arena.
            let child = unsafe { crate::exec::spawn_reclaimable_owned(domain, "wasmtime-memory-fault", async move {
                let mut memory = Creator.new_memory(MemoryType::new(1, Some(4)), 65536,
                    Some(4 * 65536), Some(RESERVATION), GUARD).unwrap();
                memory.grow_to(3 * 65536).unwrap();
                assert_eq!(phase, 2);
                panic!("deliberate fault after guarded memory growth");
            }) };
            assert_eq!(child.join().await.state(), crate::exec::TaskState::Faulted);
            assert_eq!(PROBE_BYTES.load(Ordering::Acquire), [0, 65536, 3 * 65536][phase], "fault reached the wrong allocation stage");
            let stats = crate::HEAP.account_stats(owner).unwrap();
            assert_eq!(stats.live_bytes, 0);
            assert_eq!(stats.denials != 0, phase != 2);
            assert!(crate::HEAP.arena_stats(arena).is_none());
            assert!(SLOT.lock().is_none());
            for page in 0..3 { assert!(crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE + page * 65536).is_none()); }
            assert_eq!(DROPS.load(Ordering::Relaxed), drops, "raw recovery invoked a destructor");
            crate::HEAP.unregister_owner(owner).unwrap();
            drop(child);
        }
    }
    crate::println!("  WASMTIME MEMORY RECOVERY PASS faults=48 allocation=16 growth=16 mapped=16 drops=0 live=0");
}
