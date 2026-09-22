//! Address-stable native page suballocations. Released ranges return to this
//! owned pool immediately; its backing allocation is reclaimed on pool drop.
use alloc::vec::Vec;
use crate::{native_pages::NativePages, mmu::NativeDataPermission as Permission};
const PAGE: usize = 4096;
pub(super) struct NativePagePool {
    backing: NativePages,
    allocations: Vec<u64>,
    next_id: u64,
}
impl NativePagePool {
    pub(super) fn new(pages: usize, alignment: usize) -> Option<Self> {
        let mut allocations = Vec::new();
        allocations.try_reserve_exact(pages).ok()?;
        allocations.resize(pages, 0);
        let mut backing = NativePages::allocate(pages, alignment)?;
        unsafe { backing.protect(0, pages, Permission::Inaccessible).ok()?; }
        Some(Self { backing, allocations, next_id: 1 })
    }
    pub(super) fn allocate(&mut self, pages: usize, alignment: usize,
                           permission: Permission) -> Option<usize> {
        if pages == 0 || pages > self.allocations.len() || alignment < PAGE ||
            !alignment.is_power_of_two() { return None; }
        let next = self.next_id.checked_add(1)?;
        let index = (0..=self.allocations.len() - pages).find(|&index| {
            (self.backing.address() + index * PAGE) % alignment == 0 &&
                self.allocations[index..index + pages].iter().all(|id| *id == 0)
        })?;
        // Free pages were zeroed before being returned to the pool. Initial
        // backing is alloc_zeroed. No stale data appears on recommit/reuse.
        unsafe { self.backing.protect(index, pages, permission).ok()?; }
        self.allocations[index..index + pages].fill(self.next_id);
        self.next_id = next;
        Some(self.backing.address() + index * PAGE)
    }
    fn range(&self, address: usize, bytes: usize) -> Option<(usize, usize)> {
        if bytes == 0 || bytes % PAGE != 0 || address % PAGE != 0 { return None; }
        let offset = address.checked_sub(self.backing.address())? / PAGE;
        let end = offset.checked_add(bytes / PAGE)?;
        if end > self.allocations.len() { return None; }
        let id = *self.allocations.get(offset)?;
        if id == 0 || !self.allocations[offset..end].iter().all(|item| *item == id) {
            return None;
        }
        Some((offset, end))
    }
    /// Native pointer users must be stopped while mutating mappings.
    pub(super) unsafe fn release(&mut self, address: usize, bytes: usize) -> bool {
        let Some((start, end)) = self.range(address, bytes) else { return false; };
        if unsafe { self.backing.clear(start, end - start, true) }.is_err() { return false; }
        self.allocations[start..end].fill(0);
        true
    }
    pub(super) unsafe fn protect(&mut self, address: usize, bytes: usize,
                                 permission: Permission) -> bool {
        let Some((start, end)) = self.range(address, bytes) else { return false; };
        unsafe { self.backing.protect(start, end - start, permission) }.is_ok()
    }
    pub(super) unsafe fn clear(&mut self, address: usize, bytes: usize,
                               decommit: bool) -> bool {
        let Some((start, end)) = self.range(address, bytes) else { return false; };
        unsafe { self.backing.clear(start, end - start, decommit) }.is_ok()
    }
}

#[cfg(feature = "native-cxx-probe")]
pub(super) fn probe() {
    let mut pool = NativePagePool::new(8, 8 * PAGE).expect("native page pool");
    let base = pool.allocate(4, 4 * PAGE, Permission::ReadWrite).unwrap();
    unsafe { (base as *mut u8).write_bytes(0xa5, 4 * PAGE); }
    let tail = base + 2 * PAGE;
    assert!(unsafe { pool.release(tail, 2 * PAGE) });
    assert!(crate::mmu::mapping(tail).is_none());
    assert!(!unsafe { pool.release(tail, 2 * PAGE) });
    assert!(!unsafe { pool.protect(tail, PAGE, Permission::ReadWrite) });
    let reused = pool.allocate(2, PAGE, Permission::ReadWrite).unwrap();
    assert_eq!(reused, tail, "tail must become immediately reusable without moving prefix");
    for offset in 0..2 * PAGE {
        assert_eq!(unsafe { ((base + offset) as *const u8).read() }, 0xa5);
        assert_eq!(unsafe { ((reused + offset) as *const u8).read() }, 0);
    }
    // A contiguous range crossing two live allocation identities is rejected.
    assert!(!unsafe { pool.release(base, 4 * PAGE) });
    assert_eq!(unsafe { (base as *const u8).read() }, 0xa5);
    assert!(!unsafe { pool.release(usize::MAX, PAGE) });
    assert!(unsafe { pool.clear(base, 2 * PAGE, true) });
    assert!(unsafe { pool.protect(base, 2 * PAGE, Permission::ReadOnly) });
    assert_eq!(unsafe { (base as *const u8).read() }, 0);
    assert!(unsafe { pool.release(base, 2 * PAGE) });
    assert!(unsafe { pool.release(reused, 2 * PAGE) });
    assert!(pool.allocations.iter().all(|id| *id == 0));
    drop(pool);
    crate::println!("NATIVE PAGE POOL PASS tail_reuse=1 prefix_stable=1 zero=1 ownership=1 reclaimed=1");
}
