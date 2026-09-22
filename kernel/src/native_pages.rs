//! Owned, eagerly backed native data pages. C ABI handle admission is separate.
use alloc::{alloc::{alloc_zeroed, dealloc}, vec::Vec};
use core::alloc::Layout;
use crate::mmu::{NativeDataError as Error, NativeDataPermission as Permission};
const PAGE: usize = 4096;

pub(super) struct NativePages {
    address: usize,
    layout: Layout,
    permissions: Vec<Permission>,
}
impl NativePages {
    pub(super) fn allocate(pages: usize, alignment: usize) -> Option<Self> {
        if pages == 0 || alignment < PAGE || !alignment.is_power_of_two() { return None; }
        if crate::platform::mmu().ram_granularity != vibeos_hal::MappingGranularity::Page4K
            || !crate::mmu::local_paging_enabled() { return None; }
        let size = pages.checked_mul(PAGE)?;
        let layout = Layout::from_size_align(size, alignment).ok()?;
        let mut permissions = Vec::new();
        permissions.try_reserve_exact(pages).ok()?;
        permissions.resize(pages, Permission::ReadWrite);
        let address = unsafe { alloc_zeroed(layout) } as usize;
        if address == 0 { return None; }
        Some(Self { address, layout, permissions })
    }
    pub(super) fn address(&self) -> usize { self.address }
    /// Caller must exclude all raw-pointer users while permissions change.
    pub(super) unsafe fn protect(&mut self, offset: usize, pages: usize,
                                 target: Permission) -> Result<(), Error> {
        let end = offset.checked_add(pages).ok_or(Error::InvalidRange)?;
        if pages == 0 || end > self.permissions.len() { return Err(Error::InvalidRange); }
        unsafe {
            crate::mmu::protect_native_data(self.address + offset * PAGE,
                                           &self.permissions[offset..end], target)?;
        }
        self.permissions[offset..end].fill(target);
        Ok(())
    }
    /// Caller must exclude all raw-pointer users while contents are discarded.
    /// Discard preserves permissions; decommit removes access until protect().
    pub(super) unsafe fn clear(&mut self, offset: usize, pages: usize,
                               decommit: bool) -> Result<(), Error> {
        let end = offset.checked_add(pages).ok_or(Error::InvalidRange)?;
        if pages == 0 || end > self.permissions.len() { return Err(Error::InvalidRange); }
        unsafe {
            crate::mmu::clear_native_data(self.address + offset * PAGE,
                                         &self.permissions[offset..end], decommit)?;
        }
        if decommit { self.permissions[offset..end].fill(Permission::Inaccessible); }
        Ok(())
    }
}
impl Drop for NativePages {
    fn drop(&mut self) {
        // The object must outlive every native pointer. Restore allocator
        // access before it writes free-list metadata into the returned block.
        unsafe {
            crate::mmu::protect_native_data(self.address, &self.permissions,
                                            Permission::ReadWrite)
                .expect("native page ownership/PTE mismatch during destruction");
            dealloc(self.address as *mut u8, self.layout);
        }
    }
}

#[cfg(feature = "native-cxx-probe")]
pub(super) fn probe() {
    use vibeos_core::mmu::PagePermissions as P;
    let mut pages = NativePages::allocate(8, 8 * PAGE).expect("native page probe allocation");
    let base = pages.address();
    assert_eq!(base % (8 * PAGE), 0);
    for offset in 0..8 * PAGE {
        assert_eq!(unsafe { *((base + offset) as *const u8) }, 0);
    }
    unsafe { (base as *mut u8).write(0xa5); }
    unsafe { pages.protect(0, 2, Permission::ReadOnly).unwrap(); }
    assert_eq!(unsafe { (base as *const u8).read() }, 0xa5);
    for index in 0..2 {
        let mapping = crate::mmu::mapping(base + index * PAGE).unwrap();
        assert_eq!(mapping.permissions, P::READ);
    }
    unsafe { pages.protect(2, 2, Permission::Inaccessible).unwrap(); }
    assert!(crate::mmu::mapping(base + 2 * PAGE).is_none());
    assert!(crate::mmu::mapping(base + 3 * PAGE).is_none());
    // A mismatched page later in the range must reject the whole operation.
    let wrong = [Permission::ReadOnly; 4];
    assert_eq!(unsafe { crate::mmu::protect_native_data(base, &wrong, Permission::ReadWrite) },
               Err(Error::PermissionMismatch));
    assert_eq!(crate::mmu::mapping(base).unwrap().permissions, P::READ);
    assert!(crate::mmu::mapping(base + 2 * PAGE).is_none());
    assert_eq!(unsafe { pages.protect(7, 2, Permission::ReadOnly) }, Err(Error::InvalidRange));
    assert_eq!(unsafe { pages.protect(usize::MAX, 1, Permission::ReadOnly) }, Err(Error::InvalidRange));
    unsafe { pages.protect(0, 8, Permission::ReadWrite).unwrap(); }
    for index in 0..8 {
        let mapping = crate::mmu::mapping(base + index * PAGE).unwrap();
        assert_eq!(mapping.permissions, P::READ.union(P::WRITE));
        assert!(!mapping.permissions.contains(P::EXECUTE));
    }
    unsafe { (base as *mut u8).write(0x5a); }
    assert_eq!(unsafe { (base as *const u8).read() }, 0x5a);
    // Discard a mixed range. Validate before mutation and preserve neighbors.
    unsafe { (base as *mut u8).write_bytes(0xa7, 8 * PAGE); }
    unsafe { pages.protect(1, 1, Permission::ReadOnly).unwrap(); }
    unsafe { pages.protect(2, 1, Permission::Inaccessible).unwrap(); }
    let wrong = [Permission::ReadOnly; 2];
    assert_eq!(unsafe { crate::mmu::clear_native_data(base + PAGE, &wrong, false) },
               Err(Error::PermissionMismatch));
    assert_eq!(unsafe { ((base + PAGE) as *const u8).read() }, 0xa7);
    assert_eq!(unsafe { pages.clear(7, 2, false) }, Err(Error::InvalidRange));
    assert_eq!(unsafe { pages.clear(usize::MAX, 1, true) }, Err(Error::InvalidRange));
    unsafe { pages.clear(1, 3, false).unwrap(); }
    assert_eq!(crate::mmu::mapping(base + PAGE).unwrap().permissions, P::READ);
    assert!(crate::mmu::mapping(base + 2 * PAGE).is_none());
    assert_eq!(crate::mmu::mapping(base + 3 * PAGE).unwrap().permissions,
               P::READ.union(P::WRITE));
    unsafe { pages.protect(1, 3, Permission::ReadWrite).unwrap(); }
    for offset in 0..8 * PAGE {
        let expected = if (PAGE..4 * PAGE).contains(&offset) { 0 } else { 0xa7 };
        assert_eq!(unsafe { ((base + offset) as *const u8).read() }, expected);
    }
    // Decommit dirty pages; recommit must expose zeros rather than old bytes.
    unsafe { pages.clear(4, 3, true).unwrap(); }
    for index in 4..7 { assert!(crate::mmu::mapping(base + index * PAGE).is_none()); }
    unsafe { pages.protect(4, 3, Permission::ReadOnly).unwrap(); }
    for offset in 4 * PAGE..7 * PAGE {
        assert_eq!(unsafe { ((base + offset) as *const u8).read() }, 0);
    }
    assert_eq!(unsafe { (base as *const u8).read() }, 0xa7);
    assert_eq!(unsafe { ((base + 7 * PAGE) as *const u8).read() }, 0xa7);
    // Destruction must restore mixed RO/inaccessible pages before deallocation.
    unsafe { pages.protect(0, 1, Permission::ReadOnly).unwrap(); }
    unsafe { pages.protect(1, 1, Permission::Inaccessible).unwrap(); }
    drop(pages);
    for index in 0..8 {
        assert_eq!(crate::mmu::mapping(base + index * PAGE).unwrap().permissions,
                   P::READ.union(P::WRITE));
    }
    crate::println!("NATIVE PAGES PASS zero=1 align=1 ro=1 none=1 nx=1 atomic_reject=1 restored=1 discard=1 decommit=1");
}
