//! Per-native-context page admission and accounting. No ambient kernel pages
//! can be reached through this ABI; static V8 image freezing is separate.
use crate::{native_page_pool::NativePagePool, mmu::NativeDataPermission as Permission};
use vibeos_core::heap::{enter_owner, OwnerId};
const PAGE: usize = 4096;
pub(super) struct NativeMemory {
    pool: Option<NativePagePool>,
    owner: Option<OwnerId>,
    capacity: usize,
    revoked: bool,
}
impl NativeMemory {
    pub(super) fn new(capacity: usize) -> Self {
        assert!(capacity != 0 && capacity % PAGE == 0);
        assert!(capacity.checked_mul(4).is_some());
        Self { pool: None, owner: None, capacity, revoked: false }
    }
    pub(super) fn revoke(&mut self) { self.revoked = true; }
    fn allocate(&mut self, size: usize, alignment: usize, permission: i32) -> *mut u8 {
        let Some(permission) = permission_from_abi(permission) else { return core::ptr::null_mut(); };
        if self.revoked || size == 0 || size % PAGE != 0 || size > self.capacity ||
            alignment < PAGE || !alignment.is_power_of_two() || alignment > self.capacity {
            return core::ptr::null_mut();
        }
        if self.pool.is_none() {
            let owner = match self.owner {
                Some(owner) => owner,
                None => {
                    // Heap accounting includes size-class rounding, alignment,
                    // headers and page metadata, not just client-visible bytes.
                    let Ok(owner) = crate::HEAP.create_owner(self.capacity * 4) else {
                        return core::ptr::null_mut();
                    };
                    self.owner = Some(owner);
                    owner
                }
            };
            let _scope = enter_owner(owner); // Never held across suspension.
            self.pool = NativePagePool::new(self.capacity / PAGE, PAGE);
        }
        self.pool.as_mut().and_then(|pool| pool.allocate(size / PAGE, alignment, permission))
            .map_or(core::ptr::null_mut(), |address| address as *mut u8)
    }
    fn operation(&mut self, address: usize, size: usize,
                 action: impl FnOnce(&mut NativePagePool, usize, usize) -> bool) -> i32 {
        if self.revoked { return -1; }
        match self.pool.as_mut() {
            Some(pool) => if action(pool, address, size) { 0 } else { -1 },
            None => -1,
        }
    }
}
impl Drop for NativeMemory {
    fn drop(&mut self) {
        drop(self.pool.take());
        if let Some(owner) = self.owner.take() {
            let stats = crate::HEAP.account_stats(owner).expect("native memory owner");
            assert_eq!(stats.live_bytes, 0);
            assert_eq!(stats.live_allocations, 0);
            crate::HEAP.unregister_owner(owner).expect("native memory owner teardown");
        }
    }
}
fn permission_from_abi(permission: i32) -> Option<Permission> {
    match permission {
        0 => Some(Permission::Inaccessible),
        1 => Some(Permission::ReadOnly),
        2 => Some(Permission::ReadWrite),
        _ => None,
    }
}
#[no_mangle]
extern "C" fn vibeos_native_pages_allocate(_hint: *mut u8, size: usize,
                                          alignment: usize, permission: i32) -> *mut u8 {
    crate::native_tls::with_memory(|memory| memory.allocate(size, alignment, permission))
}
#[no_mangle]
extern "C" fn vibeos_native_pages_release(address: *mut u8, size: usize) -> i32 {
    crate::native_tls::with_memory(|m| m.operation(address as usize, size,
        |pool, address, size| unsafe { pool.release(address, size) }))
}
#[no_mangle]
extern "C" fn vibeos_native_pages_protect(address: *mut u8, size: usize, permission: i32) -> i32 {
    let Some(permission) = permission_from_abi(permission) else { return -1; };
    crate::native_tls::with_memory(|m| m.operation(address as usize, size,
        |pool, address, size| unsafe { pool.protect(address, size, permission) }))
}
fn clear(address: *mut u8, size: usize, decommit: bool) -> i32 {
    crate::native_tls::with_memory(|m| m.operation(address as usize, size,
        |pool, address, size| unsafe { pool.clear(address, size, decommit) }))
}
#[no_mangle]
extern "C" fn vibeos_native_pages_discard(address: *mut u8, size: usize) -> i32 {
    clear(address, size, false)
}
#[no_mangle]
extern "C" fn vibeos_native_pages_decommit(address: *mut u8, size: usize) -> i32 {
    clear(address, size, true)
}
// Placement is deterministic first-fit within the admitted pool. Hints are
// optional and do not provide entropy or permit arbitrary-address mappings.
#[no_mangle]
extern "C" fn vibeos_native_page_hint_seed(_seed: i64) { crate::native_tls::require_current(); }
#[no_mangle]
extern "C" fn vibeos_native_page_hint() -> *mut u8 {
    crate::native_tls::require_current();
    core::ptr::null_mut()
}

#[no_mangle]
extern "C" fn vibeos_native_static_readonly(address: *mut u8, size: usize) -> i32 {
    crate::native_tls::require_current();
    if crate::mmu::freeze_native_flags(address as usize, size).is_ok() { 0 } else { -1 }
}

// Probe-only image. A production V8 image must contain only its actual flag
// object in this section, and must not enable this C++ fixture feature.
#[repr(align(4096))]
struct FlagProbe([u8; 4096]);
#[cfg(not(feature = "node-runtime"))]
#[used]
#[link_section = ".vibeos_v8_flags"]
static mut FLAG_PROBE: FlagProbe = FlagProbe([0x5a; 4096]);

#[cfg(not(feature = "node-runtime"))]
pub(super) extern "C" fn flag_probe(_: usize) -> usize {
    let address = core::ptr::addr_of_mut!(FLAG_PROBE).cast::<u8>();
    assert_eq!(vibeos_native_static_readonly(address, 8192), -1);
    assert_eq!(vibeos_native_static_readonly(address.wrapping_add(4096), 4096), -1);
    assert_eq!(vibeos_native_static_readonly(address, 4096), 0);
    assert_eq!(vibeos_native_static_readonly(address, 4096), 0);
    assert_eq!(crate::mmu::mapping(address as usize).unwrap().permissions,
               vibeos_core::mmu::PagePermissions::READ);
    assert_eq!(unsafe { address.read() }, 0x5a);
    assert_eq!(vibeos_native_pages_protect(address, 4096, 2), -1);
    assert_eq!(vibeos_native_pages_release(address, 4096), -1);
    crate::println!("NATIVE FLAGS PASS exact_range=1 readonly=1 nx=1 no_heap_thaw=1");
    42
}
