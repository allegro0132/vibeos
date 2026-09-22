//! Bounded process-lifetime newlib heap. Its allocator globals persist across
//! invocations, so the backing must not belong to an invocation's page pool.
use crate::{native_pages::NativePages, sync::SpinLock};
use vibeos_core::heap::{enter_owner, OwnerId};
const PAGE: usize = 4096;
const CAPACITY: usize = 16 * 1024 * 1024;
const QUOTA: usize = CAPACITY * 4;
struct Heap { owner: Option<OwnerId>, pages: Option<NativePages>, offset: usize }
static HEAP: SpinLock<Heap> = SpinLock::new(Heap { owner: None, pages: None, offset: 0 });

#[no_mangle]
extern "C" fn vibeos_native_sbrk(increment: isize) -> *mut u8 {
    crate::native_tls::require_current();
    let failure = usize::MAX as *mut u8;
    let mut heap = HEAP.lock();
    let Some(next) = heap.offset.checked_add_signed(increment) else { return failure; };
    if next > CAPACITY { return failure; }
    if heap.pages.is_none() {
        let owner = match heap.owner {
            Some(owner) => owner,
            None => {
                let Ok(owner) = crate::HEAP.create_owner(QUOTA) else { return failure; };
                heap.owner = Some(owner);
                owner
            }
        };
        let _scope = enter_owner(owner); // No suspension while allocator lock is held.
        let Some(pages) = NativePages::allocate(CAPACITY / PAGE, PAGE) else { return failure; };
        heap.pages = Some(pages);
    }
    let base = heap.pages.as_ref().unwrap().address();
    let previous = heap.offset;
    if next > previous {
        // Restoring a trimmed range must not expose the old contents.
        unsafe { core::ptr::write_bytes((base + previous) as *mut u8, 0, next - previous); }
    }
    heap.offset = next;
    (base + previous) as *mut u8
}

// Runs only in the fixture image, before any newlib allocator is linked/used.
pub(super) extern "C" fn probe(_: usize) -> usize {
    let base = vibeos_native_sbrk(0);
    assert_ne!(base as usize, usize::MAX);
    assert_eq!(vibeos_native_sbrk(-1) as usize, usize::MAX);
    assert_eq!(vibeos_native_sbrk(isize::MAX) as usize, usize::MAX);
    assert_eq!(vibeos_native_sbrk(isize::MIN) as usize, usize::MAX);
    assert_eq!(vibeos_native_sbrk(PAGE as isize), base);
    unsafe { base.write(0xa5); }
    assert_eq!(vibeos_native_sbrk(-(PAGE as isize)), base.wrapping_add(PAGE));
    assert_eq!(vibeos_native_sbrk(CAPACITY as isize), base);
    assert_eq!(unsafe { base.read() }, 0);
    assert_eq!(vibeos_native_sbrk(1) as usize, usize::MAX);
    assert_eq!(vibeos_native_sbrk(0), base.wrapping_add(CAPACITY));
    assert_eq!(vibeos_native_sbrk(-(CAPACITY as isize)), base.wrapping_add(CAPACITY));
    assert_eq!(vibeos_native_sbrk(0), base);
    for offset in (0..CAPACITY).step_by(PAGE) {
        assert_eq!(crate::mmu::mapping(base as usize + offset).unwrap().permissions,
                   vibeos_core::mmu::PagePermissions::READ.union(vibeos_core::mmu::PagePermissions::WRITE));
    }
    let heap = HEAP.lock();
    let stats = crate::HEAP.account_stats(heap.owner.unwrap()).unwrap();
    assert!(stats.live_bytes >= CAPACITY && stats.live_bytes <= QUOTA);
    crate::println!("NATIVE LIBC HEAP PASS bounded=1 overflow=1 trim=1 zero=1 nx=1 tcb_accounted=1 retained_bytes={}", stats.live_bytes);
    42
}
