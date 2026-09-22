//! Process-lifetime backing for trusted C++ arenas, separate from invocations.
use crate::{native_pages::NativePages, sync::SpinLock};
use vibeos_core::heap::{enter_owner, OwnerId};
const PAGE: usize = 4096;
const QUOTA: usize = 64 * 1024 * 1024;
struct Block { pages: NativePages, bytes: usize }
struct Registry { owner: Option<OwnerId>, blocks: [Option<Block>; 128] }
static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry {
    owner: None, blocks: [const { None }; 128],
});

#[no_mangle]
extern "C" fn vibeos_tcb_pages_allocate(bytes: usize) -> *mut u8 {
    crate::native_tls::require_current();
    if bytes == 0 || bytes % PAGE != 0 || bytes > QUOTA { return core::ptr::null_mut(); }
    let mut registry = REGISTRY.lock();
    let Some(index) = registry.blocks.iter().position(Option::is_none) else {
        return core::ptr::null_mut();
    };
    let owner = match registry.owner {
        Some(owner) => owner,
        None => {
            let Ok(owner) = crate::HEAP.create_owner(QUOTA) else { return core::ptr::null_mut(); };
            registry.owner = Some(owner);
            owner
        }
    };
    // This scope never suspends. Both backing and metadata are charged to the
    // permanent TCB account, never to the calling invocation or SYSTEM.
    let _owner = enter_owner(owner);
    let Some(pages) = NativePages::allocate(bytes / PAGE, PAGE) else {
        return core::ptr::null_mut();
    };
    let address = pages.address();
    registry.blocks[index] = Some(Block { pages, bytes });
    address as *mut u8
}

#[no_mangle]
extern "C" fn vibeos_tcb_pages_release(pointer: *mut u8, bytes: usize) -> i32 {
    crate::native_tls::require_current();
    let start = pointer as usize;
    if start == 0 || start % PAGE != 0 || bytes == 0 || bytes % PAGE != 0 { return -1; }
    let Some(end) = start.checked_add(bytes) else { return -1; };
    let mut registry = REGISTRY.lock();
    // Validate full allocation coverage before freeing anything. Adjacent
    // original blocks may have been coalesced by Abseil's arena free list.
    let mut cursor = start;
    while cursor < end {
        let Some(block) = registry.blocks.iter().flatten()
            .find(|block| block.pages.address() == cursor) else { return -1; };
        let Some(next) = cursor.checked_add(block.bytes) else { return -1; };
        if next > end { return -1; }
        cursor = next;
    }
    cursor = start;
    while cursor < end {
        let index = registry.blocks.iter().position(|block|
            block.as_ref().is_some_and(|block| block.pages.address() == cursor)).unwrap();
        let block = registry.blocks[index].take().unwrap();
        cursor += block.bytes;
        drop(block); // Restore allocator access, then release the original Layout.
    }
    0
}

pub(super) fn assert_reclaimed() {
    let registry = REGISTRY.lock();
    assert!(registry.blocks.iter().all(Option::is_none));
    let stats = crate::HEAP.account_stats(registry.owner.expect("TCB probe owner")).unwrap();
    assert_eq!(stats.live_bytes, 0);
    assert_eq!(stats.live_allocations, 0);
    assert!(stats.peak_bytes > 0);
    crate::println!("NATIVE TCB PAGES PASS owned=1 invalid_release=1 double_free=1 reclaimed=1");
}
