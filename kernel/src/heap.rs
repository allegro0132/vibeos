//! Kernel heap: a bump allocator backed by power-of-two size-class free lists.
//!
//! Not a general-purpose malloc. It is O(1) for both paths and good enough for
//! the allocation pattern VibeOS actually has (boxed futures, channel nodes,
//! capability slots) while staying small enough to audit in one sitting.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use crate::sync::SpinLock;

const MIN_CLASS_SHIFT: usize = 4; // 16 bytes
const NUM_CLASSES: usize = 13; // 16 B .. 64 KiB

struct FreeNode {
    next: Option<NonNull<FreeNode>>,
}

struct HeapInner {
    cursor: usize,
    end: usize,
    free: [Option<NonNull<FreeNode>>; NUM_CLASSES],
    live_bytes: usize,
    peak_bytes: usize,
}

unsafe impl Send for HeapInner {}

pub struct Heap(SpinLock<HeapInner>);

impl Heap {
    const fn new() -> Self {
        Heap(SpinLock::new(HeapInner {
            cursor: 0,
            end: 0,
            free: [None; NUM_CLASSES],
            live_bytes: 0,
            peak_bytes: 0,
        }))
    }

    /// # Safety
    /// `start..end` must be a unique, otherwise-unused region of writable RAM.
    pub unsafe fn init(&self, start: usize, end: usize) {
        let mut h = self.0.lock();
        h.cursor = start;
        h.end = end;
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        let h = self.0.lock();
        (h.live_bytes, h.peak_bytes, h.end - h.cursor)
    }
}

/// Size class index for a layout, or `None` if it must come from the bump area.
fn class_of(layout: &Layout) -> Option<usize> {
    if layout.align() > (1 << MIN_CLASS_SHIFT) {
        return None;
    }
    let size = layout.size().max(1 << MIN_CLASS_SHIFT);
    let shift = usize::BITS as usize - (size - 1).leading_zeros() as usize;
    let idx = shift.saturating_sub(MIN_CLASS_SHIFT);
    (idx < NUM_CLASSES).then_some(idx)
}

fn class_size(idx: usize) -> usize {
    1 << (idx + MIN_CLASS_SHIFT)
}

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut h = self.0.lock();
        let cls = class_of(&layout);

        if let Some(idx) = cls {
            if let Some(node) = h.free[idx].take() {
                h.free[idx] = unsafe { node.as_ref().next };
                h.live_bytes += class_size(idx);
                h.peak_bytes = h.peak_bytes.max(h.live_bytes);
                return node.as_ptr().cast();
            }
        }

        let want = cls.map_or(layout.size(), class_size);
        let align = layout.align().max(1 << MIN_CLASS_SHIFT);
        let base = (h.cursor + align - 1) & !(align - 1);
        let next = match base.checked_add(want) {
            Some(n) if n <= h.end => n,
            _ => return ptr::null_mut(),
        };
        h.cursor = next;
        h.live_bytes += want;
        h.peak_bytes = h.peak_bytes.max(h.live_bytes);
        base as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some(idx) = class_of(&layout) else { return };
        let mut h = self.0.lock();
        let node = ptr.cast::<FreeNode>();
        unsafe { node.write(FreeNode { next: h.free[idx] }) };
        h.free[idx] = NonNull::new(node);
        h.live_bytes = h.live_bytes.saturating_sub(class_size(idx));
    }
}

#[global_allocator]
pub static HEAP: Heap = Heap::new();
