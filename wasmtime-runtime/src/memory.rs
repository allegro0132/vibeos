//! Host-owned linear memory for explicit-bounds-check configurations.
use alloc::{alloc::{alloc_zeroed, dealloc}, boxed::Box, string::String};
use core::{alloc::Layout, ptr::NonNull};
use wasmtime::{LinearMemory, MemoryCreator, MemoryType};
const PAGE: usize = 4096;
pub const MEMORY_LIMIT: usize = 16 * 1024 * 1024;

pub struct BoundedMemoryCreator;
struct BoundedMemory {
    base: NonNull<u8>,
    layout: Layout,
    size: usize,
    maximum: usize,
}
// Ownership remains with one Wasmtime memory. Access through its raw pointer is
// governed by Wasmtime's store borrowing rules; shared memories are rejected.
unsafe impl Send for BoundedMemory {}
unsafe impl Sync for BoundedMemory {}
unsafe impl LinearMemory for BoundedMemory {
    fn byte_size(&self) -> usize { self.size }
    fn byte_capacity(&self) -> usize { self.layout.size() }
    fn as_ptr(&self) -> *mut u8 { self.base.as_ptr() }
    fn grow_to(&mut self, new_size: usize) -> wasmtime::Result<()> {
        if new_size < self.size || new_size > self.maximum || new_size % PAGE != 0 {
            return Err(wasmtime::Error::msg("linear memory growth exceeds its bound"));
        }
        if new_size > self.layout.size() {
            let capacity = new_size.next_power_of_two().min(MEMORY_LIMIT);
            let layout = Layout::from_size_align(capacity, PAGE).unwrap();
            let Some(base) = NonNull::new(unsafe { alloc_zeroed(layout) }) else {
                return Err(wasmtime::Error::msg("linear memory growth allocation failed"));
            };
            // Allocate before freeing: failure preserves the old base and size.
            unsafe {
                core::ptr::copy_nonoverlapping(self.base.as_ptr(), base.as_ptr(), self.size);
                dealloc(self.base.as_ptr(), self.layout);
            }
            self.base = base;
            self.layout = layout;
        } else {
            unsafe { self.base.as_ptr().add(self.size).write_bytes(0, new_size - self.size); }
        }
        self.size = new_size;
        Ok(())
    }
}
impl Drop for BoundedMemory {
    fn drop(&mut self) { unsafe { dealloc(self.base.as_ptr(), self.layout); } }
}
unsafe impl MemoryCreator for BoundedMemoryCreator {
    fn new_memory(&self, ty: MemoryType, minimum: usize, maximum: Option<usize>,
        reservation: Option<usize>, guard: usize) -> Result<Box<dyn LinearMemory>, String> {
        if ty.is_shared() || ty.is_64() || guard != 0 || minimum > MEMORY_LIMIT || minimum % PAGE != 0 {
            return Err(String::from("unsupported linear memory configuration"));
        }
        let maximum = maximum.unwrap_or(MEMORY_LIMIT).min(MEMORY_LIMIT);
        // A zero reservation is Wasmtime's movable-memory configuration. A
        // small amount of initial capacity avoids relocating the first growth.
        let capacity = match reservation {
            Some(size) if size != 0 => size,
            _ => minimum.max(PAGE).next_power_of_two().saturating_mul(2).min(MEMORY_LIMIT),
        };
        if minimum > maximum || minimum > capacity || capacity > MEMORY_LIMIT || capacity % PAGE != 0
            || reservation.is_some_and(|size| size != 0 && maximum > capacity) {
            return Err(String::from("linear memory reservation exceeds its bound"));
        }
        let layout = Layout::from_size_align(capacity, PAGE).map_err(|_| String::from("invalid linear memory layout"))?;
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or_else(|| String::from("linear memory allocation failed"))?;
        Ok(Box::new(BoundedMemory { base, layout, size: minimum, maximum }))
    }
}
