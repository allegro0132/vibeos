//! Embedder-owned code registry. No global arena-allocated collection.
use super::*;
unsafe extern "C" {
    /// On success retains ownership of this one strong reference until removal.
    fn wasmtime_code_register(start: usize, end: usize, code: *const u8) -> i32;
    /// Under the registry lock, retain must be called before returning a match.
    fn wasmtime_code_lookup(pc: usize, retain: unsafe extern "C" fn(*const u8), offset: &mut usize) -> *const u8;
    /// Removes the exact range and transfers its owned reference back to Rust.
    fn wasmtime_code_unregister(start: usize, end: usize) -> *const u8;
}
unsafe extern "C" fn retain(code: *const u8) {
    unsafe { Arc::<CodeMemory>::increment_strong_count(code.cast()); }
}
pub fn lookup_code(pc: usize) -> Option<(Arc<CodeMemory>, usize)> {
    let mut offset = 0;
    let code = unsafe { wasmtime_code_lookup(pc, retain, &mut offset) };
    if code.is_null() { None } else {
        // lookup retained this reference while removal was excluded by its lock.
        Some((unsafe { Arc::from_raw(code.cast::<CodeMemory>()) }, offset))
    }
}
pub fn register_code(image: &Arc<CodeMemory>, address: Range<usize>) -> Result<(), OutOfMemory> {
    if address.is_empty() { return Ok(()); }
    let code = Arc::into_raw(image.clone());
    if unsafe { wasmtime_code_register(address.start, address.end, code.cast()) } != 0 {
        unsafe { drop(Arc::from_raw(code)); }
        return Err(OutOfMemory::new(core::mem::size_of::<(usize, usize, usize)>()));
    }
    Ok(())
}
pub fn unregister_code(address: Range<usize>) {
    if address.is_empty() { return; }
    let code = unsafe { wasmtime_code_unregister(address.start, address.end) };
    assert!(!code.is_null(), "unregistered code range");
    // The embedder released its lock; destruction may call platform unmapping.
    unsafe { drop(Arc::from_raw(code.cast::<CodeMemory>())); }
}
