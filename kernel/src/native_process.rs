//! Invocation-local process metadata and fatal static-image termination.
#[no_mangle]
pub(super) extern "C" fn vibeos_native_fatal_exit(status: i32) -> ! {
    crate::native_tls::require_current();
    crate::println!("NATIVE FATAL EXIT status={} scope=trusted-image recovery=none", status);
    crate::native_tls::print_native_backtrace();
    // Stop through the firmware reset interface. Never jump across live C++
    // frames or release their stack/TLS/allocator as if teardown succeeded.
    crate::sbi::shutdown(status != 0)
}


pub(super) struct ProcessMetadata { title: alloc::vec::Vec<u8> }
impl ProcessMetadata {
    pub(super) fn new() -> Self { Self { title: alloc::vec::Vec::new() } }
    pub(super) fn set_title(&mut self, title: &[u8]) -> Result<(), i32> {
        if title.len() > 4096 { return Err(-20); }
        if title.contains(&0) { return Err(-9); }
        // Allocate before publishing; failure preserves the old title.
        let mut replacement = alloc::vec::Vec::new();
        replacement.try_reserve_exact(title.len()).map_err(|_| -16)?;
        replacement.extend_from_slice(title);
        self.title = replacement;
        Ok(())
    }
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_set_title(title: *const u8, length: usize) -> i32 {
    if title.is_null() { return -9; }
    if length > 4096 { return -20; }
    let title = unsafe { core::slice::from_raw_parts(title, length) };
    crate::native_tls::with_process(|process| process.set_title(title).map_or_else(|e| e, |_| 0))
}
// Returns length excluding NUL. Short output remains untouched (-21).
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_get_title(output: *mut u8, capacity: usize) -> isize {
    if output.is_null() || capacity == 0 { return -9; }
    crate::native_tls::with_process(|process| {
        let length = process.title.len();
        if capacity <= length { return -21; }
        unsafe {
            core::ptr::copy_nonoverlapping(process.title.as_ptr(), output, length);
            output.add(length).write(0);
        }
        length as isize
    })
}

// Static image metadata, never the build host's uname or environment.
#[no_mangle]
pub(super) extern "C" fn vibeos_native_system_label(field: u32) -> *const u8 {
    crate::native_tls::require_current();
    let label: &[u8] = match field {
        0 => b"VibeOS\0",
        1 => concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes(),
        2 => concat!("VibeOS kernel ", env!("CARGO_PKG_VERSION"), "\0").as_bytes(),
        3 => b"riscv64\0",
        _ => return core::ptr::null(),
    };
    label.as_ptr()
}

// Called by V8 bytecode budget interrupts on the retained native stack.
// Suspend normally so same-hart shell/cancellation tasks can run. Never call
// V8 from the scheduler or unwind/drop parked C++ frames.
#[no_mangle]
pub(super) extern "C" fn vibeos_native_checkpoint() -> i32 {
    crate::native_tls::require_current();
    if !crate::native_tls::park(crate::exec::yield_now()) { return -1; }
    match crate::native_tls::stdio_grant() {
        Some(grant) if grant.cancelled() => 1,
        _ => 0,
    }
}

#[no_mangle]
pub(super) extern "C" fn vibeos_native_is_cancelled() -> i32 {
    crate::native_tls::require_current();
    i32::from(crate::native_tls::stdio_grant().is_some_and(|grant| grant.cancelled()))
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_external_ready() -> i32 {
    crate::native_tls::require_current();
    #[cfg(feature = "node-toolkit")]
    { return i32::from(crate::native_esbuild::ready()); }
    #[cfg(not(feature = "node-toolkit"))]
    0
}
