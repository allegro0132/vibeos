//! Fatal static-image termination. This is not invocation cancellation/reaping.
#[no_mangle]
pub(super) extern "C" fn vibeos_native_fatal_exit(status: i32) -> ! {
    crate::native_tls::require_current();
    crate::println!("NATIVE FATAL EXIT status={} scope=trusted-image recovery=none", status);
    // Stop through the firmware reset interface. Never jump across live C++
    // frames or release their stack/TLS/allocator as if teardown succeeded.
    crate::sbi::shutdown(status != 0)
}
