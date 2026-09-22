//! Native clock ABI shares the RTC latch lock with WASI.
fn read(clock: u32) -> i64 {
    crate::native_tls::require_current();
    crate::wasi_clock::time(clock, 0)
        .ok()
        .and_then(|ns| i64::try_from(ns / 1_000).ok())
        .unwrap_or(-1)
}
#[no_mangle]
extern "C" fn vibeos_native_realtime_us() -> i64 { read(0) }
#[no_mangle]
extern "C" fn vibeos_native_monotonic_us() -> i64 { read(1) }
