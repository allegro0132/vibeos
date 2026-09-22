//! Native callbacks are evaluated on the native stack; only Rust futures are
//! polled by the kernel while that stack is parked.
use core::{ffi::c_void, future::{Future, poll_fn}, task::Poll};
fn now() -> Option<u64> { crate::wasi_clock::time(1, 0).ok().map(|ns| ns / 1000) }
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_wait_until_context(
    key: *mut c_void, ready: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    context: *mut c_void, timeout_us: i64,
) -> i32 {
    let Some(ready) = ready else { return -1; };
    if timeout_us < -1 { return -1; }
    let Some(admission) = crate::native_tls::admit_wait(key as usize) else { return -1; };
    let deadline = if timeout_us >= 0 {
        let Some(deadline) = now().and_then(|n| n.checked_add(timeout_us as u64)) else { return -1; };
        Some(deadline)
    } else { None };
    loop {
        let Some(listener) = admission.notify.listen() else { return -1; };
        // Register before checking; producer writes precede its notification.
        if unsafe { ready(context) } != 0 { return 1; }
        let remaining = match deadline {
            Some(deadline) => {
                let Some(now) = now() else { return -1; };
                if now >= deadline { return 0; }
                Some(deadline - now)
            }
            None => None,
        };
        let waited = crate::native_tls::park(async move {
            if let Some(micros) = remaining {
                let mut listener = core::pin::pin!(listener);
                let mut timer = core::pin::pin!(crate::exec::sleep_ms(micros.div_ceil(1000)));
                poll_fn(|cx| {
                    if listener.as_mut().poll(cx).is_ready() || timer.as_mut().poll(cx).is_ready() {
                        Poll::Ready(())
                    } else { Poll::Pending }
                }).await;
            } else { listener.await; }
        });
        if !waited { return -1; }
        // Readiness and the original deadline are rechecked after every wake.
    }
}
#[no_mangle]
unsafe extern "C" fn vibeos_native_wait_until(
    key: *mut c_void, ready: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
) -> i32 {
    match unsafe { vibeos_native_wait_until_context(key, ready, key, -1) } {
        1 => 0,
        _ => -1,
    }
}
#[no_mangle]
extern "C" fn vibeos_native_wake_all(key: *mut c_void) {
    crate::native_tls::wake_key(key as usize);
}
