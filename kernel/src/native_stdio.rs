//! Explicit native standard-stream grant. Transport is shared with WASI, but
//! no WASI guest or interpreter is involved in native read/write execution.
use alloc::sync::Arc;
use core::{future::poll_fn, sync::atomic::{AtomicU8, Ordering}};
use vibeos_wasi_command::{CommandIo, GuestIo};
use vibeos_wasi_runtime::{WasiIo, WasiIoError, IO_CHUNK};

#[derive(Clone)]
pub(super) struct StdioGrant { io: Arc<CommandIo>, closed: Arc<AtomicU8> }
impl StdioGrant {
    // Trusted launcher admission only. No ambient console fallback.
    pub(super) fn new(io: Arc<CommandIo>) -> Self {
        Self { io, closed: Arc::new(AtomicU8::new(0)) }
    }
    fn open(&self, fd: i32) -> bool {
        (0..=2).contains(&fd) && self.closed.load(Ordering::Acquire) & (1 << fd) == 0
    }
}
fn error(error: WasiIoError) -> isize {
    match error { WasiIoError::Denied => -3, WasiIoError::Closed => -4, WasiIoError::Failed => -5 }
}
// Negative ABI results: bad descriptor=-1, invalid pointer=-2, denied=-3,
// closed pipe=-4, transport/runner failure=-5. Positive results allow short IO.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_write(fd: i32, input: *const u8, length: usize) -> isize {
    if fd >= 3 {
        let kind = crate::native_files::kind(fd);
        return if kind < 0 { kind as isize } else { -1 };
    }
    let Some(grant) = crate::native_tls::stdio_grant() else { return -3; };
    if (fd != 1 && fd != 2) || !grant.open(fd) { return -1; }
    if input.is_null() && length != 0 { return -2; }
    let count = length.min(IO_CHUNK);
    let mut bytes = [0u8; IO_CHUNK];
    if count != 0 { unsafe { core::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), count); } }
    let mut result = Err(WasiIoError::Failed);
    if !crate::native_tls::park(async {
        result = poll_fn(|cx| GuestIo(&grant.io).write(cx, fd as u32, &bytes[..count])).await;
    }) { return -5; }
    result.map_or_else(error, |count| count as isize)
}
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_native_read(fd: i32, output: *mut u8, length: usize) -> isize {
    if fd >= 3 { return unsafe { crate::native_files::read(fd, output, length) }; }
    let Some(grant) = crate::native_tls::stdio_grant() else { return -3; };
    if fd != 0 || !grant.open(fd) { return -1; }
    if output.is_null() && length != 0 { return -2; }
    let count = length.min(IO_CHUNK);
    let mut bytes = [0u8; IO_CHUNK];
    let mut result = Err(WasiIoError::Failed);
    if !crate::native_tls::park(async {
        result = poll_fn(|cx| GuestIo(&grant.io).read(cx, &mut bytes[..count])).await;
    }) { return -5; }
    match result {
        Ok(count) => {
            // Revocation between delivery and native resumption denies copying.
            if grant.io.cancelled() { return -3; }
            if count != 0 { unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), output, count); } }
            count as isize
        }
        Err(failure) => error(failure),
    }
}

// Descriptor kind 1 is a pipe. No tty or regular-file authority is inferred.
#[no_mangle]
pub(super) extern "C" fn vibeos_native_fd_kind(fd: i32) -> i32 {
    if fd >= 3 { return crate::native_files::kind(fd); }
    let Some(grant) = crate::native_tls::stdio_grant() else { return -3; };
    if !grant.open(fd) { return -1; }
    if grant.io.cancelled() { return -3; }
    1
}
#[no_mangle]
pub(super) extern "C" fn vibeos_native_close(fd: i32) -> i32 {
    if fd >= 3 { return crate::native_files::close(fd); }
    let Some(grant) = crate::native_tls::stdio_grant() else { return -3; };
    if !(0..=2).contains(&fd) { return -1; }
    let mask = 1 << fd;
    if grant.closed.fetch_or(mask, Ordering::AcqRel) & mask != 0 { return -1; }
    // Closing is permitted after grant denial so cleanup can still complete.
    match fd { 0 => grant.io.stdin.close(), 1 => grant.io.stdout.close(), _ => grant.io.stderr.close() }
    0
}
