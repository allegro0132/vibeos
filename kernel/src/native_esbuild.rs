//! A bounded transform-only WASI channel; no V8 WebAssembly or subprocess.
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use core::{future::{poll_fn, Future}, pin::Pin, task::{Context, Poll, Waker}};
use vibeos_file_store::RelPath;
use vibeos_wasi_command::CommandIo;
use vibeos_wasi_runtime::WasiTerminal;

type Response = Result<Vec<u8>, i32>;
type Pending = Pin<Box<dyn Future<Output = Response> + Send>>;
const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
struct Cancel(Arc<CommandIo>);
impl Drop for Cancel { fn drop(&mut self) { self.0.cancel(); } }

pub(super) struct State { next: u64, active: Option<(u64, Option<Pending>, Option<Response>, Arc<AtomicBool>)> }
impl State { pub(super) fn new() -> Self { Self { next: 1, active: None } } }
impl Drop for State {
    fn drop(&mut self) {
        // The bridge must cancel, await the WASI reaper, and release its native
        // handle before invocation TLS is destroyed. Dropping a pending future
        // here would hide incomplete cleanup behind normal Node termination.
        assert!(self.active.is_none(), "esbuild handle must be released before invocation teardown");
    }
}

// Wasmi's module validation/instantiation is synchronous. Create the managed
// guest on a worker hart so a large official esbuild module cannot monopolize
// the boot hart's SSH/network loop. The raw-reclaimable arena is created on
// that hart, never migrated across harts after admission. The existing reaper
// still owns teardown and terminal publication.
async fn launch_service(module: Vec<u8>, io: Arc<CommandIo>,
                        authority: Box<dyn Fn() -> bool + Send + Sync>) -> Result<(), u32> {
    use vibeos_core::{exec, heap::{self, AllocationDomain}};
    let worker = (1..exec::MAX_HARTS)
        .find(|index| crate::online_hart_mask() & (1usize << index) != 0)
        .and_then(exec::HartId::new).unwrap_or(exec::HartId::BOOT);
    let (task, outcome) = {
        let _system = unsafe { heap::enter_domain(AllocationDomain::SYSTEM) };
        let outcome = Arc::new(crate::sync::SpinLock::new(None));
        let published = outcome.clone();
        let task = exec::spawn_pinned_on(worker, "esbuild-admission", async move {
            let result = crate::wasi::launch_owned(module,
                &[String::from("esbuild.wasm"), String::from("--service=0.25.0")],
                io, Some(authority));
            *published.lock() = Some(result);
        });
        (task, outcome)
    };
    let _ = task.join().await;
    let result = outcome.lock().take().unwrap_or(Err(125));
    result
}

fn prepare(packet: &[u8]) -> Result<(Pending, Arc<AtomicBool>), i32> {
    if !crate::native_esbuild_protocol::validate(packet) { return Err(-9); }
    let tools = crate::native_tls::tool_grant().ok_or(-3)?;
    let parent = crate::native_tls::stdio_grant().ok_or(-3)?;
    if !tools.live() || parent.cancelled() { return Err(-3); }
    let mut input = Vec::new();
    input.try_reserve_exact(packet.len()).map_err(|_| -14)?;
    input.extend_from_slice(packet);
    let cancel = Arc::new(AtomicBool::new(false));
    let cancelled = cancel.clone();
    Ok((Box::pin(async move {
        let module = tools.load_module(&RelPath::parse("wasi/esbuild.wasm").map_err(|_| -9)?).await?;
        if cancelled.load(Ordering::Acquire) { return Err(-3); }
        let io = Arc::new(CommandIo::new());
        let _cancel = Cancel(io.clone());
        let authority = tools.clone();
        let cancellation = parent.clone();
        let cancel_job = cancelled.clone();
        launch_service(module, io.clone(),
            Box::new(move || authority.live() && !cancellation.cancelled() && !cancel_job.load(Ordering::Acquire))).await
            .map_err(|code| if code == 75 { -8 } else { -14 })?;
        let mut offset = 0;
        let mut output = Vec::new();
        let mut error_bytes = 0usize;
        let mut failure = None;
        poll_fn(|cx| {
            if !tools.live() { io.deny(); failure = Some(-3); }
            if parent.cancelled() || cancelled.load(Ordering::Acquire) { io.cancel(); failure = Some(-3); }
            if offset < input.len() && failure.is_none() {
                match io.stdin.write(cx, &input[offset..]) {
                    Poll::Ready(Ok(n)) => { offset += n; cx.waker().wake_by_ref(); }
                    Poll::Ready(Err(_)) => { failure = Some(-5); io.cancel(); }
                    Poll::Pending => (),
                }
            }
            if offset == input.len() || failure.is_some() { io.stdin.close(); }
            // Bound each poll and drain both streams even after an error so the
            // audited WASI reaper can finish before we publish a native result.
            let mut chunk = [0u8; 2048];
            if let Poll::Ready(Ok(n)) = io.stdout.read(cx, &mut chunk) {
                if n != 0 {
                    if failure.is_none() {
                        if output.len() + n > OUTPUT_LIMIT || output.try_reserve(n).is_err() {
                            failure = Some(-14); io.cancel();
                        } else { output.extend_from_slice(&chunk[..n]); }
                    }
                    cx.waker().wake_by_ref();
                }
            }
            if let Poll::Ready(Ok(n)) = io.stderr.read(cx, &mut chunk) {
                if n != 0 {
                    error_bytes += n;
                    if error_bytes > 65536 { failure = Some(-14); io.cancel(); }
                    cx.waker().wake_by_ref();
                }
            }
            match io.poll_terminal(cx) {
                Poll::Ready(terminal) if io.stdout.drained() && io.stderr.drained() => {
                    if let Some(error) = failure { return Poll::Ready(Err(error)); }
                    Poll::Ready(match terminal {
                        WasiTerminal::Exited(0) if error_bytes == 0 => Ok(core::mem::take(&mut output)),
                        WasiTerminal::Denied | WasiTerminal::Cancelled => Err(-3),
                        WasiTerminal::LimitExceeded => Err(-14),
                        _ => Err(-5),
                    })
                }
                _ => Poll::Pending,
            }
        }).await
    }), cancel))
}

#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_esbuild_begin(input: *const u8, length: usize) -> i64 {
    if input.is_null() || length > 1024 * 1024 + 65536 { return -9; }
    let packet = unsafe { core::slice::from_raw_parts(input, length) };
    crate::native_tls::with_esbuild(|state| {
        if state.active.is_some() { return -8; }
        let (future, cancel) = match prepare(packet) { Ok(future) => future, Err(e) => return i64::from(e) };
        let Some(next) = state.next.checked_add(1).filter(|n| *n <= i64::MAX as u64) else { return -14; };
        let id = state.next;
        state.next = next;
        state.active = Some((id, Some(future), None, cancel));
        id as i64
    })
}

// Response memory belongs to TLS until release or normal invocation teardown.
#[no_mangle]
pub(super) unsafe extern "C" fn vibeos_esbuild_poll(id: u64, output: *mut *const u8,
                                                   length: *mut usize) -> i32 {
    if output.is_null() || length.is_null() { return -2; }
    let waker = Waker::from(crate::native_tls::io_notification());
    let mut cx = Context::from_waker(&waker);
    crate::native_tls::with_esbuild(|state| {
        let Some((handle, future, result, _)) = state.active.as_mut() else { return -1; };
        if *handle != id { return -1; }
        if let Some(pending) = future {
            match pending.as_mut().poll(&mut cx) {
                Poll::Pending => return -15,
                Poll::Ready(value) => { *result = Some(value); *future = None; }
            }
        }
        match result.as_ref() {
            Some(Ok(bytes)) => { unsafe { *output = bytes.as_ptr(); *length = bytes.len(); } 0 }
            Some(Err(error)) => *error,
            None => -8,
        }
    })
}

#[no_mangle]
pub(super) extern "C" fn vibeos_esbuild_cancel(id: u64) -> i32 {
    crate::native_tls::with_esbuild(|state| {
        let Some(slot) = state.active.as_ref().filter(|s| s.0 == id) else { return -1; };
        slot.3.store(true, Ordering::Release);
        crate::native_tls::io_notification().signal();
        0
    })
}

pub(super) fn ready() -> bool {
    let id = crate::native_tls::with_esbuild(|s| s.active.as_ref().map(|s| s.0));
    let Some(id) = id else { return false; };
    let mut output = core::ptr::null();
    let mut length = 0;
    unsafe { vibeos_esbuild_poll(id, &mut output, &mut length) != -15 }
}

#[no_mangle]
pub(super) extern "C" fn vibeos_esbuild_release(id: u64) -> i32 {
    crate::native_tls::with_esbuild(|state| {
        let Some(slot) = state.active.as_ref().filter(|slot| slot.0 == id) else { return -1; };
        // Release is not cancellation. Keep the future and its authority alive
        // until wait/poll has observed the fully reaped terminal result.
        if slot.1.is_some() || slot.2.is_none() { return -8; }
        state.active = None;
        0
    })
}

#[no_mangle]
pub(super) extern "C" fn vibeos_esbuild_wait(id: u64) -> i32 {
    // Take the Rust future out of TLS before parking. Native TLS is inactive
    // while the executor polls it, and no RefCell borrow spans suspension.
    let pending = crate::native_tls::with_esbuild(|state| {
        state.active.as_mut().filter(|s| s.0 == id).and_then(|s| s.1.take())
    });
    let Some(pending) = pending else {
        return crate::native_tls::with_esbuild(|s| if s.active.as_ref().is_some_and(|s| s.0 == id && s.2.is_some()) { 0 } else { -1 });
    };
    let mut result = None;
    if !crate::native_tls::park(async { result = Some(pending.await); }) { return -5; }
    crate::native_tls::with_esbuild(|state| {
        let Some(slot) = state.active.as_mut().filter(|s| s.0 == id) else { return -1; };
        slot.2 = result;
        0
    })
}

#[cfg(feature = "node-esbuild-probe")]
pub(super) async fn probe() {
    use crate::{native_call::NativeAsync, native_stdio::StdioGrant, native_tls::NativeSyncDomain};
    const PACKET: &[u8] = include_bytes!("../../tools/node-runtime/tests/esbuild-transform.packet");
    let tools = crate::native_toolkit::grant().await.expect("probe tools");
    let io = Arc::new(CommandIo::new());
    let cancel_ready = crate::native_notify::NativeNotify::new();
    let ready = cancel_ready.listen().unwrap();
    let cancelled = io.clone();
    let peer = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "esbuild-cancel-peer", async move {
        ready.await;
        crate::exec::sleep_ms(20).await;
        cancelled.cancel();
    });
    let run = NativeAsync::try_owned_entry(Box::new(move || {
        assert_eq!(unsafe { vibeos_esbuild_begin(b"bad".as_ptr(), 3) }, -9);
        let id = unsafe { vibeos_esbuild_begin(PACKET.as_ptr(), PACKET.len()) };
        assert!(id > 0);
        assert_eq!(unsafe { vibeos_esbuild_begin(PACKET.as_ptr(), PACKET.len()) }, -8);
        assert_eq!(vibeos_esbuild_release(id as u64), -8);
        assert_eq!(vibeos_esbuild_wait(id as u64), 0);
        let mut pointer = core::ptr::null();
        let mut length = 0;
        assert_eq!(unsafe { vibeos_esbuild_poll(id as u64, &mut pointer, &mut length) }, 0);
        let output = unsafe { core::slice::from_raw_parts(pointer, length) };
        assert!(output.windows(b"const answer = 42;".len()).any(|w| w == b"const answer = 42;"));
        assert_eq!(vibeos_esbuild_release(id as u64), 0);
        assert_eq!(unsafe { vibeos_esbuild_poll(id as u64, &mut pointer, &mut length) }, -1);
        for cancelled in [false, true] {
            let id = unsafe { vibeos_esbuild_begin(PACKET.as_ptr(), PACKET.len()) };
            assert!(id > 0);
            let mut signalled = false;
            loop {
                // Register before polling the external predicate: a completion
                // between polling and parking must not be lost.
                let ready = crate::native_tls::io_notification().listen().unwrap();
                let status = unsafe { vibeos_esbuild_poll(id as u64, &mut pointer, &mut length) };
                if status != -15 {
                    assert_eq!(status, if cancelled { -3 } else { 0 });
                    if !cancelled {
                        let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
                        assert!(bytes.windows(b"const answer = 42;\n".len()).any(|w| w == b"const answer = 42;\n"));
                    }
                    break;
                }
                assert_eq!(vibeos_esbuild_release(id as u64), -8);
                if cancelled && !signalled { cancel_ready.signal(); signalled = true; }
                assert!(crate::native_tls::park(ready));
            }
            assert_eq!(vibeos_esbuild_release(id as u64), 0);
        }
        42
    }), 1024 * 1024, NativeSyncDomain::new()).expect("probe native stack");
    run.tls().set_tools(tools);
    run.tls().set_stdio(StdioGrant::new(io.clone()));
    let (value, parks) = run.run().await;
    let _ = peer.join().await;
    assert_eq!(value, 42);
    assert!(parks > 0);
    assert_eq!(io.pending_waiters(), 0);
    crate::println!("NATIVE ESBUILD RELEASE pending=denied terminal=allowed PASS");
    crate::println!("NATIVE ESBUILD BRIDGE transform=1 async=1 cancel=1 rejected=1 busy=1 stale=1 returned=42 parks={} waiters=0 PASS", parks);
    crate::sbi::shutdown(false);
}
