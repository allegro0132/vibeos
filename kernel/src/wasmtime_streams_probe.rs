//! Deterministic stream/backpressure tests through native Wasm host calls.
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{future::Future, task::{Context, Poll, Waker}};
use vibeos_wasmtime_runtime::{wasi::{self, Invocation, Streams}, wasmtime::{self, Engine, Module, Store}};
use super::{async_call::NativeFuture, wasi_probe::KernelClock};
#[derive(Default)]
struct State { bulk: bool, calls: usize, waiter: Option<Waker>, read: bool, stdout: Vec<u8>, stderr: Vec<u8>, dropped: bool }
struct Io(Arc<crate::sync::SpinLock<State>>);
impl Streams for Io {
    fn read(&mut self, cx: &mut Context<'_>, data: &mut [u8]) -> Poll<Result<usize, i32>> {
        let mut state = self.0.lock(); state.calls += 1;
        if state.waiter.take().is_none() { state.waiter = Some(cx.waker().clone()); cx.waker().wake_by_ref(); return Poll::Pending; }
        if state.read { return Poll::Ready(Ok(0)); }
        let n = data.len().min(3); data[..n].copy_from_slice(&b"abc"[..n]); state.read = true;
        Poll::Ready(Ok(n))
    }
    fn write(&mut self, cx: &mut Context<'_>, fd: u32, data: &[u8]) -> Poll<Result<usize, i32>> {
        let mut state = self.0.lock(); state.calls += 1;
        if state.waiter.take().is_none() { state.waiter = Some(cx.waker().clone()); cx.waker().wake_by_ref(); return Poll::Pending; }
        let n = data.len().min(if state.bulk { 4096 } else { 2 });
        if fd == 1 { state.stdout.extend_from_slice(&data[..n]); } else { state.stderr.extend_from_slice(&data[..n]); }
        Poll::Ready(Ok(n))
    }
}
impl Drop for Io { fn drop(&mut self) { let mut s = self.0.lock(); s.waiter = None; s.dropped = true; } }
fn finish<F: Future>(future: F, pending: bool) -> F::Output {
    let mut future = core::pin::pin!(NativeFuture::new(future));
    let mut cx = Context::from_waker(Waker::noop());
    if pending { assert!(future.as_mut().poll(&mut cx).is_pending()); }
    match future.as_mut().poll(&mut cx) { Poll::Ready(r) => r, Poll::Pending => panic!("unexpected stream wait") }
}
fn module() -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    fn section(bytes: &mut Vec<u8>, id: u8, data: &[u8]) { assert!(data.len() < 128); bytes.extend([id, data.len() as u8]); bytes.extend(data); }
    section(&mut bytes, 1, &[2,0x60,4,0x7f,0x7f,0x7f,0x7f,1,0x7f,0x60,1,0x7f,1,0x7f]);
    let mut imports = alloc::vec![3];
    for name in [b"fd_read".as_slice(), b"fd_write".as_slice(), b"fd_close".as_slice()] {
        imports.push(22); imports.extend(b"wasi_snapshot_preview1"); imports.push(name.len() as u8); imports.extend(name); imports.extend([0, u8::from(name == b"fd_close")]);
    }
    section(&mut bytes, 2, &imports); section(&mut bytes, 3, &[3,0,0,1]); section(&mut bytes, 5, &[1,1,1,1]);
    section(&mut bytes, 7, &[4,4,b'r',b'e',b'a',b'd',0,3,5,b'w',b'r',b'i',b't',b'e',0,4,5,b'c',b'l',b'o',b's',b'e',0,5,6,b'm',b'e',b'm',b'o',b'r',b'y',2,0]);
    let mut code = alloc::vec![3];
    for index in [0,1] { code.extend([12,0,0x20,0,0x20,1,0x20,2,0x20,3,0x10,index,0x0b]); }
    code.extend([6,0,0x20,0,0x10,2,0x0b]);
    section(&mut bytes, 10, &code); bytes
}
pub(super) fn run(engine: &Engine) -> wasmtime::Result<()> {
    let module = Module::new(engine, module())?;
    let linker = wasi::linker_streams::<KernelClock>(engine, &module)?;
    let state = Arc::new(crate::sync::SpinLock::new(State::default()));
    let mut store = Store::new(engine, Invocation::with_streams(&[], KernelClock, Box::new(Io(state.clone())))?);
    store.set_fuel(100_000)?;
    let instance = finish(linker.instantiate_async(&mut store, &module), false)?;
    let memory = instance.get_memory(&mut store, "memory").unwrap();
    memory.write(&mut store, 0, &[64,0,0,0,5,0,0,0])?;
    let read = instance.get_typed_func::<(i32,i32,i32,i32),i32>(&mut store, "read")?;
    let write = instance.get_typed_func::<(i32,i32,i32,i32),i32>(&mut store, "write")?;
    assert_eq!(finish(read.call_async(&mut store, (0,0,1,16)), true)?, 0);
    assert_eq!(&memory.data(&store)[64..67], b"abc");
    assert_eq!(memory.data(&store)[16], 3);
    assert_eq!(finish(write.call_async(&mut store, (1,0,1,16)), true)?, 0);
    assert_eq!(memory.data(&store)[16], 2);
    assert_eq!(finish(write.call_async(&mut store, (2,0,1,16)), true)?, 0);
    assert_eq!(state.lock().stdout, b"ab"); assert_eq!(state.lock().stderr, b"ab");
    let before = state.lock().calls;
    // Invalid second iovec must reject before touching the valid first one.
    memory.write(&mut store, 8, &[255,255,0,0,2,0,0,0])?;
    for fd in [0,1] {
        let func = if fd == 0 { &read } else { &write };
        assert_eq!(finish(func.call_async(&mut store, (fd,0,2,16)), false)?, 21);
        assert_eq!(finish(func.call_async(&mut store, (fd,0,1,65534)), false)?, 21);
    }
    assert_eq!(state.lock().calls, before);
    assert_eq!(finish(read.call_async(&mut store, (0,0,1,16)), true)?, 0);
    assert_eq!(memory.data(&store)[16], 0); // EOF
    state.lock().bulk = true;
    memory.write(&mut store, 4, &4096u32.to_le_bytes())?;
    for index in 0..16 {
        assert_eq!(finish(write.call_async(&mut store, (1 + index % 2,0,1,16)), true)?, 0);
    }
    { let s = state.lock(); assert_eq!(s.stdout.len() + s.stderr.len(), 65536); }
    let before = state.lock().calls;
    // Output quota is an invocation limit: the guest is unwound instead of
    // receiving an errno it could ignore in a hostcall loop.
    let error = finish(write.call_async(&mut store, (1,0,1,16)), false).unwrap_err();
    assert!(alloc::format!("{error:#}").contains("WASI output limit"), "{error:#}");
    drop(error);
    assert!(store.data().resource_limit_hit());
    assert_eq!(state.lock().calls, before, "output over budget reached host");
    let mut future = Box::pin(NativeFuture::new(read.call_async(&mut store, (0,0,1,16))));
    assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    assert!(state.lock().waiter.is_some());
    drop(future); drop(store);
    { let state = state.lock(); assert!(state.dropped && state.waiter.is_none()); }
    for _ in 0..100 { command_pipe(engine, &module)?; }
    crate::println!("  WASMTIME STREAMS PASS short_read=1 short_write=1 eof=1 stderr=1 invalid_no_io=1 output_limit=65536 command_pipe=100 fd_close=1 cancel_waiters=0");
    Ok(())
}

fn command_pipe(engine: &Engine, module: &Module) -> wasmtime::Result<()> {
    let io = Arc::new(vibeos_wasi_command::CommandIo::new());
    let linker = wasi::linker_streams::<KernelClock>(engine, module)?;
    let mut store = Store::new(engine, Invocation::with_streams(&[], KernelClock,
        Box::new(super::command_io::CommandStreams(io.clone())))?);
    store.set_fuel(100_000)?;
    let instance = finish(linker.instantiate_async(&mut store, module), false)?;
    let memory = instance.get_memory(&mut store, "memory").unwrap();
    memory.write(&mut store, 0, &[64,0,0,0,5,0,0,0])?;
    let read = instance.get_typed_func::<(i32,i32,i32,i32),i32>(&mut store, "read")?;
    let write = instance.get_typed_func::<(i32,i32,i32,i32),i32>(&mut store, "write")?;
    let close = instance.get_typed_func::<i32,i32>(&mut store, "close")?;
    assert_eq!(finish(close.call_async(&mut store, 2), false)?, 0);
    assert!(io.stderr.drained());
    assert_eq!(finish(close.call_async(&mut store, 2), false)?, 8);
    assert_eq!(finish(write.call_async(&mut store, (2,0,1,16)), false)?, 8);
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = Box::pin(NativeFuture::new(read.call_async(&mut store, (0,0,1,16))));
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert_eq!(io.pending_waiters(), 1);
    assert_eq!(io.stdin.write(&mut cx, b"abc"), Poll::Ready(Ok(3)));
    match future.as_mut().poll(&mut cx) { Poll::Ready(r) => assert_eq!(r?, 0), Poll::Pending => panic!("pipe did not resume") }
    drop(future);
    assert_eq!(&memory.data(&store)[64..67], b"abc");
    io.stdin.close();
    assert_eq!(finish(read.call_async(&mut store, (0,0,1,16)), false)?, 0);
    assert_eq!(memory.data(&store)[16], 0);
    let chunk = [0u8; vibeos_wasi_runtime::IO_CHUNK];
    for _ in 0..8 { assert_eq!(io.stdout.write(&mut cx, &chunk), Poll::Ready(Ok(chunk.len()))); }
    let mut future = Box::pin(NativeFuture::new(write.call_async(&mut store, (1,0,1,16))));
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert_eq!(io.pending_waiters(), 1);
    let mut out = [0u8; vibeos_wasi_runtime::IO_CHUNK];
    assert_eq!(io.stdout.read(&mut cx, &mut out), Poll::Ready(Ok(out.len())));
    match future.as_mut().poll(&mut cx) { Poll::Ready(r) => assert_eq!(r?, 0), Poll::Pending => panic!("pipe did not resume") }
    drop(future);
    // Queue is full again; cancellation must detach the suspended writer.
    let mut future = Box::pin(NativeFuture::new(write.call_async(&mut store, (1,0,1,16))));
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future); drop(store);
    assert_eq!(io.pending_waiters(), 0);
    assert!(!io.cancelled(), "transport drop must not overwrite the supervisor result");
    Ok(())
}
