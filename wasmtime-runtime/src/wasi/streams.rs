//! Streaming Preview 1 I/O, suspended on Wasmtime's native fiber.
use super::*;
use alloc::boxed::Box;
use core::{future::poll_fn, task::{Context, Poll}};
/// Host-owned streams. Pending must register a wakeup without consuming input
/// or committing output. Ready counts must not exceed the supplied slice.
/// Dropping the invocation must remove any pending host registrations.
pub trait Streams: Send + 'static {
    /// Close the invocation's descriptor without closing unrelated host handles.
    fn close(&mut self, _fd: u32) -> Result<(), i32> { Ok(()) }
    fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, i32>>;
    fn write(&mut self, cx: &mut Context<'_>, fd: u32, bytes: &[u8]) -> Poll<Result<usize, i32>>;
}
impl<C: Clock> Invocation<C> {
    pub fn with_streams(args: &[String], clock: C, streams: Box<dyn Streams>) -> wasmtime::Result<Self> {
        let mut state = Self::new(args, Vec::new(), clock)?;
        state.streams = Some(streams);
        Ok(state)
    }
}
async fn transfer<C: Clock>(caller: &mut Caller<'_, Invocation<C>>, read: bool, args: &[Val]) -> Result<i32, i32> {
    let p: [usize; 4] = core::array::from_fn(|i| args[i].i32().unwrap() as u32 as usize);
    let memory = caller.get_export("memory").and_then(|e| e.into_memory()).ok_or(FAULT)?;
    let (data, state) = memory.data_and_store_mut(caller);
    if p[0] >= 3 || state.closed[p[0]] || (read && p[0] != 0) || (!read && p[0] == 0) {
        return Err(BADF);
    }
    if p[2] > 1024 { return Err(28); }
    range(data, p[1], p[2] * 8)?;
    range(data, p[3], 4)?;
    let mut selected = None;
    for i in 0..p[2] {
        let addr = word(data, p[1] + i * 8);
        let len = word(data, p[1] + i * 8 + 4);
        range(data, addr, len)?;
        if selected.is_none() && len != 0 { selected = Some((addr, len.min(4096))); }
    }
    let mut count = 0;
    if let Some((addr, mut len)) = selected {
        if !read {
            len = len.min(65536 - state.written);
            if len == 0 {
                state.resources.exceeded = true;
                return Err(27);
            }
        }
        let io = state.streams.as_mut().ok_or(IO)?;
        // The caller/store borrow excludes guest execution or memory growth
        // throughout this await. Host slice borrows cannot escape a poll call.
        count = if read {
            poll_fn(|cx| io.read(cx, &mut data[addr..addr + len])).await?
        } else {
            poll_fn(|cx| io.write(cx, p[0] as u32, &data[addr..addr + len])).await?
        };
        if count > len { return Err(IO); }
        if !read { state.written += count; }
    }
    put(data, p[3], &(count as u32).to_le_bytes())?;
    Ok(SUCCESS)
}
/// Use with an async-enabled engine and Invocation::with_streams. All non-I/O
/// imports retain the same checked signatures and semantics as the sync linker.
pub fn linker_streams<C: Clock>(engine: &Engine, module: &Module) -> wasmtime::Result<Linker<Invocation<C>>> {
    let mut linker = super::linker(engine, module)?;
    linker.allow_shadowing(true);
    for import in module.imports() {
        let read = match import.name() { "fd_read" => true, "fd_write" => false, _ => continue };
        let ExternType::Func(ty) = import.ty() else { unreachable!() };
        linker.func_new_async(import.module(), import.name(), ty,
            move |mut caller, args, results| Box::new(async move {
                results[0] = Val::I32(transfer(&mut caller, read, args).await.unwrap_or_else(|errno| errno));
                // Output quota is an invocation limit, not a recoverable file
                // error that a guest may ignore indefinitely in a hostcall loop.
                if caller.data().resource_limit_hit() {
                    wasmtime::bail!("WASI output limit");
                }
                Ok(())
            }))?;
    }
    linker.allow_shadowing(false);
    Ok(linker)
}
