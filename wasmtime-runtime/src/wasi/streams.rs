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
    /// Reserve output bytes against the whole invocation's ceiling before a
    /// write; the grant may be smaller than `want`, and zero means the
    /// ceiling is exhausted. Reserving first is what keeps several guest
    /// threads from spending the same remaining bytes. The per-store
    /// 65,536-byte ceiling always applies as well.
    fn reserve_output(&mut self, want: usize) -> usize { want }
    /// Return the part of a reservation the write did not use.
    fn release_output(&mut self, _unused: usize) {}
}
/// Give back the unused part of an output reservation.
fn release<C: Clock>(caller: &mut Caller<'_, Invocation<C>>, unused: usize) {
    if unused != 0 {
        if let Some(io) = caller.data_mut().streams.as_mut() { io.release_output(unused); }
    }
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
    let memory = guest_memory(caller).map_err(|_| FAULT)?;
    let selected = memory.with_data(caller, |data, state| -> Result<Option<(usize, usize)>, i32> {
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
        Ok(selected)
    })?;
    let mut count = 0;
    if let Some((addr, mut len)) = selected {
        // Bytes reserved against the invocation-wide ceiling for this write.
        let mut reserved = 0;
        if !read {
            let state = caller.data_mut();
            len = len.min(65536 - state.written);
            if len != 0 {
                if let Some(io) = state.streams.as_mut() {
                    len = io.reserve_output(len);
                    reserved = len;
                }
            }
            if len == 0 {
                state.resources.exceeded = true;
                return Err(27);
            }
        }
        let transferred: Result<usize, i32> = {
            match &memory {
                GuestMemory::Local(local) => {
                    let (data, state) = local.data_and_store_mut(&mut *caller);
                    // The caller/store borrow excludes guest execution or memory
                    // growth throughout this await. Host slice borrows cannot
                    // escape a poll call.
                    match state.streams.as_mut() {
                        None => Err(IO),
                        Some(io) if read => poll_fn(|cx| io.read(cx, &mut data[addr..addr + len])).await,
                        Some(io) => poll_fn(|cx| io.write(cx, p[0] as u32, &data[addr..addr + len])).await,
                    }
                }
                GuestMemory::Shared(_) => {
                    // Other guest threads keep running during the await, so no
                    // slice into shared memory may live across it: stage the
                    // bytes in this store's own scratch buffer, kept across
                    // calls so a print-heavy guest does not allocate per line.
                    let mut scratch = core::mem::take(&mut caller.data_mut().scratch);
                    scratch.clear();
                    scratch.resize(len, 0);
                    let result = if read {
                        match caller.data_mut().streams.as_mut().ok_or(IO) {
                            Ok(io) => match poll_fn(|cx| io.read(cx, &mut scratch)).await {
                                Ok(n) if n > len => Err(IO),
                                Ok(n) => {
                                    memory.with_data(caller, |data, _| data[addr..addr + n].copy_from_slice(&scratch[..n]));
                                    Ok(n)
                                }
                                Err(e) => Err(e),
                            },
                            Err(e) => Err(e),
                        }
                    } else {
                        memory.with_data(caller, |data, _| scratch.copy_from_slice(&data[addr..addr + len]));
                        match caller.data_mut().streams.as_mut().ok_or(IO) {
                            Ok(io) => poll_fn(|cx| io.write(cx, p[0] as u32, &scratch)).await,
                            Err(e) => Err(e),
                        }
                    };
                    caller.data_mut().scratch = scratch;
                    result
                }
            }
        };
        count = match transferred {
            Ok(n) if n <= len => n,
            Ok(_) => { release(caller, reserved); return Err(IO); }
            Err(errno) => { release(caller, reserved); return Err(errno); }
        };
        if !read {
            caller.data_mut().written += count;
            release(caller, reserved - count);
        }
    }
    memory.with_data(caller, |data, _| put(data, p[3], &(count as u32).to_le_bytes()))?;
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
