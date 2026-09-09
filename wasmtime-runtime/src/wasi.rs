//! Preview 1 adapter with bounded buffered or asynchronous streaming stdio.
//! The command service must add admission limits, scheduling and capability policy
//! before exposing this adapter to uploaded programs.
use alloc::{string::String, vec::Vec};
use wasmtime::{Caller, Engine, Extern, ExternType, Linker, Memory, Module, SharedMemory, Val, ValType};
#[path = "../../wasi-runtime/src/abi.rs"]
#[allow(dead_code)]
mod abi;
use abi::*;
// Share the exact declaration limits with the Wasmi command entry. This module
// is compiled against each backend's pinned wasmparser version.
#[path = "../../wasi-runtime/src/validate.rs"]
mod validate;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError { Malformed, Unsupported, Contract, Import, Limit }
impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "WASI admission: {self:?}") }
}
impl core::error::Error for AdmissionError {}
type WasiError = AdmissionError;
#[derive(Clone, Copy)]
struct WasiLimits { module_bytes: usize, memory_bytes: usize, threads: bool }

#[cfg(feature = "async")]
mod streams;
#[cfg(feature = "async")]
pub use streams::{Streams, linker_streams};
#[cfg(feature = "threads")]
pub mod threads;

/// The guest's exported `memory`, either private to this store or the shared
/// memory every guest thread instantiates against.
pub(crate) enum GuestMemory { Local(Memory), Shared(SharedMemory) }
pub(crate) fn guest_memory<T>(caller: &mut Caller<'_, T>) -> wasmtime::Result<GuestMemory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Ok(GuestMemory::Local(memory)),
        Some(Extern::SharedMemory(memory)) => Ok(GuestMemory::Shared(memory)),
        _ => wasmtime::bail!("missing memory"),
    }
}
impl GuestMemory {
    /// Run `f` over the current guest bytes and the store data.
    ///
    /// For shared memory the slice aliases bytes that other guest threads may
    /// access concurrently. Host calls only touch guest-designated ranges and
    /// never retain the slice beyond this synchronous call, so a racing guest
    /// observes exactly the data races the threads proposal already permits.
    /// The base of a shared memory never moves and it only grows.
    pub(crate) fn with_data<T, R>(&self, caller: &mut Caller<'_, T>, f: impl FnOnce(&mut [u8], &mut T) -> R) -> R {
        match self {
            GuestMemory::Local(memory) => {
                let (data, state) = memory.data_and_store_mut(caller);
                f(data, state)
            }
            GuestMemory::Shared(memory) => {
                let cells = memory.data();
                let data = unsafe { core::slice::from_raw_parts_mut(cells.as_ptr() as *mut u8, cells.len()) };
                f(data, caller.data_mut())
            }
        }
    }
}

/// Clocks are supplied explicitly by the embedding, never inferred by the runtime.
pub trait Clock: Send + 'static {
    fn time(&mut self, id: u32, precision: u64) -> Result<u64, i32>;
    fn resolution(&mut self, id: u32) -> Result<u64, i32>;
}
pub struct Invocation<C> {
    /// wasi-threads identifier: 0 for the main thread, >= 1 for spawned threads.
    pub tid: u32,
    argv: Vec<Vec<u8>>,
    input: Vec<u8>,
    read: usize,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    closed: [bool; 3],
    pub exit: Option<u32>,
    clock: C,
    resources: Resources,
    #[cfg(feature = "async")]
    streams: Option<alloc::boxed::Box<dyn Streams>>,
    #[cfg(feature = "async")]
    written: usize,
}
impl<C: Clock> Invocation<C> {
    pub fn resource_limits(&mut self) -> &mut dyn wasmtime::ResourceLimiter { &mut self.resources }
    pub fn resource_limit_hit(&self) -> bool { self.resources.exceeded }
    pub fn new(args: &[String], input: Vec<u8>, clock: C) -> wasmtime::Result<Self> {
        let size = args
            .iter()
            .try_fold(0usize, |n, s| n.checked_add(s.len())?.checked_add(1));
        if args.len() > 128
            || size.is_none_or(|n| n > 16384)
            || args.iter().any(|s| s.as_bytes().contains(&0))
            || input.len() > 65536
        {
            wasmtime::bail!("WASI invocation limit");
        }
        Ok(Self {
            tid: 0,
            argv: args
                .iter()
                .map(|s| {
                    let mut v = s.as_bytes().to_vec();
                    v.push(0);
                    v
                })
                .collect(),
            input,
            read: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            closed: [false; 3],
            exit: None,
            clock,
            resources: Resources { exceeded: false },
            #[cfg(feature = "async")]
            streams: None,
            #[cfg(feature = "async")]
            written: 0,
        })
    }
}
fn range(data: &[u8], p: usize, n: usize) -> Result<(), i32> {
    if p.checked_add(n).is_some_and(|end| end <= data.len()) {
        Ok(())
    } else {
        Err(FAULT)
    }
}
fn put(data: &mut [u8], p: usize, bytes: &[u8]) -> Result<(), i32> {
    range(data, p, bytes.len())?;
    data[p..p + bytes.len()].copy_from_slice(bytes);
    Ok(())
}
fn word(data: &[u8], p: usize) -> usize {
    u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize
}
fn call<C: Clock>(
    name: &str,
    data: &mut [u8],
    state: &mut Invocation<C>,
    a: [u64; 9],
) -> Result<i32, i32> {
    let p = a.map(|v| v as u32 as usize);
    let fd = |state: &Invocation<C>| {
        if p[0] < 3 && !state.closed[p[0]] {
            Ok(())
        } else {
            Err(BADF)
        }
    };
    match name {
        "args_sizes_get" | "environ_sizes_get" => {
            range(data, p[0], 4)?;
            range(data, p[1], 4)?;
            let (count, size) = if name == "args_sizes_get" {
                (state.argv.len(), state.argv.iter().map(Vec::len).sum())
            } else {
                (0, 0)
            };
            put(data, p[0], &(count as u32).to_le_bytes())?;
            put(data, p[1], &(size as u32).to_le_bytes())?;
        }
        "args_get" => {
            range(data, p[0], state.argv.len() * 4)?;
            range(data, p[1], state.argv.iter().map(Vec::len).sum())?;
            let mut offset = p[1];
            for (i, arg) in state.argv.iter().enumerate() {
                put(data, p[0] + 4 * i, &(offset as u32).to_le_bytes())?;
                put(data, offset, arg)?;
                offset += arg.len();
            }
        }
        "environ_get" => (),
        "clock_time_get" | "clock_res_get" => {
            let time = name == "clock_time_get";
            let dest = p[if time { 2 } else { 1 }];
            range(data, dest, 8)?;
            if a[0] > 3 {
                return Err(28);
            }
            let ns = if time {
                state.clock.time(a[0] as u32, a[1])?
            } else {
                state.clock.resolution(a[0] as u32)?
            };
            if !time && ns == 0 {
                return Err(IO);
            }
            put(data, dest, &ns.to_le_bytes())?;
        }
        "fd_close" => {
            fd(state)?;
            #[cfg(feature = "async")]
            if let Some(streams) = state.streams.as_mut() { streams.close(p[0] as u32)?; }
            state.closed[p[0]] = true;
        }
        "fd_seek" | "fd_tell" => {
            fd(state)?;
            return Err(SPIPE);
        }
        "fd_prestat_get" | "fd_prestat_dir_name" => return Err(BADF),
        "fd_fdstat_get" | "fd_filestat_get" => {
            fd(state)?;
            let mut buf = [0u8; 64];
            let len = if name == "fd_fdstat_get" {
                buf[0] = 2;
                let rights: u64 = (if p[0] == 0 { 2 } else { 64 }) | (1 << 21);
                buf[8..16].copy_from_slice(&rights.to_le_bytes());
                24
            } else {
                buf[16] = 2;
                buf[24..32].copy_from_slice(&1u64.to_le_bytes());
                64
            };
            put(data, p[1], &buf[..len])?;
        }
        "fd_read" | "fd_write" => {
            #[cfg(feature = "async")]
            if state.streams.is_some() { return Err(IO); }
            fd(state)?;
            let read = name == "fd_read";
            if (read && p[0] != 0) || (!read && p[0] == 0) {
                return Err(BADF);
            }
            if p[2] > 1024 {
                return Err(28);
            }
            range(data, p[1], p[2] * 8)?;
            range(data, p[3], 4)?;
            // Check all vectors before consuming input or committing any output.
            let mut selected = None;
            for i in 0..p[2] {
                let addr = word(data, p[1] + 8 * i);
                let len = word(data, p[1] + 8 * i + 4);
                range(data, addr, len)?;
                if selected.is_none() && len != 0 {
                    selected = Some((addr, len.min(4096)));
                }
            }
            let mut count = 0;
            if let Some((addr, len)) = selected {
                if read {
                    count = len.min(state.input.len() - state.read);
                    put(data, addr, &state.input[state.read..state.read + count])?;
                    state.read += count;
                } else {
                    count = len.min(65536 - state.stdout.len() - state.stderr.len());
                    if count == 0 {
                        state.resources.exceeded = true;
                        return Err(27);
                    }
                    let out = if p[0] == 1 {
                        &mut state.stdout
                    } else {
                        &mut state.stderr
                    };
                    out.extend_from_slice(&data[addr..addr + count]);
                }
            }
            put(data, p[3], &(count as u32).to_le_bytes())?;
        }
        _ => return Err(NOSYS),
    }
    Ok(SUCCESS)
}
/// Apply the shared command profile's structural admission before compilation.
/// The embedding must still supervise compiler allocations and scheduling.
pub fn compile(engine: &Engine, bytes: &[u8]) -> wasmtime::Result<Module> {
    compile_with(engine, bytes, false)
}
/// Like [`compile`]; with `threads` the wasi-threads contract is admitted:
/// an imported shared, bounded `env.memory`, `wasi::thread-spawn`, and the
/// `wasi_thread_start` export. The exported `memory` may then be shared.
pub fn compile_with(engine: &Engine, bytes: &[u8], threads: bool) -> wasmtime::Result<Module> {
    validate::inspect(bytes, WasiLimits { module_bytes: 512 * 1024, memory_bytes: 16 * 1024 * 1024, threads })
        .map_err(wasmtime::Error::new)?;
    let module = Module::new(engine, bytes)?;
    match module.get_export("memory") {
        Some(ExternType::Memory(m)) if !m.is_64() && (!m.is_shared() || threads) => (),
        _ => wasmtime::bail!("memory export required"),
    }
    match module.get_export("_start") {
        Some(ExternType::Func(f)) if f.params().len() == 0 && f.results().len() == 0 => (),
        _ => wasmtime::bail!("_start: () -> () required"),
    }
    if uses_threads(&module) {
        match module.get_export(THREAD_START_EXPORT) {
            Some(ExternType::Func(f))
                if f.params().len() == 2
                    && f.params().all(|p| matches!(p, ValType::I32))
                    && f.results().len() == 0 => (),
            _ => wasmtime::bail!("wasi_thread_start: (i32, i32) -> () required"),
        }
    }
    check_imports(&module)?;
    Ok(module)
}
/// Whether the module imports the wasi-threads shared memory. Structural
/// admission (`validate::inspect`) has already required the full contract.
pub fn uses_threads(module: &Module) -> bool {
    module.imports().any(|i| i.module() == "env" && i.name() == "memory")
}
fn is_thread_import(import: &wasmtime::ImportType<'_>) -> bool {
    (import.module() == THREAD_SPAWN_MODULE && import.name() == THREAD_SPAWN_NAME)
        || (import.module() == "env" && import.name() == "memory")
}
fn check_imports(module: &Module) -> wasmtime::Result<()> {
    for import in module.imports() {
        if import.module() == "env" && import.name() == "memory" {
            match import.ty() {
                ExternType::Memory(m) if m.is_shared() && !m.is_64() && m.maximum().is_some() => continue,
                _ => wasmtime::bail!("env.memory must be a bounded shared memory"),
            }
        }
        if import.module() == THREAD_SPAWN_MODULE && import.name() == THREAD_SPAWN_NAME {
            match import.ty() {
                ExternType::Func(f)
                    if f.params().len() == 1
                        && matches!(f.params().next(), Some(ValType::I32))
                        && f.results().len() == 1
                        && matches!(f.results().next(), Some(ValType::I32)) => continue,
                _ => wasmtime::bail!("wasi.thread-spawn: (i32) -> i32 required"),
            }
        }
        if import.module() != "wasi_snapshot_preview1" {
            wasmtime::bail!("unknown import namespace");
        }
        let sig = abi::signature(import.name())
            .ok_or_else(|| wasmtime::format_err!("unknown WASI import"))?;
        let ExternType::Func(ty) = import.ty() else {
            wasmtime::bail!("host resource imports forbidden");
        };
        let valid = ty.params().len() == sig.len()
            && ty
                .params()
                .zip(sig.bytes())
                .all(|(t, c)| matches!((t, c), (ValType::I32, b'i') | (ValType::I64, b'l')))
            && if import.name() == "proc_exit" {
                ty.results().len() == 0
            } else {
                ty.results().len() == 1 && matches!(ty.results().next(), Some(ValType::I32))
            };
        if !valid {
            wasmtime::bail!("incorrect WASI signature");
        }
    }
    Ok(())
}
pub fn linker<C: Clock>(
    engine: &Engine,
    module: &Module,
) -> wasmtime::Result<Linker<Invocation<C>>> {
    check_imports(module)?;
    let mut linker = Linker::new(engine);
    let mut defined = alloc::collections::BTreeSet::new();
    for import in module.imports() {
        // The shared memory and spawner are defined by the threads embedding.
        if is_thread_import(&import) {
            continue;
        }
        let ExternType::Func(ty) = import.ty() else {
            wasmtime::bail!("function required");
        };
        // Duplicate imports refer to the same definition.
        if !defined.insert(String::from(import.name())) {
            continue;
        }
        let name = String::from(import.name());
        linker.func_new(
            import.module(),
            import.name(),
            ty,
            move |mut caller: Caller<'_, Invocation<C>>, args, results| {
                let mut a = [0u64; 9];
                for (dst, src) in a.iter_mut().zip(args) {
                    *dst = match src {
                        Val::I32(v) => *v as u32 as u64,
                        Val::I64(v) => *v as u64,
                        _ => wasmtime::bail!("non-scalar ABI"),
                    };
                }
                if name == "proc_exit" {
                    caller.data_mut().exit = Some(a[0] as u32);
                    wasmtime::bail!("WASI proc_exit");
                }
                let memory = guest_memory(&mut caller)?;
                let errno = memory.with_data(&mut caller, |data, state| call(&name, data, state, a));
                results[0] = Val::I32(errno.unwrap_or_else(|errno| errno));
                if caller.data().resource_limit_hit() {
                    wasmtime::bail!("WASI output limit");
                }
                Ok(())
            },
        )?;
    }
    Ok(linker)
}


// Match the existing command contract: failed memory/table growth terminates
// with a resource status, even if guest code would ignore a -1 grow result.
struct Resources { exceeded: bool }
impl wasmtime::ResourceLimiter for Resources {
    fn memory_growing(&mut self, _: usize, desired: usize, maximum: Option<usize>) -> wasmtime::Result<bool> {
        if desired > (16 * 1024 * 1024).min(maximum.unwrap_or(usize::MAX)) {
            self.exceeded = true; wasmtime::bail!("WASI memory limit");
        }
        Ok(true)
    }
    fn table_growing(&mut self, _: usize, desired: usize, maximum: Option<usize>) -> wasmtime::Result<bool> {
        if desired > 4096usize.min(maximum.unwrap_or(usize::MAX)) {
            self.exceeded = true; wasmtime::bail!("WASI table limit");
        }
        Ok(true)
    }
    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> { self.exceeded = true; Err(error) }
    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> { self.exceeded = true; Err(error) }
    fn instances(&self) -> usize { 1 }
    fn memories(&self) -> usize { 1 }
    fn tables(&self) -> usize { 1 }
}
