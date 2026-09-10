//! Capability-neutral, bounded WASI Preview 1 command interpreter.
//! All external I/O and clocks are supplied per invocation; there is no filesystem,
//! entropy, global linker, or ambient environment in this crate.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
#[cfg(feature = "rv64-cache")]
pub use wasmi::native;
mod abi;
mod validate;
#[cfg(test)]
mod validate_tests;
pub mod profile;
pub mod output_budget;
pub use output_budget::OutputBudget;
use abi::*;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{
    fmt,
    task::{Context, Poll},
};
use wasmi::{
    Config, Engine, Error, Func, Linker, Memory, Module, ResumableCall, ResumableCallHostTrap,
    ResumableCallOutOfFuel, Store, StoreLimits, StoreLimitsBuilder, Val, ValType,
};

pub const PROFILE: &str = "wasi-preview1-command-v1";
pub const IO_CHUNK: usize = 1024;
#[derive(Clone, Copy, Debug)]
pub struct WasiLimits {
    pub module_bytes: usize,
    pub memory_bytes: usize,
    pub allocation_bytes: usize,
    pub argument_bytes: usize,
    pub arguments: usize,
    pub output_bytes: usize,
    /// Trusted embedding budget, default 10 million, hard ceiling 100 billion.
    /// Guest arguments cannot select this value. The poll quantum stays bounded.
    pub total_fuel: u64,
    pub poll_quantum: u64,
    /// Admit the wasi-threads contract (shared imported memory, atomics,
    /// `wasi::thread-spawn`). The interpreter never executes threads; only the
    /// native command backend may set this.
    pub threads: bool,
}
impl Default for WasiLimits {
    fn default() -> Self {
        Self {
            module_bytes: profile::MODULE_BYTES,
            memory_bytes: profile::MEMORY_BYTES,
            allocation_bytes: profile::ALLOCATION_BYTES,
            argument_bytes: 16 * 1024,
            arguments: 128,
            output_bytes: 64 * 1024,
            total_fuel: if cfg!(feature = "python-wasi") { 10_000_000_000 } else { 10_000_000 },
            poll_quantum: if cfg!(feature = "python-wasi") { 100_000 } else { 10_000 },
            threads: false,
        }
    }
}
impl WasiLimits {
    fn check(self) -> Result<(), WasiError> {
        let max = Self::default();
        if self.module_bytes == 0
            || self.module_bytes > max.module_bytes
            || self.memory_bytes == 0
            || self.memory_bytes > max.memory_bytes
            || self.allocation_bytes == 0
            || self.allocation_bytes > max.allocation_bytes
            || self.arguments > max.arguments
            || self.argument_bytes > max.argument_bytes
            || self.output_bytes > max.output_bytes
            || self.total_fuel == 0
            || self.total_fuel > 100_000_000_000
            || self.poll_quantum == 0
            || self.poll_quantum > self.total_fuel
            || self.poll_quantum > max.poll_quantum
        {
            return Err(WasiError::Limit);
        }
        if self.threads {
            return Err(WasiError::Unsupported);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiError {
    Malformed,
    Unsupported,
    Contract,
    Import,
    Limit,
    Arguments,
    Engine,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiTerminal {
    Exited(u32),
    Trapped,
    Cancelled,
    Denied,
    LimitExceeded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiIoError {
    Closed,
    Denied,
    Failed,
}
/// Clock access is an explicit embedding grant. No host clock is used by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WasiClockError {
    Unsupported,
    Denied,
    Failed,
}
/// Implementations register the supplied waker on pending I/O. A successful
/// read/write may be short, but must never exceed the supplied slice length.
pub trait WasiIo {
    /// Nanoseconds since Unix epoch (0) or an unspecified monotonic origin (1).
    /// CPU clocks (2/3) may be unsupported. Precision is an allowed error hint.
    fn clock_time(&mut self, _id: u32, _precision: u64) -> Result<u64, WasiClockError> {
        Err(WasiClockError::Unsupported)
    }
    /// Resolution in nanoseconds, strictly positive on success.
    fn clock_resolution(&mut self, _id: u32) -> Result<u64, WasiClockError> {
        Err(WasiClockError::Unsupported)
    }
    fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, WasiIoError>>;
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        fd: u32,
        bytes: &[u8],
    ) -> Poll<Result<usize, WasiIoError>>;
}
#[derive(Debug)]
struct HostYield;
impl fmt::Display for HostYield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WASI host yield")
    }
}
impl wasmi::errors::HostError for HostYield {}
struct HostCall {
    name: String,
    args: [u64; 9],
}
struct HostState {
    limits: StoreLimits,
    call: Option<HostCall>,
}
enum Continuation {
    Fuel(ResumableCallOutOfFuel),
    Host(ResumableCallHostTrap, Option<i32>),
}

pub struct WasiInvocation {
    store: Store<HostState>,
    memory: Memory,
    start: Func,
    continuation: Option<Continuation>,
    started: bool,
    pending: Option<HostCall>,
    argv: Vec<Vec<u8>>,
    limits: WasiLimits,
    fuel: u64,
    output: usize,
    closed: [bool; 3],
    terminal: Option<WasiTerminal>,
    io_buffer: [u8; IO_CHUNK],
    io_ready: bool,
}
impl WasiInvocation {
    /// Install the trusted code publisher before the invocation starts.
    #[cfg(feature = "rv64-cache")]
    pub fn enable_native_cache(
        &mut self,
        backend: alloc::sync::Arc<dyn native::CodeMemory>,
    ) -> bool {
        !self.started && self.terminal.is_none() && self.store.engine().enable_native_cache(backend)
    }
    #[cfg(feature = "rv64-cache")]
    pub fn native_cache_stats(&self) -> (usize, usize, u64) {
        self.store.engine().native_cache_stats()
    }
    /// Caller must construct and poll inside its own quota-controlled allocation domain.
    pub fn new(bytes: &[u8], arguments: &[String], limits: WasiLimits) -> Result<Self, WasiError> {
        limits.check()?;
        validate::inspect(bytes, limits)?;
        // Ordinary profiles retain their conservative size heuristic. The Duo
        // CPython profile is admitted against its enforced allocation owner:
        // frozen bytecode/data makes the 32x file-size estimate inappropriate.
        if !cfg!(feature = "python-duo") && bytes
            .len()
            .checked_mul(32)
            .and_then(|n| n.checked_add(256 * 1024))
            .is_none_or(|n| n > limits.allocation_bytes)
        {
            return Err(WasiError::Limit);
        }
        if arguments.is_empty() || arguments.len() > limits.arguments {
            return Err(WasiError::Arguments);
        }
        let mut argv = Vec::new();
        let mut argument_bytes = 0usize;
        for arg in arguments {
            if arg.as_bytes().contains(&0) {
                return Err(WasiError::Arguments);
            }
            argument_bytes = argument_bytes
                .checked_add(arg.len() + 1)
                .ok_or(WasiError::Arguments)?;
            if argument_bytes > limits.argument_bytes {
                return Err(WasiError::Arguments);
            }
            let mut value = arg.as_bytes().to_vec();
            value.push(0);
            argv.push(value);
        }
        let mut config = Config::default();
        config
            .floats(true)
            .wasm_mutable_global(true)
            .wasm_sign_extension(true)
            .wasm_saturating_float_to_int(true)
            .wasm_multi_value(true)
            .wasm_bulk_memory(true)
            .wasm_reference_types(true)
            .wasm_multi_memory(false)
            .wasm_memory64(false)
            .wasm_tail_call(false)
            .wasm_extended_const(false)
            .wasm_custom_page_sizes(false)
            .wasm_wide_arithmetic(false)
            .consume_fuel(true)
            .ignore_custom_sections(true)
            .set_max_recursion_depth(profile::DECLARATIONS.max_call_depth as usize)
            .set_min_stack_height(4096)
            .set_max_stack_height(128 * 1024)
            .set_max_cached_stacks(0)
            .compilation_mode(wasmi::CompilationMode::Eager)
            .enforced_limits(wasmi::EnforcedLimits::strict().with_max_functions(profile::DECLARATIONS.max_functions));
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes).map_err(|_| WasiError::Unsupported)?;
        let mut linker = Linker::new(&engine);
        for import in module.imports() {
            let signature = abi::signature(import.name()).ok_or(WasiError::Import)?;
            let ty = import.ty().func().ok_or(WasiError::Import)?;
            let params: Vec<_> = signature
                .bytes()
                .map(|c| {
                    if c == b'i' {
                        ValType::I32
                    } else {
                        ValType::I64
                    }
                })
                .collect();
            let results = if import.name() == "proc_exit" {
                &[][..]
            } else {
                &[ValType::I32][..]
            };
            if import.module() != "wasi_snapshot_preview1"
                || ty.params() != params
                || ty.results() != results
            {
                return Err(WasiError::Import);
            }
            let name = import.name().to_string();
            linker
                .func_new(
                    import.module(),
                    import.name(),
                    ty.clone(),
                    move |mut caller: wasmi::Caller<'_, HostState>, inputs, _| {
                        let mut args = [0; 9];
                        for (slot, val) in args.iter_mut().zip(inputs) {
                            *slot = match val {
                                Val::I32(v) => *v as u32 as u64,
                                Val::I64(v) => *v as u64,
                                _ => return Err(Error::host(HostYield)),
                            };
                        }
                        caller.data_mut().call = Some(HostCall {
                            name: name.clone(),
                            args,
                        });
                        Err(Error::host(HostYield))
                    },
                )
                .map_err(|_| WasiError::Import)?;
        }
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.memory_bytes)
            .table_elements(profile::DECLARATIONS.max_table_elements as usize)
            .instances(1)
            .memories(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &engine,
            HostState {
                limits: store_limits,
                call: None,
            },
        );
        store.limiter(|s| &mut s.limits);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| WasiError::Limit)?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(WasiError::Contract)?;
        let start = instance
            .get_func(&store, "_start")
            .ok_or(WasiError::Contract)?;
        let ty = start.ty(&store);
        if !ty.params().is_empty() || !ty.results().is_empty() {
            return Err(WasiError::Contract);
        }
        Ok(Self {
            store,
            memory,
            start,
            continuation: None,
            started: false,
            pending: None,
            argv,
            limits,
            fuel: limits.total_fuel,
            output: 0,
            closed: [false; 3],
            terminal: None,
            io_buffer: [0; IO_CHUNK],
            io_ready: false,
        })
    }
    /// Pending solely at a fuel boundary, without a pending host I/O call.
    pub fn yielded_for_fuel(&self) -> bool {
        self.terminal.is_none()
            && self.pending.is_none()
            && matches!(self.continuation, Some(Continuation::Fuel(_)))
    }
    pub fn consumed_fuel(&self) -> u64 {
        self.limits.total_fuel - self.fuel
    }
    pub fn cancel(&mut self) {
        let _ = self.finish(WasiTerminal::Cancelled);
    }
    pub fn deny(&mut self) {
        let _ = self.finish(WasiTerminal::Denied);
    }
    fn finish(&mut self, terminal: WasiTerminal) -> Poll<WasiTerminal> {
        if self.terminal.is_none() {
            self.terminal = Some(terminal);
        }
        self.continuation = None;
        self.pending = None;
        self.store.data_mut().call = None;
        Poll::Ready(self.terminal.unwrap())
    }
    fn charge(&mut self, amount: u64) -> bool {
        match self.fuel.checked_sub(amount) {
            Some(left) => {
                self.fuel = left;
                true
            }
            None => false,
        }
    }
    /// One bounded interpreter quantum or host operation. Ready is stable and
    /// cannot execute guest instructions again, including after proc_exit.
    pub fn poll(&mut self, cx: &mut Context<'_>, io: &mut dyn WasiIo) -> Poll<WasiTerminal> {
        if let Some(terminal) = self.terminal {
            return Poll::Ready(terminal);
        }
        if let Some(call) = self.pending.take() {
            let host_cost = 100
                + match call.name.as_str() {
                    "fd_read" | "fd_write" => call.args[2].saturating_mul(8),
                    "args_get" => self.argv.iter().map(|value| value.len() as u64).sum(),
                    _ => 0,
                };
            if !self.io_ready && !self.charge(host_cost) {
                return self.finish(WasiTerminal::LimitExceeded);
            }
            self.io_ready = true;
            let errno = match self.host(&call, cx, io) {
                Poll::Pending => {
                    self.pending = Some(call);
                    return Poll::Pending;
                }
                Poll::Ready(Err(terminal)) => return self.finish(terminal),
                Poll::Ready(Ok(errno)) => errno,
            };
            self.io_ready = false;
            if let Some(Continuation::Host(_, result)) = &mut self.continuation {
                *result = Some(errno);
            } else {
                return self.finish(WasiTerminal::Trapped);
            }
        }
        if self.fuel == 0 {
            return self.finish(WasiTerminal::LimitExceeded);
        }
        let grant = self.fuel.min(self.limits.poll_quantum);
        if self.store.set_fuel(grant).is_err() {
            return self.finish(WasiTerminal::Trapped);
        }
        let result = match self.continuation.take() {
            Some(Continuation::Fuel(c)) => {
                if c.required_fuel() > grant {
                    return self.finish(WasiTerminal::LimitExceeded);
                }
                c.resume(&mut self.store, &mut [])
            }
            Some(Continuation::Host(c, Some(errno))) => {
                c.resume(&mut self.store, &[Val::I32(errno)], &mut [])
            }
            None if !self.started => {
                self.started = true;
                self.start.call_resumable(&mut self.store, &[], &mut [])
            }
            _ => return self.finish(WasiTerminal::Trapped),
        };
        self.fuel -= grant - self.store.get_fuel().unwrap_or(0).min(grant);
        match result {
            Ok(ResumableCall::Finished) => self.finish(WasiTerminal::Exited(0)),
            Ok(ResumableCall::OutOfFuel(c)) => {
                if c.required_fuel() > self.fuel || c.required_fuel() > self.limits.poll_quantum {
                    return self.finish(WasiTerminal::LimitExceeded);
                }
                self.continuation = Some(Continuation::Fuel(c));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(ResumableCall::HostTrap(c)) => {
                let Some(call) = self.store.data_mut().call.take() else {
                    return self.finish(WasiTerminal::Trapped);
                };
                self.pending = Some(call);
                self.continuation = Some(Continuation::Host(c, None));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => self.finish(
                if matches!(
                    error.as_trap_code(),
                    Some(
                        wasmi::TrapCode::GrowthOperationLimited
                            | wasmi::TrapCode::OutOfFuel
                            | wasmi::TrapCode::StackOverflow
                    )
                ) {
                    WasiTerminal::LimitExceeded
                } else {
                    WasiTerminal::Trapped
                },
            ),
        }
    }
    fn range(&self, address: u64, size: usize) -> bool {
        usize::try_from(address)
            .ok()
            .and_then(|p| p.checked_add(size))
            .is_some_and(|end| end <= self.memory.data_size(&self.store))
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), i32> {
        self.memory
            .write(&mut self.store, address as usize, bytes)
            .map_err(|_| FAULT)
    }
    fn u32(&mut self, address: u64, value: u32) -> Result<(), i32> {
        self.write(address, &value.to_le_bytes())
    }
    fn read_u32(&self, address: u64) -> Result<u32, i32> {
        let mut bytes = [0; 4];
        self.memory
            .read(&self.store, address as usize, &mut bytes)
            .map_err(|_| FAULT)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn host(
        &mut self,
        call: &HostCall,
        cx: &mut Context<'_>,
        io: &mut dyn WasiIo,
    ) -> Poll<Result<i32, WasiTerminal>> {
        if call.name == "proc_exit" {
            return Poll::Ready(Err(WasiTerminal::Exited(call.args[0] as u32)));
        }
        if call.name == "fd_read" || call.name == "fd_write" {
            return self.host_io(call, cx, io);
        }
        if call.name == "clock_time_get" || call.name == "clock_res_get" {
            let time = call.name == "clock_time_get";
            let address = call.args[if time { 2 } else { 1 }];
            // Validate the entire timestamp before consulting the embedding.
            if !self.range(address, 8) {
                return Poll::Ready(Ok(FAULT));
            }
            if call.args[0] > 3 {
                return Poll::Ready(Ok(28)); // INVAL
            }
            let result = if time {
                io.clock_time(call.args[0] as u32, call.args[1])
            } else {
                io.clock_resolution(call.args[0] as u32)
            };
            return Poll::Ready(match result {
                Ok(0) if !time => Ok(IO),
                Ok(ns) => Ok(self
                    .write(address, &ns.to_le_bytes())
                    .map_or_else(|e| e, |_| SUCCESS)),
                Err(WasiClockError::Unsupported) => Ok(NOSYS),
                Err(WasiClockError::Denied) => Err(WasiTerminal::Denied),
                Err(WasiClockError::Failed) => Ok(IO),
            });
        }
        Poll::Ready(Ok(self.host_sync(call).unwrap_or_else(|errno| errno)))
    }
    fn host_sync(&mut self, call: &HostCall) -> Result<i32, i32> {
        let a = call.args;
        match call.name.as_str() {
            "args_sizes_get" | "environ_sizes_get" => {
                if !self.range(a[0], 4) || !self.range(a[1], 4) {
                    return Err(FAULT);
                }
                let (count, bytes) = if call.name == "args_sizes_get" {
                    (
                        self.argv.len() as u32,
                        self.argv.iter().map(|v| v.len() as u32).sum(),
                    )
                } else {
                    (0, 0)
                };
                self.u32(a[0], count)?;
                self.u32(a[1], bytes)?;
            }
            "args_get" => {
                let bytes: usize = self.argv.iter().map(Vec::len).sum();
                if !self.range(a[0], self.argv.len() * 4) || !self.range(a[1], bytes) {
                    return Err(FAULT);
                }
                let mut offset = a[1];
                for i in 0..self.argv.len() {
                    self.u32(a[0] + i as u64 * 4, offset as u32)?;
                    let value = &self.argv[i];
                    self.memory
                        .write(&mut self.store, offset as usize, value)
                        .map_err(|_| FAULT)?;
                    offset += value.len() as u64;
                }
            }
            "environ_get" => (),
            "fd_close" => {
                self.fd(a[0])?;
                self.closed[a[0] as usize] = true;
            }
            "fd_fdstat_get" | "fd_filestat_get" => {
                self.fd(a[0])?;
                let mut buf = [0u8; 64];
                let len = if call.name == "fd_fdstat_get" {
                    // Bounded byte pipes, not TTYs. WASI has no FIFO filetype;
                    // UNKNOWN prevents libc isatty() from selecting a REPL.
                    buf[0] = 0;
                    let rights: u64 = if a[0] == 0 { 2 } else { 64 } | (1 << 21);
                    buf[8..16].copy_from_slice(&rights.to_le_bytes());
                    24
                } else {
                    buf[16] = 0;
                    buf[24..32].copy_from_slice(&1u64.to_le_bytes());
                    64
                };
                self.write(a[1], &buf[..len])?;
            }
            "fd_seek" | "fd_tell" => {
                self.fd(a[0])?;
                return Err(SPIPE);
            }
            "fd_prestat_get" | "fd_prestat_dir_name" => return Err(BADF),
            _ => return Err(NOSYS),
        }
        Ok(SUCCESS)
    }
    fn fd(&self, fd: u64) -> Result<(), i32> {
        if fd >= 3 || self.closed[fd as usize] {
            Err(BADF)
        } else {
            Ok(())
        }
    }
    fn host_io(
        &mut self,
        call: &HostCall,
        cx: &mut Context<'_>,
        io: &mut dyn WasiIo,
    ) -> Poll<Result<i32, WasiTerminal>> {
        let a = call.args;
        let read = call.name == "fd_read";
        if self.fd(a[0]).is_err() || (read && a[0] != 0) || (!read && a[0] == 0) {
            return Poll::Ready(Ok(BADF));
        }
        let count = a[2] as usize;
        if count > 1024 {
            return Poll::Ready(Err(WasiTerminal::LimitExceeded));
        }
        if !self.range(a[1], count * 8) || !self.range(a[3], 4) {
            return Poll::Ready(Ok(FAULT));
        }
        // Validate every iovec before any externally visible I/O, including later vectors.
        let mut selected = None;
        for i in 0..count {
            let address = self.read_u32(a[1] + i as u64 * 8).unwrap() as u64;
            let len = self.read_u32(a[1] + i as u64 * 8 + 4).unwrap() as usize;
            if !self.range(address, len) {
                return Poll::Ready(Ok(FAULT));
            }
            if selected.is_none() && len != 0 {
                selected = Some((address, len.min(IO_CHUNK)));
            }
        }
        let Some((address, len)) = selected else {
            let _ = self.u32(a[3], 0);
            return Poll::Ready(Ok(SUCCESS));
        };
        if self.fuel < len as u64 {
            return Poll::Ready(Err(WasiTerminal::LimitExceeded));
        }
        if !read
            && self
                .output
                .checked_add(len)
                .is_none_or(|n| n > self.limits.output_bytes)
        {
            return Poll::Ready(Err(WasiTerminal::LimitExceeded));
        }
        let result = if read {
            io.read(cx, &mut self.io_buffer[..len])
        } else {
            if self
                .memory
                .read(&self.store, address as usize, &mut self.io_buffer[..len])
                .is_err()
            {
                return Poll::Ready(Ok(FAULT));
            }
            io.write(cx, a[0] as u32, &self.io_buffer[..len])
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(WasiIoError::Denied)) => Poll::Ready(Err(WasiTerminal::Denied)),
            Poll::Ready(Err(error)) => Poll::Ready(Ok(if error == WasiIoError::Closed {
                PIPE
            } else {
                IO
            })),
            Poll::Ready(Ok(n)) => {
                if n > len || (!read && n == 0) {
                    return Poll::Ready(Err(WasiTerminal::Trapped));
                }
                self.charge(n as u64);
                if read {
                    if self
                        .memory
                        .write(&mut self.store, address as usize, &self.io_buffer[..n])
                        .is_err()
                    {
                        return Poll::Ready(Err(WasiTerminal::Trapped));
                    }
                } else {
                    self.output += n;
                }
                let _ = self.u32(a[3], n as u32);
                Poll::Ready(Ok(SUCCESS))
            }
        }
    }
}
