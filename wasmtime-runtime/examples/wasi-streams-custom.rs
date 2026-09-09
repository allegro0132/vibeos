//! Real standard-library WASI program through the no_std custom platform port.
#[path = "support/host_platform.rs"]
mod host_platform;
use vibeos_wasmtime_runtime::{
    configuration,
    wasi::{self, Clock, Invocation},
};
struct HostClock(std::time::Instant);
impl Clock for HostClock {
    fn time(&mut self, id: u32, _precision: u64) -> Result<u64, i32> {
        match id {
            0 => Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| 29)?
                .as_nanos() as u64),
            1 => Ok(self.0.elapsed().as_nanos() as u64),
            _ => Err(52),
        }
    }
    fn resolution(&mut self, id: u32) -> Result<u64, i32> {
        if id < 2 { Ok(1) } else { Err(52) }
    }
}
fn main() -> wasmtime::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("MODULE.wasm [arguments...]");
    let argv = std::iter::once(path.clone())
        .chain(args)
        .collect::<Vec<_>>();
    let mut config = configuration();
    config.max_wasm_stack(32 * 1024).async_support(true).async_stack_size(256 * 1024);
    let engine = wasmtime::Engine::new(&config)?;
    let module = wasi::compile(&engine, &std::fs::read(path)?)?;
    let linker = wasi::linker_streams::<HostClock>(&engine, &module)?;
    let state = Invocation::with_streams(&argv, HostClock(std::time::Instant::now()), Box::new(HostStreams(false)))?;
    let mut store = wasmtime::Store::new(&engine, state);
    store.set_fuel(100_000_000_000)?;
    store.fuel_async_yield_interval(Some(10_000))?;
    let instance = drive(linker.instantiate_async(&mut store, &module))?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let result = drive(start.call_async(&mut store, ()));
    assert!(store.data().stdout.is_empty() && store.data().stderr.is_empty());
    let exit = match store.data().exit {
        Some(code) => {
            drop(result);
            code
        }
        None => {
            result?;
            0
        }
    };
    eprintln!("wasi_exit={exit} fuel_remaining={}", store.get_fuel()?);
    drop((instance, store, linker, module, engine));
    assert_eq!(host_platform::memory_counts().2, 0);
    if exit != 0 {
        std::process::exit(if exit <= 255 { exit as i32 } else { 1 });
    }
    Ok(())
}

struct HostStreams(bool);
impl HostStreams {
    fn wait(&mut self, cx: &mut std::task::Context<'_>) -> bool {
        self.0 = !self.0;
        if self.0 { cx.waker().wake_by_ref(); }
        self.0
    }
}
impl wasi::Streams for HostStreams {
    fn read(&mut self, cx: &mut std::task::Context<'_>, bytes: &mut [u8]) -> std::task::Poll<Result<usize, i32>> {
        use std::io::Read;
        if self.wait(cx) { return std::task::Poll::Pending; }
        let len = bytes.len().min(7);
        std::task::Poll::Ready(std::io::stdin().read(&mut bytes[..len]).map_err(|_| 29))
    }
    fn write(&mut self, cx: &mut std::task::Context<'_>, fd: u32, bytes: &[u8]) -> std::task::Poll<Result<usize, i32>> {
        use std::io::Write;
        if self.wait(cx) { return std::task::Poll::Pending; }
        let bytes = &bytes[..bytes.len().min(11)];
        std::task::Poll::Ready(if fd == 1 { std::io::stdout().write(bytes) } else { std::io::stderr().write(bytes) }.map_err(|_| 29))
    }
}
fn drive<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop { if let std::task::Poll::Ready(result) = future.as_mut().poll(&mut cx) { return result; } }
}
