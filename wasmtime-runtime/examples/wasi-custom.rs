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
    use std::io::{Read, Write};
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("MODULE.wasm [arguments...]");
    let argv = std::iter::once(path.clone())
        .chain(args)
        .collect::<Vec<_>>();
    let mut input = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut input)?;
    let mut config = configuration();
    config.max_wasm_stack(32 * 1024);
    let engine = wasmtime::Engine::new(&config)?;
    let module = wasi::compile(&engine, &std::fs::read(path)?)?;
    let linker = wasi::linker::<HostClock>(&engine, &module)?;
    let state = Invocation::new(&argv, input, HostClock(std::time::Instant::now()))?;
    let mut store = wasmtime::Store::new(&engine, state);
    store.set_fuel(100_000_000_000)?;
    let instance = linker.instantiate(&mut store, &module)?;
    let result = instance
        .get_typed_func::<(), ()>(&mut store, "_start")?
        .call(&mut store, ());
    std::io::stdout().write_all(&store.data().stdout)?;
    std::io::stderr().write_all(&store.data().stderr)?;
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
