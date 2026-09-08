// Host diagnostic runner for the exact capability-neutral WASI runtime.
// With instruction-profile, stderr also contains dynamic Wasmi opcode counts.
use std::{
    io::{Read, Write},
    task::{Context, Poll, Waker},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use vibeos_wasi_runtime::*;

struct Io(Instant);
impl WasiIo for Io {
    fn clock_time(&mut self, id: u32, _: u64) -> Result<u64, WasiClockError> {
        match id {
            0 => Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64),
            1 => Ok(self.0.elapsed().as_nanos() as u64),
            _ => Err(WasiClockError::Unsupported),
        }
    }
    fn clock_resolution(&mut self, id: u32) -> Result<u64, WasiClockError> {
        if id < 2 {
            Ok(1)
        } else {
            Err(WasiClockError::Unsupported)
        }
    }
    fn read(&mut self, _: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, WasiIoError>> {
        Poll::Ready(
            std::io::stdin()
                .read(bytes)
                .map_err(|_| WasiIoError::Failed),
        )
    }
    fn write(
        &mut self,
        _: &mut Context<'_>,
        fd: u32,
        bytes: &[u8],
    ) -> Poll<Result<usize, WasiIoError>> {
        Poll::Ready(
            match fd {
                1 => std::io::stdout().write(bytes),
                2 => std::io::stderr().write(bytes),
                _ => return Poll::Ready(Err(WasiIoError::Closed)),
            }
            .map_err(|_| WasiIoError::Failed),
        )
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(!args.is_empty(), "usage: run MODULE.wasm [arguments...]");
    let module = std::fs::read(&args[0]).unwrap();
    let limits = WasiLimits {
        total_fuel: 100_000_000_000,
        ..Default::default()
    };
    let setup = Instant::now();
    let mut invocation = WasiInvocation::new(&module, &args, limits).unwrap();
    eprintln!("setup_seconds={:.6} limits={limits:?} engine=vendored-wasmi extra_checks=true native_cache=false", setup.elapsed().as_secs_f64());
    let mut io = Io(Instant::now());
    let mut cx = Context::from_waker(Waker::noop());
    let mut polls = 0u64;
    let terminal = loop {
        polls += 1;
        if let Poll::Ready(result) = invocation.poll(&mut cx, &mut io) {
            break result;
        }
    };
    eprintln!(
        "terminal={terminal:?} polls={polls} fuel={} seconds={:.6}",
        invocation.consumed_fuel(),
        io.0.elapsed().as_secs_f64()
    );
    #[cfg(feature = "instruction-profile")]
    for (name, count) in wasmi::instruction_profile::take() {
        eprintln!("opcode\t{name}\t{count}");
    }
    std::process::exit(match terminal {
        WasiTerminal::Exited(0) => 0,
        _ => 1,
    });
}
