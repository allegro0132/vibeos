// Host allocation diagnostic for sizing the CPython command on small boards.
// Requested allocator bytes exclude allocator metadata and fragmentation.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
static BUDDY: AtomicUsize = AtomicUsize::new(0);
static BUDDY_PEAK: AtomicUsize = AtomicUsize::new(0);
fn charge(layout: Layout) -> usize {
    (56 + layout.size().max(1) + layout.align().max(16) - 1).next_power_of_two()
}
fn buddy_add(n: usize) {
    let live = BUDDY.fetch_add(n, Ordering::Relaxed) + n;
    BUDDY_PEAK.fetch_max(live, Ordering::Relaxed);
}
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
struct Meter;
fn allocated(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() { allocated(layout.size()); buddy_add(charge(layout)); }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout); }
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        BUDDY.fetch_sub(charge(layout), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(size);
            let next_layout = Layout::from_size_align(size, layout.align()).unwrap();
            if charge(next_layout) != charge(layout) {
                buddy_add(charge(next_layout));
                BUDDY.fetch_sub(charge(layout), Ordering::Relaxed);
            }
        }
        next
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;
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
        #[cfg(not(feature = "python-wasi"))]
        total_fuel: 100_000_000_000,
        ..Default::default()
    };
    if std::env::var_os("WASI_DIAG").is_some() {
        let mut config = wasmi::Config::default();
        config.enforced_limits(wasmi::EnforcedLimits::strict());
        let result = wasmi::Module::new(&wasmi::Engine::new(&config), &module[..]);
        eprintln!("module diagnostic: {:?}", result.err());
        return;
    }
    let baseline = BUDDY.load(Ordering::Relaxed);
    BUDDY_PEAK.store(baseline, Ordering::Relaxed);
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
    eprintln!("allocation_live_bytes={} allocation_peak_bytes={}", LIVE.load(Ordering::Relaxed), PEAK.load(Ordering::Relaxed));
    eprintln!("estimated_buddy_peak={} estimated_invocation_peak={}", BUDDY_PEAK.load(Ordering::Relaxed), BUDDY_PEAK.load(Ordering::Relaxed)-baseline);
    std::process::exit(match terminal {
        WasiTerminal::Exited(0) => 0,
        _ => 1,
    });
}
