// Execute the actual runtime with the kernel allocator in a Duo-sized heap.
// A resident SYSTEM allocation and a freed upload-sized buffer reproduce the
// pressure and size-class mismatch omitted by requested-byte accounting.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use vibeos_core::heap::{Heap, enter_owner};
static HEAP: Heap = Heap::new();
static START: AtomicUsize = AtomicUsize::new(0);
static END: AtomicUsize = AtomicUsize::new(0);
static FAILURE: std::sync::Mutex<Option<vibeos_core::heap::AllocationFailure>> = std::sync::Mutex::new(None);
fn record(p: *mut u8) -> *mut u8 {
    if p.is_null() { *FAILURE.lock().unwrap() = HEAP.last_failure(); }
    p
}
struct BoardAllocator;
unsafe impl GlobalAlloc for BoardAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if START.load(Ordering::Relaxed) == 0 { unsafe { System.alloc(layout) } }
        else { record(unsafe { HEAP.alloc(layout) }) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if (START.load(Ordering::Relaxed)..END.load(Ordering::Relaxed)).contains(&(ptr as usize)) {
            record(unsafe { HEAP.realloc(ptr, layout, size) })
        } else { unsafe { System.realloc(ptr, layout, size) } }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let address = ptr as usize;
        if (START.load(Ordering::Relaxed)..END.load(Ordering::Relaxed)).contains(&address) {
            unsafe { HEAP.dealloc(ptr, layout); }
        } else { unsafe { System.dealloc(ptr, layout); } }
    }
}
#[global_allocator]
static ALLOCATOR: BoardAllocator = BoardAllocator;
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
    const BYTES: usize = 50_442_240;
    vibeos_core::arch::set_test_hart_id(0);
    let memory = unsafe { System.alloc(Layout::from_size_align(BYTES, 4096).unwrap()) };
    assert!(!memory.is_null());
    let start = memory as usize;
    unsafe { HEAP.init(start, start + BYTES); }
    END.store(start + BYTES, Ordering::Relaxed);
    START.store(start, Ordering::Relaxed);
    let _resident = vec![0u8; 3 * 1024 * 1024]; // 4 MiB charge, conservative baseline
    let upload = vec![0u8; 12 * 1024 * 1024]; // 16 MiB, freed before module load
    std::hint::black_box(&upload);
    drop(upload);
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert!(!args.is_empty(), "usage: run MODULE.wasm [arguments...]");
    let module = std::fs::read(&args[0]).unwrap();
    let limits = WasiLimits {
        #[cfg(not(feature = "python-wasi"))]
        total_fuel: 100_000_000_000,
        ..Default::default()
    };
    let owner = HEAP.create_owner(40 * 1024 * 1024).unwrap();
    let mut owner_scope = unsafe { enter_owner(owner) };
    let setup = Instant::now();
    let mut invocation = match WasiInvocation::new(&module, &args, limits) {
        Ok(value) => value,
        Err(error) => { eprintln!("admission={error:?} heap={:?} failure={:?}", HEAP.snapshot(), *FAILURE.lock().unwrap()); std::process::exit(1); }
    };
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
    drop(invocation);
    owner_scope.restore();
    eprintln!("board_heap={:?} failure={:?}", HEAP.snapshot(), *FAILURE.lock().unwrap());
    std::process::exit(match terminal {
        WasiTerminal::Exited(0) => 0,
        _ => 1,
    });
}
