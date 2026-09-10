//! Live pre-MMU contract acceptance. This test image publishes copied CPU
//! metadata and reservation-subtracted heap ranges; Mars resource policy is separate.
use super::Board;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU8, Ordering},
};
use vibeos_hal::{
    boot::{BootError, BootRequest},
    fdt::Fdt,
    Board as _,
};
struct State {
    ready: AtomicU8,
    harts: UnsafeCell<[usize; 4]>,
    hz: UnsafeCell<u64>,
    heap: UnsafeCell<vibeos_hal::memory::BootMemory<16>>,
}
// Boot hart writes once before Release; readers require Acquire publication.
unsafe impl Sync for State {}
static STATE: State = State {
    ready: AtomicU8::new(0),
    harts: UnsafeCell::new([0; 4]),
    hz: UnsafeCell::new(0),
    heap: UnsafeCell::new(vibeos_hal::memory::BootMemory::new()),
};
pub unsafe fn admit(request: BootRequest) -> Result<(), BootError> {
    let bytes = unsafe { request.dtb()? };
    let tree = Fdt::new(bytes).map_err(|_| BootError::InvalidDtb)?;
    let cpus = tree.cpus::<16>().map_err(|_| BootError::InvalidCpu)?;
    if u64::from(cpus.timebase_hz) != Board::INFO.timebase_hz {
        return Err(BootError::InvalidTimebase);
    }
    if !Board::HART_IDS.contains(&request.physical_hart)
        || Board::HART_IDS.iter().any(|hart| {
            !cpus
                .entries()
                .iter()
                .any(|cpu| cpu.hart == *hart && cpu.enabled && cpu.supports_sv39())
        })
    {
        return Err(BootError::InvalidCpu);
    }
    let memory = tree
        .memory::<16>(request.dtb_address)
        .map_err(|_| BootError::InvalidMemory)?;
    let heap = request.usable_heap(&memory)?;
    let mut harts = [request.physical_hart; 4];
    let mut next = 1;
    for &hart in Board::HART_IDS {
        if hart != request.physical_hart {
            harts[next] = hart;
            next += 1;
        }
    }
    STATE
        .ready
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| BootError::AlreadyInitialized)?;
    unsafe {
        *STATE.heap.get() = heap;
        *STATE.harts.get() = harts;
        *STATE.hz.get() = u64::from(cpus.timebase_hz);
    }
    STATE.ready.store(2, Ordering::Release);
    Ok(())
}
pub fn hart_ids() -> &'static [usize] {
    assert_eq!(STATE.ready.load(Ordering::Acquire), 2);
    unsafe { &*STATE.harts.get() }
}
pub fn timebase_hz() -> u64 {
    assert_eq!(STATE.ready.load(Ordering::Acquire), 2);
    unsafe { *STATE.hz.get() }
}

pub fn heap_regions() -> &'static [vibeos_hal::AddressRange] {
    assert_eq!(STATE.ready.load(Ordering::Acquire), 2);
    unsafe { (&*STATE.heap.get()).ranges() }
}
