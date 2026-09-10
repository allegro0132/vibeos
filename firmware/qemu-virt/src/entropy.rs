//! Firmware owns the entropy engine and DMA state; IRQ ack is state-free.
use super::Board;
use core::cell::UnsafeCell;
use vibeos_driver_virtio_mmio::MmioTransport;
use vibeos_driver_virtio_rng::{self as driver, Engine};
use vibeos_hal::{
    entropy::{EntropyDevice, Error, Pending},
    Board as _,
};
struct State {
    engine: Option<Engine>,
    pending: Pending<driver::Submission>,
}
struct Storage(UnsafeCell<State>);
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(State {
    engine: None,
    pending: Pending::new(),
}));
// SAFETY: operation table caller owns the unique device/DMA claim. IRQs do
// not access this state. Kernel scheduler serializes completion and mutation.
unsafe fn state() -> &'static mut State {
    &mut *STORAGE.0.get()
}
fn engine(s: &mut State) -> &mut Engine {
    s.engine.as_mut().expect("prepared entropy device")
}
unsafe fn read_state() -> &'static State { &*STORAGE.0.get() }
unsafe fn read_engine() -> &'static Engine { read_state().engine.as_ref().expect("prepared entropy device") }
fn error(e: driver::Error) -> Error {
    match e {
        driver::Error::InvalidLength => Error::InvalidLength,
        driver::Error::Busy => Error::Busy,
        driver::Error::Protocol => Error::Protocol,
        driver::Error::Unsupported => Error::Unsupported,
        driver::Error::DriverRestarted => Error::DriverRestarted,
        driver::Error::IdentityExhausted => Error::IdentityExhausted,
        driver::Error::Quarantined => Error::Quarantined,
    }
}
unsafe fn transport(slot: usize, base: usize) -> Result<MmioTransport, Error> {
    let t = MmioTransport::probe_slot(Board::INFO.virtio_mmio.ok_or(Error::Unsupported)?, slot)
        .ok_or(Error::Unsupported)?;
    if t.base() != base || t.device_id() != 4 {
        return Err(Error::Unsupported);
    }
    Ok(t)
}
#[no_mangle]
pub static VIBEOS_ENTROPY_DEVICE: EntropyDevice = EntropyDevice {
    dma_base: driver::dma_base,
    dma_bytes: driver::DMA_BYTES,
    prepare: |slot, base, epoch, budget| unsafe {
        let t = transport(slot, base)?;
        let s = state();
        s.pending.clear();
        s.engine = None;
        s.engine = Some(Engine::prepare(t, epoch, budget).map_err(error)?);
        Ok(())
    },
    start: || unsafe { read_engine().start().map_err(error) },
    epoch: || unsafe { read_engine().epoch() },
    accepted_features: || unsafe { read_engine().accepted_features() },
    operational: || unsafe { read_engine().operational() },
    submit: |bytes| unsafe {
        let s = state();
        let epoch = engine(s).epoch();
        let token = s.pending.reserve(epoch)?;
        let submitted = engine(s).submit(bytes).map_err(error)?;
        s.pending.publish(token, submitted);
        Ok(token)
    },
    completion: |token| unsafe {
        match read_state().pending.get(token) {
            Some(submission) => read_engine().completion(submission).is_some(),
            None => false,
        }
    },
    finish: |token, output| unsafe {
        let s = state();
        let submission = s.pending.get(token).ok_or(Error::DriverRestarted)?;
        let result = engine(s).finish(submission, output).map_err(error);
        if result.is_ok() {
            s.pending.clear();
        }
        result
    },
    require_reset: || unsafe { engine(state()).require_reset() },
    reset_and_prepare: |epoch, budget| unsafe {
        let s = state();
        let result = engine(s).reset_and_prepare(epoch, budget).map_err(error);
        if result.is_ok() {
            s.pending.clear();
        }
        result
    },
    shutdown: |budget| unsafe {
        let s = state();
        let result = engine(s).shutdown(budget).map_err(error);
        if result.is_ok() {
            s.pending.clear();
        }
        result
    },
    confirmed_reset: |slot, base, budget| unsafe {
        let Ok(t) = transport(slot, base) else {
            return false;
        };
        let reset = driver::confirmed_reset(t, budget);
        if reset {
            let s = state();
            s.pending.clear();
            s.engine = None;
        }
        reset
    },
    acknowledge: |base| unsafe { driver::acknowledge_interrupt_at(base) },
};
