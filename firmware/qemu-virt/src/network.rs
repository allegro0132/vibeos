//! Queued packet controller composition; shared DMA remains owned by its driver.
use super::Board;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use vibeos_driver_virtio_mmio::MmioTransport;
use vibeos_driver_virtio_net::{self as driver, Engine};
use vibeos_hal::{
    queued_network::{Device, Error},
    Board as _,
};
struct Storage(UnsafeCell<Option<Engine>>);
unsafe impl Sync for Storage {}
static ENGINE: Storage = Storage(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
unsafe fn engine() -> &'static mut Engine {
    (*ENGINE.0.get()).as_mut().expect("attached network engine")
}
unsafe fn read_engine() -> &'static Engine {
    (*ENGINE.0.get()).as_ref().expect("attached network engine")
}
unsafe fn transport(slot: usize, base: usize) -> Option<MmioTransport> {
    let t = MmioTransport::probe_slot(Board::INFO.virtio_mmio?, slot)?;
    (t.base() == base && t.device_id() == 1).then_some(t)
}
#[no_mangle]
pub static VIBEOS_QUEUED_PACKET_DEVICE: Device = Device {
    dma_base: driver::dma_base,
    dma_size: driver::dma_size(),
    dma_quarantined: driver::dma_quarantined,
    attach: |slot, base, epoch| unsafe {
        let t = transport(slot, base).ok_or(Error::Offline)?;
        CLAIMED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Offline)?;
        match Engine::attach(t, epoch) {
            Ok(e) => {
                *ENGINE.0.get() = Some(e);
                Ok(())
            }
            Err(e) => {
                if !driver::dma_quarantined() {
                    CLAIMED.store(false, Ordering::Release);
                }
                Err(e)
            }
        }
    },
    info: || unsafe { read_engine().info() },
    start: || unsafe { read_engine().start() },
    service_events: |causes| unsafe { engine().service_device_events(causes) },
    drain_tx: || unsafe { engine().drain_transmit_completions() },
    receive: || unsafe { engine().receive() },
    transmit: |frame, deadline| unsafe { engine().submit_transmit(frame, deadline) },
    check_timeout: |now| unsafe { engine().check_timeout(now) },
    reset: |reason| unsafe { engine().reset_and_reinitialize(reason) },
    shutdown: |reason| unsafe {
        let Some(mut e) = (*ENGINE.0.get()).take() else {
            return !driver::dma_quarantined();
        };
        let reset = e.shutdown(reason);
        drop(e);
        if reset {
            CLAIMED.store(false, Ordering::Release);
        }
        reset
    },
    force_quarantine: || unsafe { engine().force_quarantine() },
    quarantine_before_attach: |slot, base| unsafe {
        CLAIMED.store(true, Ordering::Release);
        if let Some(t) = transport(slot, base) {
            driver::quarantine_before_attach(t);
        }
    },
    recover: |slot, base| unsafe {
        let Some(t) = transport(slot, base) else {
            return false;
        };
        vibeos_hal::devices::abandon_faulted_instance(&mut *ENGINE.0.get());
        let reset = driver::recover_faulted_transport(t);
        if reset {
            CLAIMED.store(false, Ordering::Release);
        }
        reset
    },
    acknowledge: |base| unsafe { driver::acknowledge_irq_at_base(base) },
};
