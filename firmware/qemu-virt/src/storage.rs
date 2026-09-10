//! Firmware-owned queued block engine. Kernel owns scheduler and recovery policy.
use super::Board;
use core::cell::UnsafeCell;
use vibeos_driver_virtio_blk::{self as driver, BlockEngine};
use vibeos_driver_virtio_core::{BlockOperation, UsedElement};
use vibeos_driver_virtio_mmio::MmioTransport;
use vibeos_hal::{
    queued_block::{Completion, Device, Error, Info, Operation, Submission},
    Board as _,
};
struct State {
    engine: Option<BlockEngine>,
    serial: u64,
    pending: Option<(Submission, driver::PendingSubmission)>,
}
struct Storage(UnsafeCell<State>);
// SAFETY: only the kernel's exclusive incarnation invokes mutations; IRQ ack
// does not access this state. Shared queries cannot race mutation.
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(State {
    engine: None,
    serial: 0,
    pending: None,
}));
unsafe fn state() -> &'static mut State {
    &mut *STORAGE.0.get()
}
unsafe fn read_engine() -> &'static BlockEngine {
    (*STORAGE.0.get())
        .engine
        .as_ref()
        .expect("attached block engine")
}
fn engine(s: &mut State) -> &mut BlockEngine {
    s.engine.as_mut().expect("attached block engine")
}
fn error(e: driver::HardwareError) -> Error {
    match e {
        driver::HardwareError::AlreadyClaimed => Error::AlreadyClaimed,
        driver::HardwareError::QueueFull => Error::QueueFull,
        driver::HardwareError::ReadOnly => Error::ReadOnly,
        driver::HardwareError::FlushUnsupported => Error::FlushUnsupported,
        driver::HardwareError::DeviceIo => Error::DeviceIo,
        driver::HardwareError::Unsupported => Error::Unsupported,
        driver::HardwareError::Protocol => Error::Protocol,
        driver::HardwareError::Quarantined => Error::Quarantined,
        driver::HardwareError::RestartRequired => Error::RestartRequired,
    }
}
unsafe fn transport(slot: usize, base: usize) -> Result<MmioTransport, Error> {
    let t = MmioTransport::probe_slot(Board::INFO.virtio_mmio.ok_or(Error::Unsupported)?, slot)
        .ok_or(Error::Unsupported)?;
    if t.base() != base || t.device_id() != 2 {
        return Err(Error::Unsupported);
    }
    Ok(t)
}
fn pending(s: &State, token: Submission) -> Result<driver::PendingSubmission, Error> {
    s.pending
        .filter(|(current, _)| *current == token)
        .map(|(_, p)| p)
        .ok_or(Error::Protocol)
}
#[no_mangle]
pub static VIBEOS_QUEUED_BLOCK_DEVICE: Device = Device {
    dma_base: driver::dma_base,
    dma_bytes: driver::DMA_BYTES,
    attach: |slot, base, epoch| unsafe {
        let t = transport(slot, base)?;
        let s = state();
        if s.engine.is_some() {
            return Err(Error::AlreadyClaimed);
        }
        s.engine = Some(BlockEngine::attach(t, epoch).map_err(error)?);
        s.pending = None;
        Ok(())
    },
    info: || unsafe {
        let info = read_engine().info();
        Info {
            capacity_sectors: info.capacity_sectors,
            queue_size: info.queue_size,
            read_only: info.read_only,
            supports_flush: info.supports_flush,
            epoch: info.epoch,
        }
    },
    mark_ready: || unsafe { read_engine().mark_ready() },
    needs_reset: || unsafe { read_engine().device_needs_reset() },
    refresh_capacity: || unsafe { engine(state()).refresh_capacity().map_err(error) },
    require_reset: || unsafe { engine(state()).require_device_reset() },
    submit: |op, data, published| unsafe {
        let s = state();
        if s.pending.is_some() {
            return Err(Error::QueueFull);
        }
        let serial = s.serial.checked_add(1).ok_or(Error::RestartRequired)?;
        let operation = match op {
            Operation::Read { sector, blocks: 1 } => BlockOperation::Read { sector },
            Operation::Write { sector, blocks: 1 } => BlockOperation::Write { sector },
            Operation::Read { sector, blocks } => BlockOperation::ReadBlocks {
                sector,
                block_count: blocks,
            },
            Operation::Write { sector, blocks } => BlockOperation::WriteBlocks {
                sector,
                block_count: blocks,
            },
            Operation::Flush => BlockOperation::Flush,
        };
        let submission = engine(s)
            .submit_tracked(operation, data, published)
            .map_err(error)?;
        let token = Submission {
            epoch: engine(s).info().epoch,
            serial,
            previous_used: submission.previous_used_index(),
        };
        s.serial = serial;
        s.pending = Some((token, submission));
        Ok(token)
    },
    notify: || unsafe { read_engine().notify() },
    used_index: || unsafe { read_engine().used_index() },
    used_element: |index| unsafe {
        let e = read_engine().used_element(index);
        Completion {
            id: e.id,
            length: e.length,
        }
    },
    complete: |token, index, used, out| unsafe {
        let s = state();
        let submitted = pending(s, token)?;
        let result = engine(s)
            .complete(
                submitted,
                index,
                UsedElement {
                    id: used.id,
                    length: used.length,
                },
                out,
            )
            .map_err(error);
        // The driver consumed the used entry for all media statuses; protocol
        // failure itself requires reset before any further submission.
        s.pending = None;
        result
    },
    timeout: |token| unsafe {
        let s = state();
        let submitted = pending(s, token)?;
        engine(s).timeout(submitted).map_err(error)
    },
    reset: || unsafe {
        let s = state();
        let result = engine(s).reset_and_reinitialize().map_err(error);
        if result.is_ok() {
            s.pending = None;
        }
        result
    },
    shutdown: || unsafe {
        let s = state();
        let e = s.engine.take().ok_or(Error::AlreadyClaimed)?;
        let result = e.shutdown().map_err(error);
        if result.is_ok() {
            s.pending = None;
        }
        result
    },
    recover: |slot, base| unsafe {
        let t = transport(slot, base)?;
        // Fault recovery is called only after the old owner cannot resume.
        driver::recover_after_fault(t).map_err(error)?;
        let s = state();
        s.engine = None;
        s.pending = None;
        Ok(())
    },
    acknowledge: |base| unsafe { driver::acknowledge_interrupt_at(base) },
};
