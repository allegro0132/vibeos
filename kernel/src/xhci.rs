//! Kernel composition adapter for the board-independent XHCI driver.
//!
//! PCI discovery, interrupt routing, synchronization, task wakeups, and TTY
//! injection are kernel policy. The XHCI/USB/BOT/HID engine and its fixed DMA
//! layout live in `vibeos-driver-xhci`.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::UnsafeCell;

use crate::pci::Bar;
use crate::sync::SpinLock;
use vibeos_driver_xhci::{Controller, DmaStorage, InterruptHandle, MmioRegion, XhciResources};

pub use vibeos_driver_xhci::{DeviceInfo, DeviceKind, Info};

struct SharedDma(UnsafeCell<DmaStorage>);

// Safety: `CONTROLLER` is the only owner admitted to this storage and every
// access through it is serialized by the kernel lock below.
unsafe impl Sync for SharedDma {}

#[link_section = ".dma"]
static DMA: SharedDma = SharedDma(UnsafeCell::new(DmaStorage::new()));

static CONTROLLER: SpinLock<Option<Controller<'static>>> = SpinLock::new(None);
static IRQ_WAIT: crate::exec::WaitQueue = crate::exec::WaitQueue::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BarMissing,
    BarOutsidePlatform,
    InterruptMissing,
    InterruptRoute,
    Driver(vibeos_driver_xhci::Error),
}

impl From<vibeos_driver_xhci::Error> for Error {
    fn from(error: vibeos_driver_xhci::Error) -> Self {
        Self::Driver(error)
    }
}

pub fn init() -> Result<Option<Info>, Error> {
    // Holding the composition lock across initialization prevents a retry from
    // manufacturing a second mutable reference to the permanent DMA storage.
    let mut published = CONTROLLER.lock();
    if let Some(controller) = published.as_ref() {
        return Ok(Some(controller.info()));
    }

    let function = match crate::pci::find_xhci() {
        Some(function) => function,
        None => return Ok(None),
    };
    let mmio = bar_region(function.bars[0])?;
    let irq = function.interrupt_line.ok_or(Error::InterruptMissing)?;
    function.enable_bus_mastering();

    // Safety: the BSP maps the complete PCI MMIO aperture, `bar_region`
    // validates this function's entire BAR within it, and the static DMA area
    // is identity mapped and exclusively borrowed while `published` is empty.
    let mut controller =
        unsafe { Controller::initialize(XhciResources { mmio, irq }, &mut *DMA.0.get()) }?;
    let info = controller.info();
    let irq_context = controller.interrupt_handle().into_context();
    crate::plic::register(irq, irq_handler, irq_context).map_err(|_| Error::InterruptRoute)?;

    controller.enable_interrupts();
    *published = Some(controller);
    if crate::plic::enable(irq).is_err() {
        if let Some(mut controller) = published.take() {
            controller.disable_interrupts();
        }
        crate::plic::unregister(irq);
        return Err(Error::InterruptRoute);
    }
    Ok(Some(info))
}

pub fn info() -> Option<Info> {
    CONTROLLER.lock().as_ref().map(Controller::info)
}

pub fn devices() -> Vec<DeviceInfo> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(|controller| controller.devices().collect())
        .unwrap_or_default()
}

pub fn read_sector(sector: u64) -> Result<[u8; 512], Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::Driver(vibeos_driver_xhci::Error::NoMassStorage))?
        .read_sector(sector)
        .map_err(Error::Driver)
}

pub fn write_sector(sector: u64, bytes: &[u8; 512]) -> Result<(), Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::Driver(vibeos_driver_xhci::Error::NoMassStorage))?
        .write_sector(sector, bytes)
        .map_err(Error::Driver)
}

pub async fn service_task() {
    loop {
        // Register before inspecting the event ring. An IRQ racing the drain
        // advances this waiter's epoch, so awaiting it cannot lose the wake.
        let ready = IRQ_WAIT.wait();
        let input = {
            let mut guard = CONTROLLER.lock();
            guard.as_mut().map(Controller::service)
        };
        if let Some(input) = input {
            for byte in input.as_slice() {
                crate::uart::inject_usb_input(*byte);
            }
        }
        ready.await;
    }
}

fn bar_region(bar: Bar) -> Result<MmioRegion, Error> {
    let (base, length) = match bar {
        Bar::Memory32 { address, size, .. } => (address as usize, size as usize),
        Bar::Memory64 { address, size, .. } => (
            usize::try_from(address).map_err(|_| Error::BarOutsidePlatform)?,
            usize::try_from(size).map_err(|_| Error::BarOutsidePlatform)?,
        ),
        _ => return Err(Error::BarMissing),
    };
    let aperture = crate::platform::PCI.mmio;
    let end = base.checked_add(length).ok_or(Error::BarOutsidePlatform)?;
    if base < aperture.start || end > aperture.end {
        return Err(Error::BarOutsidePlatform);
    }
    MmioRegion::new(base, length).map_err(Error::Driver)
}

fn irq_handler(context: usize, _irq_entry: u64) {
    // Safety: `context` was produced by `InterruptHandle::into_context` for
    // the published controller, and unregister happens before that mapping
    // could be retired.
    let handle = unsafe { InterruptHandle::from_context(context) };
    if handle.acknowledge() {
        IRQ_WAIT.wake_all();
    }
}
