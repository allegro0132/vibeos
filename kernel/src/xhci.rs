//! Kernel composition adapter for the board-independent XHCI driver.
//!
//! PCI discovery, interrupt routing, synchronization, task wakeups, and TTY
//! injection are kernel policy. The XHCI/USB/BOT/HID engine and its fixed DMA
//! layout live in `vibeos-driver-xhci`.

extern crate alloc;

use alloc::vec::Vec;

use crate::pci::Bar;
use crate::sync::SpinLock;
use vibeos_hal::usb::{host, MmioRegion};

pub use vibeos_hal::usb::{DeviceInfo, DeviceKind, Info};

static CONTROLLER: SpinLock<bool> = SpinLock::new(false);
static IRQ_WAIT: crate::exec::WaitQueue = crate::exec::WaitQueue::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BarMissing,
    BarOutsidePlatform,
    InterruptMissing,
    PciConfiguration,
    InterruptRoute,
    Driver(vibeos_hal::usb::Error),
}

impl From<vibeos_hal::usb::Error> for Error {
    fn from(error: vibeos_hal::usb::Error) -> Self {
        Self::Driver(error)
    }
}

pub fn init() -> Result<Option<Info>, Error> {
    // Holding the composition lock across initialization prevents a retry from
    // manufacturing a second mutable reference to the permanent DMA storage.
    let mut published = CONTROLLER.lock();
    if *published {
        return Ok(Some(unsafe { (host().info)() }));
    }

    let function = match crate::pci::find_xhci() {
        Some(function) => function,
        None => return Ok(None),
    };
    let mmio = bar_region(function.bars[0])?;
    let irq = function.interrupt_line.ok_or(Error::InterruptMissing)?;
    crate::pci::enable_bus_mastering(function).map_err(|_| Error::PciConfiguration)?;

    // Safety: the BSP maps the complete PCI MMIO aperture, `bar_region`
    // validates this function's entire BAR within it, and the static DMA area
    // is identity mapped and exclusively borrowed while `published` is empty.
    let info = unsafe { (host().initialize)(mmio, irq) }?;
    let irq_context = unsafe { (host().interrupt_context)() };
    if crate::plic::register(irq, irq_handler, irq_context).is_err() {
        unsafe {
            (host().disable_interrupts)();
        }
        return Err(Error::InterruptRoute);
    }
    unsafe {
        (host().enable_interrupts)();
    }
    if crate::plic::enable(irq).is_err() {
        unsafe {
            (host().disable_interrupts)();
        }
        crate::plic::unregister(irq);
        return Err(Error::InterruptRoute);
    }
    *published = true;
    Ok(Some(info))
}

pub fn info() -> Option<Info> {
    let active = CONTROLLER.lock();
    (*active).then(|| unsafe { (host().info)() })
}
pub fn devices() -> Vec<DeviceInfo> {
    let active = CONTROLLER.lock();
    let mut output = Vec::new();
    if *active {
        unsafe {
            (host().devices)(&mut |device| output.push(device));
        }
    }
    output
}
pub fn read_sector(sector: u64) -> Result<[u8; 512], Error> {
    let active = CONTROLLER.lock();
    if !*active {
        return Err(Error::Driver(vibeos_hal::usb::Error::NoMassStorage));
    }
    unsafe { (host().read_sector)(sector).map_err(Error::Driver) }
}
pub fn write_sector(sector: u64, bytes: &[u8; 512]) -> Result<(), Error> {
    let active = CONTROLLER.lock();
    if !*active {
        return Err(Error::Driver(vibeos_hal::usb::Error::NoMassStorage));
    }
    unsafe { (host().write_sector)(sector, bytes).map_err(Error::Driver) }
}

pub async fn service_task() {
    loop {
        // Register before inspecting the event ring. An IRQ racing the drain
        // advances this waiter's epoch, so awaiting it cannot lose the wake.
        let ready = IRQ_WAIT.wait();
        let input = {
            let active = CONTROLLER.lock();
            (*active).then(|| unsafe { (host().service)() })
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
    let aperture = crate::platform::pci().mmio;
    let end = base.checked_add(length).ok_or(Error::BarOutsidePlatform)?;
    if base < aperture.start || end > aperture.end {
        return Err(Error::BarOutsidePlatform);
    }
    MmioRegion::new(base, length).map_err(Error::Driver)
}

fn irq_handler(context: usize, _irq_entry: u64) {
    // SAFETY: firmware produced this token for the live mapped controller.
    // Its IRQ callback touches MMIO only, without borrowing controller state.
    if unsafe { (host().acknowledge)(context) } {
        IRQ_WAIT.wake_all();
    }
}
