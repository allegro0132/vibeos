//! Permanent controller and DMA storage; IRQ routing remains kernel-owned.
use core::cell::UnsafeCell;
use vibeos_driver_xhci::{Controller, DmaStorage, InterruptHandle, XhciResources};
use vibeos_hal::usb::{Error, Host};
struct SharedDma(UnsafeCell<DmaStorage>);
unsafe impl Sync for SharedDma {}
#[link_section = ".dma"]
static DMA: SharedDma = SharedDma(UnsafeCell::new(DmaStorage::new()));
struct State(UnsafeCell<Option<(XhciResources, Controller<'static>)>>);
// SAFETY: kernel controller lock serializes all operations. IRQ acknowledgement
// uses only the immutable MMIO token and does not borrow this state or DMA.
unsafe impl Sync for State {}
static CONTROLLER: State = State(UnsafeCell::new(None));
unsafe fn controller() -> &'static mut Controller<'static> {
    &mut (*CONTROLLER.0.get())
        .as_mut()
        .expect("initialized USB host")
        .1
}
unsafe fn read_controller() -> &'static Controller<'static> {
    &(*CONTROLLER.0.get())
        .as_ref()
        .expect("initialized USB host")
        .1
}
#[no_mangle]
pub static VIBEOS_USB_HOST: Host = Host {
    initialize: |mmio, irq| unsafe {
        let resources = XhciResources { mmio, irq };
        if let Some((current, c)) = (*CONTROLLER.0.get()).as_ref() {
            if *current != resources {
                return Err(Error::InvalidMmioRegion);
            }
            // A failed IRQ route can retry without reborrowing a live DMA slab.
            return Ok(c.info());
        }
        let c = Controller::initialize(resources, &mut *DMA.0.get())?;
        let info = c.info();
        *CONTROLLER.0.get() = Some((resources, c));
        Ok(info)
    },
    info: || unsafe { read_controller().info() },
    devices: |visit| unsafe {
        for device in read_controller().devices() {
            visit(device);
        }
    },
    interrupt_context: || unsafe { read_controller().interrupt_handle().into_context() },
    enable_interrupts: || unsafe { controller().enable_interrupts() },
    disable_interrupts: || unsafe { controller().disable_interrupts() },
    acknowledge: |context| unsafe { InterruptHandle::from_context(context).acknowledge() },
    read_sector: |sector| unsafe { controller().read_sector(sector) },
    write_sector: |sector, bytes| unsafe { controller().write_sector(sector, bytes) },
    service: || unsafe { controller().service() },
};
