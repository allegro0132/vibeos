//! Firmware ownership of the polling USB controller and DMA.
use super::Board;
use core::cell::UnsafeCell;
use vibeos_driver_dwc2_host::{Controller, DmaStorage, InstanceState};
use vibeos_hal::{usb_polling::*, Board as _};
struct State(UnsafeCell<Option<Controller>>);
// SAFETY: the HAL host contract requires all calls to be serialized.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(None));
#[cfg_attr(target_arch = "riscv64", link_section = ".dma")]
static DMA: DmaStorage = DmaStorage::new();
static INSTANCE: InstanceState = InstanceState::new();
unsafe fn controller() -> &'static mut Controller {
    (*STATE.0.get())
        .as_mut()
        .expect("initialized polling USB host")
}
#[no_mangle]
pub static VIBEOS_POLLING_USB_HOST: Host = Host {
    initialize: |hz, time| unsafe {
        if let Some(c) = (*STATE.0.get()).as_ref() {
            return Ok(c.info());
        }
        let c = Controller::initialize(
            Board::INFO.dwc2.unwrap(),
            &PLATFORM,
            &DMA,
            &INSTANCE,
            hz,
            time,
        )?;
        let info = c.info();
        *STATE.0.get() = Some(c);
        Ok(info)
    },
    connected: || unsafe { controller().connected() },
    info: || unsafe { controller().info() },
    network_bus_path: || unsafe { controller().network_bus_path() },
    snapshot: || unsafe {
        Snapshot {
            info: controller().info(),
            connected: controller().connected(),
            device: controller().device(),
            child: controller().child(),
            children: controller().children(),
            hub: controller().hub(),
            hubs: controller().hubs(),
            configuration: controller().configuration(),
            configurations: controller().configurations(),
            configuration_device_address: controller().configuration_device_address(),
            report_descriptor: controller().report_descriptor(),
            keyboard: controller().keyboard(),
            keyboard_device_address: controller().keyboard_device_address(),
            mass_storage: controller().mass_storage(),
            storage_device_address: controller().storage_device_address(),
            cdc_ecm: controller().cdc_ecm(),
            cdc_ecm_device_address: controller().cdc_ecm_device_address(),
            telemetry: controller().telemetry(),
        }
    },
    device: || unsafe { controller().device() },
    keyboard: || unsafe { controller().keyboard() },
    telemetry: || unsafe { controller().telemetry() },
    enumerate_device: || unsafe { controller().enumerate_device() },
    configure_hid_keyboard: || unsafe { controller().configure_hid_keyboard() },
    configure_mass_storage: || unsafe { controller().configure_mass_storage() },
    switch_rtl8151_install_mode: || unsafe { controller().switch_rtl8151_install_mode() },
    configure_cdc_ecm: || unsafe { controller().configure_cdc_ecm() },
    receive_cdc_ecm: |output| unsafe { controller().receive_cdc_ecm(output) },
    transmit_cdc_ecm: |frame| unsafe { controller().transmit_cdc_ecm(frame) },
    poll_cdc_ecm_carrier: || unsafe { controller().poll_cdc_ecm_carrier() },
    read_sector: |sector| unsafe { controller().read_sector(sector) },
    write_sector: |sector, bytes| unsafe { controller().write_sector(sector, bytes) },
    hub_topology_changed: || unsafe { controller().hub_topology_changed() },
    poll_keyboard: || unsafe { controller().poll_keyboard() },
};

unsafe fn platform(
    hz: u64,
    time: fn() -> u64,
) -> Result<vibeos_platform_cv1800b::usb::Usb<vibeos_platform_cv1800b::usb::Mmio>, Error> {
    use vibeos_bsp_milkv_duo::{SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END, USB_PHY_BASE, USB_PHY_END};
    use vibeos_hal::AddressRange;
    Ok(vibeos_platform_cv1800b::usb::Usb(
        vibeos_platform_cv1800b::usb::Mmio::new(
            AddressRange::new(SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
            AddressRange::new(USB_PHY_BASE, USB_PHY_END),
            hz,
            time,
        )?,
    ))
}
static PLATFORM: vibeos_hal::usb_polling::Platform = vibeos_hal::usb_polling::Platform {
    prepare: |hz, time| unsafe { Ok(platform(hz, time)?.prepare()) },
    rollback: |saved| unsafe {
        platform(Board::INFO.timebase_hz, || 0)
            .expect("valid USB platform wiring")
            .rollback(saved)
    },
    telemetry: || unsafe {
        platform(Board::INFO.timebase_hz, || 0)
            .expect("valid USB platform wiring")
            .telemetry()
    },
    dma: &vibeos_platform_cv1800b::cache::DMA,
};
