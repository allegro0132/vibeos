//! Kernel composition for the fixed CV1800B DWC2 host controller.

use crate::{println, sync::SpinLock};
use vibeos_driver_dwc2_host::{
    CdcEcmInfo, ConfigurationInfo, Controller, DeviceInfo, DmaStorage, Error, HidKeyboardInfo,
    HidReportDescriptor, HubChildInfo, HubInfo, Info, MassStorageInfo, Telemetry, UsbBusPath,
    MAX_DEVICE_CONFIGURATIONS, MAX_HUB_CHILDREN,
};

static CONTROLLER: SpinLock<Option<Controller>> = SpinLock::new(None);
#[cfg_attr(target_arch = "riscv64", link_section = ".dma")]
static DMA: DmaStorage = DmaStorage::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub info: Info,
    pub connected: bool,
    pub device: Option<DeviceInfo>,
    pub child: Option<DeviceInfo>,
    pub children: [Option<HubChildInfo>; MAX_HUB_CHILDREN],
    pub hub: Option<HubInfo>,
    pub hubs: [Option<HubInfo>; MAX_HUB_CHILDREN],
    pub configuration: Option<ConfigurationInfo>,
    pub configurations: [Option<ConfigurationInfo>; MAX_DEVICE_CONFIGURATIONS],
    pub configuration_device_address: Option<u8>,
    pub report_descriptor: Option<HidReportDescriptor>,
    pub keyboard: Option<HidKeyboardInfo>,
    pub keyboard_device_address: Option<u8>,
    pub mass_storage: Option<MassStorageInfo>,
    pub storage_device_address: Option<u8>,
    pub cdc_ecm: Option<CdcEcmInfo>,
    pub cdc_ecm_device_address: Option<u8>,
    pub telemetry: Telemetry,
}

pub fn init() -> Result<Info, Error> {
    let mut published = CONTROLLER.lock();
    if let Some(controller) = published.as_ref() {
        return Ok(controller.info());
    }
    // Safety: the Milk-V BSP maps and exclusively assigns the fixed USB core,
    // PHY and TOP control ranges to this adapter for the kernel lifetime.
    let controller = unsafe {
        Controller::initialize(
            crate::platform::DWC2,
            &DMA,
            crate::platform::TIMEBASE_HZ,
            crate::sbi::time,
        )
    }?;
    let info = controller.info();
    *published = Some(controller);
    Ok(info)
}

pub fn connected() -> bool {
    CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(Controller::connected)
}

pub fn info() -> Option<Info> {
    CONTROLLER.lock().as_ref().map(Controller::info)
}

pub fn network_bus_path() -> Option<UsbBusPath> {
    CONTROLLER
        .lock()
        .as_ref()
        .and_then(Controller::network_bus_path)
}

pub fn snapshot() -> Option<Snapshot> {
    CONTROLLER.lock().as_ref().map(|controller| Snapshot {
        info: controller.info(),
        connected: controller.connected(),
        device: controller.device(),
        child: controller.child(),
        children: controller.children(),
        hub: controller.hub(),
        hubs: controller.hubs(),
        configuration: controller.configuration(),
        configurations: controller.configurations(),
        configuration_device_address: controller.configuration_device_address(),
        report_descriptor: controller.report_descriptor(),
        keyboard: controller.keyboard(),
        keyboard_device_address: controller.keyboard_device_address(),
        mass_storage: controller.mass_storage(),
        storage_device_address: controller.storage_device_address(),
        cdc_ecm: controller.cdc_ecm(),
        cdc_ecm_device_address: controller.cdc_ecm_device_address(),
        telemetry: controller.telemetry(),
    })
}

pub fn enumerate_device() -> Result<Option<DeviceInfo>, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .enumerate_device()
}

pub fn configure_hid_keyboard() -> Result<Option<HidKeyboardInfo>, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .configure_hid_keyboard()
}

pub fn configure_mass_storage() -> Result<Option<MassStorageInfo>, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .configure_mass_storage()
}

pub fn switch_rtl8151_install_mode() -> Result<bool, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .switch_rtl8151_install_mode()
}

pub fn configure_cdc_ecm() -> Result<Option<CdcEcmInfo>, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .configure_cdc_ecm()
}

pub fn receive_cdc_ecm(output: &mut [u8]) -> Result<usize, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .receive_cdc_ecm(output)
}

pub fn transmit_cdc_ecm(frame: &[u8]) -> Result<(), Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .transmit_cdc_ecm(frame)
}

pub fn read_sector(sector: u64) -> Result<[u8; 512], Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .read_sector(sector)
}

pub fn write_sector(sector: u64, bytes: &[u8; 512]) -> Result<(), Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .write_sector(sector, bytes)
}

pub fn hub_topology_changed() -> Result<bool, Error> {
    CONTROLLER
        .lock()
        .as_mut()
        .ok_or(Error::NoDevice)?
        .hub_topology_changed()
}

pub async fn service_task() {
    let mut was_connected = CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|controller| controller.connected() && controller.device().is_some());
    let mut hub_poll_elapsed_ms = 0u16;
    loop {
        let connected = CONTROLLER
            .lock()
            .as_ref()
            .is_some_and(Controller::connected);
        let topology_changed = if connected && was_connected && hub_poll_elapsed_ms >= 250 {
            hub_poll_elapsed_ms = 0;
            hub_topology_changed().unwrap_or(false)
        } else {
            false
        };
        if connected && (!was_connected || topology_changed) {
            let attached = {
                let mut guard = CONTROLLER.lock();
                match guard.as_mut() {
                    Some(controller) => {
                        controller
                            .enumerate_device()
                            .and_then(|device| match device {
                                Some(device) => {
                                    let keyboard = controller.configure_hid_keyboard()?;
                                    let mode_switched = controller.switch_rtl8151_install_mode()?;
                                    let cdc_ecm = if mode_switched {
                                        None
                                    } else {
                                        controller.configure_cdc_ecm()?
                                    };
                                    let storage = if mode_switched {
                                        None
                                    } else {
                                        controller.configure_mass_storage()?
                                    };
                                    Ok(Some((device, keyboard, storage, mode_switched, cdc_ecm)))
                                }
                                None => Ok(None),
                            })
                    }
                    None => Err(Error::NoDevice),
                }
            };
            match attached {
                Ok(Some((device, keyboard, storage, mode_switched, cdc_ecm))) => {
                    println!(
                        "  usb dev   hotplug addr {}, {:?}, {:04x}:{:04x}, USB {:#06x}, EP0 {}",
                        device.address,
                        device.speed,
                        device.vendor_id,
                        device.product_id,
                        device.usb_version,
                        device.max_packet_size_0,
                    );
                    if mode_switched {
                        println!(
                            "  usb net   sent RTL8151 install-mode switch; waiting for Ethernet re-enumeration"
                        );
                    }
                    if let Some(ecm) = cdc_ecm {
                        println!(
                            "  usb net   CDC-ECM configured, interface {} alt {}, IN ep {}, OUT ep {}, MAC {:?}",
                            ecm.data_interface,
                            ecm.data_alternate,
                            ecm.endpoint_in & 0x0f,
                            ecm.endpoint_out & 0x0f,
                            ecm.mac_address,
                        );
                    }
                    match keyboard {
                        Some(keyboard) => println!(
                            "  usb hid   attached {:?} keyboard, interface {}, IN ep {}, MPS {}, poll {} ms",
                            keyboard.protocol,
                            keyboard.interface,
                            keyboard.endpoint_in & 0x0f,
                            keyboard.max_packet_size,
                            keyboard.interval_ms,
                        ),
                        None => println!(
                            "  usb hid   attached device has no supported keyboard interface"
                        ),
                    }
                    if let Some(storage) = storage {
                        println!(
                            "  usb disk  attached SCSI/BOT, interface {}, IN ep {}, OUT ep {}, {} sectors x {} bytes",
                            storage.interface,
                            storage.endpoint_in & 0x0f,
                            storage.endpoint_out & 0x0f,
                            storage.capacity_sectors.unwrap_or(0),
                            storage.block_size.unwrap_or(0),
                        );
                    }
                }
                Ok(None) => println!("  usb hid   device disconnected during hotplug enumeration"),
                Err(error) => println!("  usb hid   hotplug enumeration FAILED: {:?}", error),
            }
            was_connected = true;
        } else if !connected && was_connected {
            if let Some(controller) = CONTROLLER.lock().as_mut() {
                let _ = controller.enumerate_device();
            }
            println!("  usb hid   device disconnected; waiting for reconnect");
            was_connected = false;
        }

        let (input, interval_ms) = {
            let mut guard = CONTROLLER.lock();
            match guard.as_mut() {
                Some(controller) if controller.keyboard().is_some() => (
                    controller.poll_keyboard(),
                    controller
                        .keyboard()
                        .map_or(10, |keyboard| keyboard.interval_ms),
                ),
                _ => (Err(Error::NoDevice), 100),
            }
        };
        if let Ok(input) = input {
            for byte in input.as_slice() {
                crate::uart::inject_usb_input(*byte);
            }
        }
        let interval_ms = interval_ms.max(1);
        crate::exec::sleep_ms(u64::from(interval_ms)).await;
        hub_poll_elapsed_ms = hub_poll_elapsed_ms.saturating_add(interval_ms);
    }
}

pub fn telemetry() -> Option<Telemetry> {
    CONTROLLER.lock().as_ref().map(Controller::telemetry)
}
