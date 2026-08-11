//! Kernel composition for the fixed CV1800B DWC2 host controller.

use crate::{println, sync::SpinLock};
use vibeos_driver_dwc2_host::{
    ConfigurationInfo, Controller, DeviceInfo, Error, HidKeyboardInfo, HidReportDescriptor,
    HubInfo, Info, Telemetry,
};

static CONTROLLER: SpinLock<Option<Controller>> = SpinLock::new(None);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub info: Info,
    pub connected: bool,
    pub device: Option<DeviceInfo>,
    pub child: Option<DeviceInfo>,
    pub hub: Option<HubInfo>,
    pub configuration: Option<ConfigurationInfo>,
    pub report_descriptor: Option<HidReportDescriptor>,
    pub keyboard: Option<HidKeyboardInfo>,
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

pub fn snapshot() -> Option<Snapshot> {
    CONTROLLER.lock().as_ref().map(|controller| Snapshot {
        info: controller.info(),
        connected: controller.connected(),
        device: controller.device(),
        child: controller.child(),
        hub: controller.hub(),
        configuration: controller.configuration(),
        report_descriptor: controller.report_descriptor(),
        keyboard: controller.keyboard(),
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

pub async fn service_task() {
    let mut was_connected = CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|controller| controller.connected() && controller.device().is_some());
    loop {
        let connected = CONTROLLER
            .lock()
            .as_ref()
            .is_some_and(Controller::connected);
        if connected && !was_connected {
            let attached = {
                let mut guard = CONTROLLER.lock();
                match guard.as_mut() {
                    Some(controller) => {
                        controller
                            .enumerate_device()
                            .and_then(|device| match device {
                                Some(device) => controller
                                    .configure_hid_keyboard()
                                    .map(|keyboard| Some((device, keyboard))),
                                None => Ok(None),
                            })
                    }
                    None => Err(Error::NoDevice),
                }
            };
            match attached {
                Ok(Some((device, keyboard))) => {
                    println!(
                        "  usb dev   hotplug addr {}, {:?}, {:04x}:{:04x}, USB {:#06x}, EP0 {}",
                        device.address,
                        device.speed,
                        device.vendor_id,
                        device.product_id,
                        device.usb_version,
                        device.max_packet_size_0,
                    );
                    match keyboard {
                        Some(keyboard) => println!(
                            "  usb hid   attached boot keyboard, interface {}, IN ep {}, MPS {}, poll {} ms",
                            keyboard.interface,
                            keyboard.endpoint_in & 0x0f,
                            keyboard.max_packet_size,
                            keyboard.interval_ms,
                        ),
                        None => println!(
                            "  usb hid   attached device has no boot keyboard interface"
                        ),
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
        crate::exec::sleep_ms(u64::from(interval_ms.max(1))).await;
    }
}

pub fn telemetry() -> Option<Telemetry> {
    CONTROLLER.lock().as_ref().map(Controller::telemetry)
}
