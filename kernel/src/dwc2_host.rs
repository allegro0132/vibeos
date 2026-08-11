//! Kernel composition for the fixed CV1800B DWC2 host controller.

use crate::sync::SpinLock;
use vibeos_driver_dwc2_host::{Controller, DeviceInfo, Error, HidKeyboardInfo, Info, Telemetry};

static CONTROLLER: SpinLock<Option<Controller>> = SpinLock::new(None);

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

pub fn keyboard_ready() -> bool {
    CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|controller| controller.keyboard().is_some())
}

pub async fn service_task() {
    loop {
        let (input, interval_ms) = {
            let mut guard = CONTROLLER.lock();
            match guard.as_mut() {
                Some(controller) => (
                    controller.poll_keyboard(),
                    controller
                        .keyboard()
                        .map_or(10, |keyboard| keyboard.interval_ms),
                ),
                None => (Err(Error::NoDevice), 10),
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
