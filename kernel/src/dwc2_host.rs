//! Kernel composition for the fixed CV1800B DWC2 host controller.

use crate::sync::SpinLock;
use vibeos_driver_dwc2_host::{Controller, Error, Info, Telemetry};

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

pub fn telemetry() -> Option<Telemetry> {
    CONTROLLER.lock().as_ref().map(Controller::telemetry)
}
