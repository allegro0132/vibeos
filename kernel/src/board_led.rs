//! Kernel adapter for the Milk-V Duo board-status LED driver.

pub use vibeos_driver_milkv_duo_led::Snapshot as BlueLedInfo;

pub fn init() -> BlueLedInfo {
    // SAFETY: the Milk-V BSP identity-maps both declared apertures for the
    // firmware lifetime. Boot calls this before publishing any other owner of
    // GPIOC24 or its pad-mux register.
    unsafe { vibeos_driver_milkv_duo_led::initialize(crate::platform::STATUS_LED) }
        .expect("Milk-V Duo BSP must provide a valid status LED description")
}
