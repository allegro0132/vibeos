//! Boot-only Duo setup and diagnostics; no dependency on kernel policy.
use super::{Board, BoardContract};
use core::cell::UnsafeCell;
use vibeos_driver_milkv_duo_led::Snapshot;
struct BootState(UnsafeCell<Option<Snapshot>>);
// SAFETY: BootPlatform callbacks run only on the boot hart before SMP. The
// snapshot is published before the report callback and never mutated again.
unsafe impl Sync for BootState {}
static LED: BootState = BootState(UnsafeCell::new(None));
pub unsafe fn platform_init(write: fn(&str)) {
    assert!((*LED.0.get()).is_none(), "platform initialized twice");
    let led = initialize_led(Board::INFO.status_led.expect("Duo LED wiring"), write);
    *LED.0.get() = Some(led);
}
pub unsafe fn initialize_led(
    description: vibeos_hal::StatusLedDescription,
    write: fn(&str),
) -> Snapshot {
    let led = vibeos_driver_milkv_duo_led::initialize(description)
        .expect("Duo status LED resources must be valid");
    write(if led.on() {
        "[VibeOS] blue status LED on\r\n"
    } else if led.output_asserted() {
        "[VibeOS] blue status LED output asserted (input unconfirmed)\r\n"
    } else {
        "[VibeOS] blue status LED readback failed\r\n"
    });
    led
}
pub unsafe fn platform_report(print: fn(core::fmt::Arguments<'_>)) {
    let led = (*LED.0.get()).expect("platform initialized before diagnostics");
    report_led(led, print);
}
pub fn report_led(led: Snapshot, print: fn(core::fmt::Arguments<'_>)) {
    print(format_args!(
        "  led       blue GPIOC24 {} (pinmux {:#x}, dir {:#010x}, data {:#010x}, input {:#010x})\n",
        led.status(),
        led.pinmux,
        led.direction,
        led.data,
        led.external
    ));
}
