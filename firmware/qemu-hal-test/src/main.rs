#![no_std]
#![no_main]
//! Composition acceptance image: real QEMU devices, no kernel board profile.
//! Reuse the production firmware providers rather than mock hardware tables.
use core::arch::global_asm;
global_asm!(".section .text.boot\n.option norvc\n.global _start\n_start:\nj vibeos_kernel_start");
extern crate vibeos_kernel;
use vibeos_bsp_qemu_virt::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
mod early_devices;
#[path = "../../qemu-virt/src/network.rs"]
mod network;
#[path = "../../qemu-virt/src/storage.rs"]
mod storage;
#[path = "../../qemu-virt/src/transport.rs"]
mod transport;
unsafe fn platform_init(_write: fn(&str)) {}
#[cfg(feature = "boot-admission-test")]
mod boot_admission;
#[cfg(feature = "eqos-model-test")]
mod eqos_model;
#[cfg(feature = "eqos-model-test")]
mod eqos_ring_model;
#[cfg(feature = "jh7110-sd-model-test")]
mod jh7110_sd_model;
#[cfg(feature = "mars-composition-test")]
mod mars_composition;
unsafe fn platform_report(_print: fn(core::fmt::Arguments<'_>)) {
    #[cfg(feature = "eqos-model-test")]
    {
        eqos_model::run();
        eqos_ring_model::run();
        _print(format_args!("EQOS_RING_MODEL PASS tx=bounded rx=copied recovery=quarantined\n"));
        _print(format_args!(
            "EQOS_MODEL PASS mdio=clause22 descriptors=bounded\n"
        ));
    }
    #[cfg(feature = "mars-composition-test")]
    {
        mars_composition::run();
        _print(format_args!(
            "MARS_COMPOSITION_MODEL PASS admission=ok partition=bounded\n"
        ));
    }
    #[cfg(feature = "mars-resources-test")]
    {
        let fixture = include_bytes!("../../../boards/milkv-mars/tests/fixtures/resources.dtb");
        let resources =
            vibeos_bsp_milkv_mars::resources::admit(fixture).expect("Mars fixture admission");
        assert_eq!(resources.syscon.len(), 4096);
        let harts = vibeos_bsp_milkv_mars::harts::admit(fixture, 4, false).unwrap();
        assert_eq!(harts.ids(), &[4, 1, 2, 3]);
        _print(format_args!(
            "MARS_RESOURCES_MODEL PASS contexts=2,4,6,8 syscon_bytes=4096\n"
        ));
    }
    #[cfg(feature = "boot-admission-test")]
    _print(format_args!(
        "BOOT_ADMISSION PASS boot={} count={} timebase={}\n",
        hart_ids()[0],
        hart_ids().len(),
        timebase_hz()
    ));
    #[cfg(feature = "boot-admission-test")]
    _print(format_args!(
        "BOOT_HEAP PASS regions={} bytes={}\n",
        boot_admission::heap_regions().len(),
        boot_admission::heap_regions()
            .iter()
            .map(|r| r.len())
            .sum::<usize>()
    ));
    #[cfg(feature = "jh7110-sd-model-test")]
    {
        jh7110_sd_model::run();
        _print(format_args!(
            "JH7110_SD_MODEL PASS source_hz=49500000 timeout_cleanup=ok\n"
        ));
    }
}
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0001).unwrap();
const NETWORK_DRIVER_NAME: &str = "virtio-mmio";

#[cfg(not(feature = "boot-admission-test"))]
fn hart_ids() -> &'static [usize] {
    Board::HART_IDS
}
#[cfg(not(feature = "boot-admission-test"))]
fn timebase_hz() -> u64 {
    Board::INFO.timebase_hz
}
#[cfg(feature = "boot-admission-test")]
use boot_admission::{hart_ids, timebase_hz};
#[cfg(feature = "boot-admission-test")]
const BOOT_ADMISSION: Option<
    unsafe fn(vibeos_hal::boot::BootRequest) -> Result<(), vibeos_hal::boot::BootError>,
> = Some(boot_admission::admit);
#[cfg(not(feature = "boot-admission-test"))]
const BOOT_ADMISSION: Option<
    unsafe fn(vibeos_hal::boot::BootRequest) -> Result<(), vibeos_hal::boot::BootError>,
> = None;

#[cfg(feature = "boot-admission-test")]
const BOOT_HEAP_REGIONS: Option<fn() -> &'static [vibeos_hal::AddressRange]> =
    Some(boot_admission::heap_regions);
#[cfg(not(feature = "boot-admission-test"))]
const BOOT_HEAP_REGIONS: Option<fn() -> &'static [vibeos_hal::AddressRange]> = None;

const HEAP_END: usize = Board::MMU.ram.end;
