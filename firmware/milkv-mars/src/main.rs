#![no_std]
#![no_main]
//! Mars serial/SD bring-up image. EQoS and qualified entropy are not composed,
//! so this image intentionally exposes no NIC and cannot enable SSH yet.
use core::{
    arch::global_asm,
    cell::UnsafeCell,
    sync::atomic::{AtomicU8, Ordering},
};
use vibeos_bsp_milkv_mars::Board;
use vibeos_firmware_milkv_mars::{Admission, SbiExtensions};
use vibeos_hal::{
    boot::{BootError, BootRequest},
    Board as BoardContract,
};
use vibeos_runtime_riscv as sbi;
global_asm!(".section .text.boot\n.option norvc\n.global _start\n_start:\nj vibeos_kernel_start");
extern crate vibeos_kernel;
#[path = "../../early_devices.rs"]
mod early_devices;
mod storage;
struct BootState {
    ready: AtomicU8,
    value: UnsafeCell<Option<Admission>>,
}
unsafe impl Sync for BootState {}
static BOOT: BootState = BootState {
    ready: AtomicU8::new(0),
    value: UnsafeCell::new(None),
};
fn admission() -> &'static Admission {
    assert_eq!(BOOT.ready.load(Ordering::Acquire), 2);
    unsafe { (&*BOOT.value.get()).as_ref().unwrap() }
}
unsafe fn admit(request: BootRequest) -> Result<(), BootError> {
    let dtb = unsafe { request.dtb()? };
    let capabilities = SbiExtensions {
        hsm: sbi::probe_extension(0x48534d),
        ipi: sbi::probe_extension(0x735049),
        rfence: sbi::probe_extension(sbi::RFENCE_EXTENSION_ID),
        time: sbi::probe_extension(0x54494d45),
    };
    let value = vibeos_firmware_milkv_mars::admit(dtb, &request, capabilities)?;
    BOOT.ready
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| BootError::AlreadyInitialized)?;
    unsafe { *BOOT.value.get() = Some(value) };
    BOOT.ready.store(2, Ordering::Release);
    Ok(())
}
fn hart_ids() -> &'static [usize] {
    admission().harts.ids()
}
fn timebase_hz() -> u64 {
    u64::from(admission().harts.timebase_hz)
}
const BOOT_ADMISSION: Option<unsafe fn(BootRequest) -> Result<(), BootError>> = Some(admit);
const BOOT_HEAP_REGIONS: Option<fn() -> &'static [vibeos_hal::AddressRange]> =
    Some(|| admission().heap.ranges());
const HEAP_END: usize = vibeos_bsp_milkv_mars::RAM.end;
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0003).unwrap();
const NETWORK_DRIVER_NAME: &str = "unavailable (JH7110 EQoS pending)";
unsafe fn platform_init(_write: fn(&str)) {}
unsafe fn platform_report(print: fn(core::fmt::Arguments<'_>)) {
    print(format_args!("MARS_BOOT_ADMISSION PASS boot={} harts={} timebase={} heap_regions={} SBI=HSM,IPI,RFENCE,TIME\n",
        hart_ids()[0],hart_ids().len(),timebase_hz(),admission().heap.ranges().len()));
    print(format_args!("Mars bring-up image: SD data-only PIO; EQoS/SSH not available; physical acceptance pending\n"));
}
#[no_mangle]
pub static VIBEOS_PACKET_DEVICE: vibeos_hal::network::Device = vibeos_hal::network::Device {
    present: false,
    registers: vibeos_hal::AddressRange::new(0, 0),
    irq: 0,
    rx_queue_size: 0,
    dma_base: || 0,
    telemetry: || vibeos_hal::network::Telemetry::default(),
    claim: |_, _, _| Err(vibeos_hal::network::Error::InvalidDescription),
    tx_owned: || false,
    transmit: |_| Err(vibeos_hal::network::Error::InvalidDescription),
    receive: |_| None,
    poll_link: || {},
    shutdown: || true,
    recover: || false,
};

const _: () = {
    let slice = match vibeos_image_policy::BLOCK_DATA_SLICE {
        Some(slice) => slice,
        None => panic!("Mars data policy"),
    };
    assert!(slice.first_sector == 0);
    assert!(slice.sector_count == vibeos_firmware_milkv_mars::DATA_SECTOR_COUNT);
};
