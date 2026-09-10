//! Exclusively owned SDIO1 instance behind the data partition boundary.
use core::cell::UnsafeCell;
use vibeos_driver_dw_mshc::{Card, Mmio};
use vibeos_firmware_milkv_mars::{partition::Partition, DATA_FIRST_SECTOR, DATA_SECTOR_COUNT};
use vibeos_hal::block::{Error, PioBlockDevice};
use vibeos_platform_jh7110::sd;
struct Storage(UnsafeCell<Option<Partition<Card<Mmio>>>>);
// HAL callers serialize initialization, diagnostics and every operation.
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(None));
unsafe fn card() -> &'static mut Partition<Card<Mmio>> {
    (*STORAGE.0.get())
        .as_mut()
        .expect("initialized Mars SD instance")
}
fn platform_error(error: sd::Error) -> Error {
    match error {
        sd::Error::TimedOut => Error::TimedOut,
        _ => Error::InvalidConfiguration,
    }
}
#[no_mangle]
pub static VIBEOS_PIO_BLOCK_DEVICE: PioBlockDevice = PioBlockDevice {
    resource_kind: "jh7110-dw-mshc-mmio",
    name: "JH7110 SDIO1 data partition",
    registers: vibeos_bsp_milkv_mars::SD_REGISTERS,
    irq: vibeos_bsp_milkv_mars::SD_IRQ,
    initialize: |hz, time, log| unsafe {
        *STORAGE.0.get() = None;
        let resources = super::admission().resources;
        let mut platform = sd::Mmio::new(resources.crg, resources.syscon, resources.pins, time)
            .map_err(platform_error)?;
        let clock = sd::prepare(
            &mut platform,
            vibeos_bsp_milkv_mars::SD_PINS,
            hz,
            vibeos_bsp_milkv_mars::SD_SETTLE_MS,
        )
        .map_err(platform_error)?;
        let mut description = vibeos_bsp_milkv_mars::sd_controller(clock.source_hz);
        description.registers = resources.sd;
        let hardware = Card::initialize(Mmio::new(resources.sd), description, time, hz)
            .map_err(Error::from)?;
        let physical = hardware.info().capacity_sectors;
        let partition = Partition::new(hardware, physical, DATA_FIRST_SECTOR, DATA_SECTOR_COUNT)?;
        log(format_args!(
            "Mars SDIO1 source={} Hz data-first={} sectors={} (boot area excluded)\n",
            clock.source_hz,
            DATA_FIRST_SECTOR,
            partition.sectors()
        ));
        *STORAGE.0.get() = Some(partition);
        Ok(DATA_SECTOR_COUNT)
    },
    read: |sector, output| unsafe { card().read(sector, output) },
    write: |sector, data, verify, published| unsafe {
        card().write(sector, data, verify, published)
    },
    flush: |published| unsafe { card().flush(published) },
    diagnostics: || unsafe { card().diagnostics() },
    probe_read: None,
};
