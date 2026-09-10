//! Statically owned SDHCI instance; kernel capabilities serialize access.
use super::Board;
use core::cell::UnsafeCell;
use vibeos_driver_sdhci_blk::{adaptive::AdaptiveCard, Card};
use vibeos_hal::{
    block::{Diagnostics, Error, PioBlockDevice},
    Board as _,
};
struct Storage(UnsafeCell<Option<AdaptiveCard>>);
// SAFETY: the PioBlockDevice contract requires exclusive serialized access.
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage(UnsafeCell::new(None));
unsafe fn card() -> &'static mut AdaptiveCard {
    (*STORAGE.0.get())
        .as_mut()
        .expect("initialized PIO instance")
}
#[no_mangle]
pub static VIBEOS_PIO_BLOCK_DEVICE: PioBlockDevice = PioBlockDevice {
    resource_kind: "cv1800b-sdhci-mmio",
    name: "CV1800B SDIO0",
    registers: Board::INFO.sdhci.unwrap().registers,
    irq: Board::INFO.sdhci.unwrap().irq,
    initialize: |hz, time, log| unsafe {
        *STORAGE.0.get() = None;
        let mut slot = vibeos_platform_cv1800b::sd::SdSlot(vibeos_platform_cv1800b::sd::Mmio::new(
            vibeos_hal::AddressRange::new(
                vibeos_bsp_milkv_duo::SOC_CONTROL_BASE,
                vibeos_bsp_milkv_duo::SOC_CONTROL_MMIO_END,
            ),
            hz,
            time,
        )?);
        let hardware = Card::initialize(
            Board::INFO.sdhci.ok_or(Error::InvalidConfiguration)?,
            hz,
            time,
            &mut slot,
        )?;
        let capacity = hardware.info().capacity_sectors;
        *STORAGE.0.get() = Some(AdaptiveCard::new(hardware, log));
        Ok(capacity)
    },
    read: |sector, output| unsafe { card().read_blocks(sector, output) },
    write: |sector, data, verify, published| unsafe {
        let card = card();
        card.set_write_readback(verify);
        card.write_blocks_tracked(sector, data, published)
    },
    flush: |published| unsafe { card().flush_tracked(published) },
    diagnostics: || unsafe {
        let c = card().hardware();
        Diagnostics {
            command: c.last_command(),
            interrupt_status: c.last_interrupt_status(),
            present_state: c.present_state(),
        }
    },
    probe_read: Some(|sector, out, budget| unsafe {
        card()
            .hardware_mut()
            .diagnostic_probe_multiblock_read(sector, out, budget)
    }),
};
