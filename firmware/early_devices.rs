//! Shared static composition for boards with a 16550 console and PLIC.
use super::{Board, BoardContract};
use vibeos_driver_plic::{Mmio as PlicMmio, Plic};
use vibeos_driver_uart16550::{Mmio as UartMmio, Uart};
use vibeos_hal::devices::{ConsoleOps, EarlyDevices, InterruptControllerOps};

// SAFETY: board descriptions supply mapped device apertures. The kernel
// serializes console TX and PLIC enable updates, and owns boot-hart RX/claims.
static UART: Uart<UartMmio> =
    Uart::new(unsafe { UartMmio::new(Board::INFO.uart) }, Board::INFO.uart);
static PLIC: Plic<PlicMmio> = Plic::new(
    unsafe { PlicMmio::new(Board::INFO.plic) },
    Board::INFO.plic.max_irq,
);

#[no_mangle]
pub static VIBEOS_EARLY_DEVICES: EarlyDevices = EarlyDevices {
    console: ConsoleOps {
        description: Board::INFO.uart,
        capabilities: Board::INFO.console,
        init: || UART.init(),
        write_byte: |byte| UART.write_byte(byte),
        drain: || UART.drain(),
        interrupt: || UART.interrupt(),
        read_byte: || UART.read_byte(),
    },
    interrupts: InterruptControllerOps {
        description: Board::INFO.plic,
        supervisor_context: Board::plic_s_context,
        init_context: |context| PLIC.init_context(context),
        set_enabled: |context, irq, enabled| PLIC.set_enabled(context, irq, enabled),
        claim: |context| PLIC.claim(context),
        complete: |context, irq| PLIC.complete(context, irq),
    },
};

use core::cell::UnsafeCell;
use vibeos_hal::boot::{ram_page_table_pages, BootPlatform, PageTableArena};
const _: () = {
    assert!(Board::MMU.device_level1_tables <= vibeos_hal::boot::MAX_DEVICE_LEVEL1_TABLES);
    assert!(Board::MMU.device_level0_tables <= vibeos_hal::boot::MAX_DEVICE_LEVEL0_TABLES);
};
const RAM_TABLE_PAGES: usize = ram_page_table_pages(Board::MMU.ram);
#[repr(C, align(4096))]
struct RamTables(UnsafeCell<[[u64; 512]; RAM_TABLE_PAGES]>);
// SAFETY: only the kernel page-table owner accesses this static after boot.
unsafe impl Sync for RamTables {}
static RAM_TABLES: RamTables = RamTables(UnsafeCell::new([[0; 512]; RAM_TABLE_PAGES]));
#[no_mangle]
pub static VIBEOS_BOOT_PLATFORM: BootPlatform = BootPlatform {
    managed_block_id: super::MANAGED_BLOCK_ID,
    network_driver_name: super::NETWORK_DRIVER_NAME,
    info: Board::INFO,
    memory_map: Board::MEMORY_MAP,
    mmu: Board::MMU,
    heap_end: super::HEAP_END,
    hart_ids: super::hart_ids,
    timebase_hz: super::timebase_hz,
    admit_boot: super::BOOT_ADMISSION,
    heap_regions: super::BOOT_HEAP_REGIONS,
    rtc: Board::RTC,
    cold_reset: Board::RESET,
    early_platform_init: super::platform_init,
    platform_report: super::platform_report,
    ram_page_tables: || PageTableArena {
        base: RAM_TABLES.0.get() as usize,
        pages: RAM_TABLE_PAGES,
    },
};
