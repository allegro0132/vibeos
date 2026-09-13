#![no_std]
#![no_main]
use core::{arch::global_asm, cell::UnsafeCell, mem::MaybeUninit};
use vibeos_hal::{
    boot::{ram_page_table_pages, BootError, BootPlatform, BootRequest, PageTableArena},
    memory::BootMemory,
    runtime_platform::{self, BlockBackend, BoardId, EntropyBackend, Firmware, NetworkBackend},
    AddressRange,
};
extern crate vibeos_kernel;
global_asm!(include_str!("entry.S"));
#[cfg(feature = "board-milkv-duo")]
mod duo;
#[cfg(feature = "board-milkv-mars")]
mod mars;
#[cfg(feature = "board-qemu-virt")]
mod qemu;
include!(concat!(env!("OUT_DIR"), "/configuration.rs"));

struct BootState {
    platform: BootPlatform,
    heap: BootMemory<16>,
    tables: PageTableArena,
    harts: [usize; 4],
    hart_count: usize,
    timebase: u64,
    original_report: unsafe fn(fn(core::fmt::Arguments<'_>)),
}
struct State(UnsafeCell<MaybeUninit<BootState>>);
// Written only by the boot hart, then published by runtime_platform::publish.
unsafe impl Sync for State {}
static STATE: State = State(UnsafeCell::new(MaybeUninit::uninit()));
fn state() -> &'static BootState {
    unsafe { (&*STATE.0.get()).assume_init_ref() }
}
pub unsafe fn page_tables() -> PageTableArena {
    state().tables
}
fn heap_regions() -> &'static [AddressRange] {
    state().heap.ranges()
}
fn hart_ids() -> &'static [usize] {
    &state().harts[..state().hart_count]
}
fn timebase_hz() -> u64 {
    state().timebase
}

unsafe fn report(print: fn(core::fmt::Arguments<'_>)) {
    (state().original_report)(print);
    let f = runtime_platform::get();
    print(format_args!(
        "UNIVERSAL board={:?} config={}\n",
        f.board, CONFIG_DIGEST
    ));
    print(format_args!("  components {:?}\n", f.components));
    for (id, reason) in unavailable(f.board) {
        print(format_args!("  unavailable {}: {}\n", id, reason));
    }
}
macro_rules! table {
    ($feature:literal, $value:path) => {{
        #[cfg(feature = $feature)]
        {
            Some(&$value)
        }
        #[cfg(not(feature = $feature))]
        {
            None
        }
    }};
}
fn empty(
    board: BoardId,
    platform: &'static BootPlatform,
    early: &'static vibeos_hal::devices::EarlyDevices,
) -> Firmware {
    Firmware {
        board,
        platform,
        early,
        block_backend: BlockBackend::None,
        network_backend: NetworkBackend::None,
        entropy_backend: EntropyBackend::None,
        block_first_sector: 0,
        block_sector_count: 0,
        pio_block: None,
        queued_block: None,
        packet: None,
        queued_packet: None,
        entropy: None,
        transport: None,
        pci: None,
        usb: None,
        polling_usb: None,
        components: components(board),
    }
}
fn assemble(board: BoardId) -> Result<Firmware, BootError> {
    match board {
        #[cfg(feature = "board-qemu-virt")]
        BoardId::QemuVirt => {
            let mut f = empty(
                board,
                &qemu::early_devices::VIBEOS_BOOT_PLATFORM,
                &qemu::early_devices::VIBEOS_EARLY_DEVICES,
            );
            f.queued_block = table!(
                "driver-virtio-blk",
                qemu::storage::VIBEOS_QUEUED_BLOCK_DEVICE
            );
            f.queued_packet = table!(
                "driver-virtio-net",
                qemu::network::VIBEOS_QUEUED_PACKET_DEVICE
            );
            f.entropy = table!("driver-virtio-rng", qemu::entropy::VIBEOS_ENTROPY_DEVICE);
            f.transport = table!(
                "driver-virtio-mmio",
                qemu::transport::VIBEOS_DEVICE_TRANSPORT
            );
            f.pci = table!("driver-pci", qemu::pci::VIBEOS_PCI_HOST);
            f.usb = table!("driver-xhci", qemu::usb::VIBEOS_USB_HOST);
            if f.queued_block.is_some() {
                f.block_backend = BlockBackend::Queued;
                f.block_sector_count = if f.components.contains(&"file-tree") {
                    262144
                } else {
                    131072
                };
            }
            if f.queued_packet.is_some() {
                f.network_backend = NetworkBackend::Queued;
            }
            if f.entropy.is_some() {
                f.entropy_backend = EntropyBackend::Queued;
            } else if enabled(board, "jitter-entropy") {
                f.entropy_backend = EntropyBackend::Jitter;
            }
            Ok(f)
        }
        #[cfg(feature = "board-milkv-duo")]
        BoardId::MilkvDuo => {
            let mut f = empty(
                board,
                &duo::early_devices::VIBEOS_BOOT_PLATFORM,
                &duo::early_devices::VIBEOS_EARLY_DEVICES,
            );
            f.pio_block = table!("driver-sdhci-blk", duo::storage::VIBEOS_PIO_BLOCK_DEVICE);
            f.packet = table!("driver-dwmac-net", duo::network::VIBEOS_PACKET_DEVICE);
            f.polling_usb = table!("driver-dwc2-host", duo::usb::VIBEOS_POLLING_USB_HOST);
            if f.pio_block.is_some() {
                f.block_backend = BlockBackend::Pio;
                f.block_first_sector = 262145;
                f.block_sector_count = 1048576;
            }
            if f.packet.is_some() {
                f.network_backend = NetworkBackend::Packet;
            }
            if enabled(board, "jitter-entropy") {
                f.entropy_backend = EntropyBackend::Jitter;
            }
            Ok(f)
        }
        #[cfg(feature = "board-milkv-mars")]
        BoardId::MilkvMars => {
            let mut f = empty(
                board,
                &mars::early_devices::VIBEOS_BOOT_PLATFORM,
                &mars::early_devices::VIBEOS_EARLY_DEVICES,
            );
            f.pio_block = table!("driver-dw-mshc", mars::storage::VIBEOS_PIO_BLOCK_DEVICE);
            f.packet = table!("driver-eqos-net", mars::network::VIBEOS_PACKET_DEVICE);
            f.entropy = table!("driver-starfive-trng", mars::VIBEOS_ENTROPY_DEVICE);
            if f.pio_block.is_some() {
                f.block_backend = BlockBackend::Pio;
                f.block_sector_count = 1048576;
            }
            if f.packet.is_some() {
                f.network_backend = NetworkBackend::Packet;
            }
            if enabled(board, "jitter-entropy") {
                f.entropy_backend = EntropyBackend::Jitter;
            }
            // Diagnostic TRNG does not replace the selected jitterentropy source.
            Ok(f)
        }
        #[allow(unreachable_patterns)]
        _ => Err(BootError::UnsupportedFirmware),
    }
}

extern "C" {
    static _start: u8;
    static __heap_start: u8;
}
/// Called after BSS clearing, before the first UART access, MMU, or heap use.
#[no_mangle]
pub unsafe extern "C" fn vibeos_select_platform(hart: usize, dtb_address: usize) -> bool {
    match select(hart, dtb_address) {
        Ok(()) => true,
        Err(_) => {
            for c in b"UNIVERSAL BOOT REJECTED: DTB, board, ISA or memory contract\n" {
                vibeos_runtime_riscv::legacy_putchar(*c);
            }
            false
        }
    }
}
unsafe fn select(hart: usize, dtb_address: usize) -> Result<(), BootError> {
    let base = core::ptr::addr_of!(_start) as usize;
    let heap_start = core::ptr::addr_of!(__heap_start) as usize;
    // The bootloader contract supplies readable physical DTB memory. Only
    // known board RAM envelopes are permitted before parsing the header.
    let initial = BootRequest {
        physical_hart: hart,
        dtb_address,
        ram: AddressRange::new(0x40000000, 0x140000000),
        static_memory: AddressRange::new(base, heap_start),
        heap_envelope: AddressRange::new(heap_start, heap_start),
    };
    let bytes = initial.dtb()?;
    let board = vibeos_firmware_universal::identify(bytes).map_err(|_| BootError::InvalidDtb)?;
    let mut firmware = assemble(board)?;
    let mut platform = *firmware.platform;
    if base < platform.mmu.ram.start || base % (2 << 20) != 0 || heap_start >= platform.heap_end {
        return Err(BootError::InvalidMemory);
    }
    vibeos_firmware_universal::early_resources(
        bytes,
        platform.info.uart.registers.start,
        platform.info.plic.registers.start,
    )
    .map_err(|_| BootError::InvalidDtb)?;
    let dtb = vibeos_hal::fdt::Fdt::new(bytes).map_err(|_| BootError::InvalidDtb)?;
    let inventory = dtb.cpus::<8>().map_err(|_| BootError::InvalidCpu)?;
    let boot = inventory
        .entries()
        .iter()
        .find(|cpu| cpu.hart == hart && cpu.enabled && cpu.supports_sv39())
        .ok_or(BootError::InvalidCpu)?;
    if !vibeos_firmware_universal::supports_isa(boot.isa, cfg!(feature = "component-wasmtime"))
        || inventory.timebase_hz == 0
    {
        return Err(BootError::InvalidCpu);
    }
    let mut harts = [0; 4];
    harts[0] = hart;
    let mut count = 1;
    for cpu in inventory
        .entries()
        .iter()
        .filter(|c| c.enabled && c.supports_sv39() && c.hart != hart)
    {
        if count == 4
            || !vibeos_firmware_universal::supports_isa(
                cpu.isa,
                cfg!(feature = "component-wasmtime"),
            )
        {
            return Err(BootError::InvalidCpu);
        }
        harts[count] = cpu.hart;
        count += 1;
    }
    let request = BootRequest {
        physical_hart: hart,
        dtb_address,
        ram: platform.mmu.ram,
        static_memory: AddressRange::new(base, heap_start),
        heap_envelope: AddressRange::new(heap_start, platform.heap_end),
    };
    if let Some(admit) = platform.admit_boot {
        admit(request)?;
    }
    let memory = dtb
        .memory::<16>(dtb_address)
        .map_err(|_| BootError::InvalidMemory)?;
    let mut heap = request.usable_heap(&memory)?;
    platform.mmu.ram.start = base;
    let pages = ram_page_table_pages(platform.mmu.ram);
    let bytes = pages.checked_mul(4096).ok_or(BootError::InvalidMemory)?;
    let table_base = heap
        .ranges()
        .iter()
        .find(|r| r.len() >= bytes)
        .ok_or(BootError::InvalidMemory)?
        .start;
    let end = table_base
        .checked_add(bytes)
        .ok_or(BootError::InvalidMemory)?;
    heap.reserve(AddressRange::new(table_base, end))
        .map_err(|_| BootError::InvalidMemory)?;
    if heap.ranges().is_empty() {
        return Err(BootError::InvalidMemory);
    }
    core::ptr::write_bytes(table_base as *mut u8, 0, bytes);
    let original_report = platform.platform_report;
    platform.platform_report = report;
    platform.admit_boot = None;
    platform.heap_regions = Some(heap_regions);
    platform.hart_ids = hart_ids;
    platform.timebase_hz = timebase_hz;
    (*STATE.0.get()).write(BootState {
        platform,
        heap,
        original_report,
        tables: PageTableArena {
            base: table_base,
            pages,
        },
        harts,
        hart_count: count,
        timebase: u64::from(inventory.timebase_hz),
    });
    firmware.platform = &state().platform;
    runtime_platform::publish(firmware)?;
    Ok(())
}
