use vibeos_bsp_qemu_virt::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
pub(super) mod early_devices;

#[cfg(all(
    feature = "mmu-large-memory",
    any(feature = "python-wasi", feature = "storage-bench")
))]
compile_error!("the high-RAM probe requires the ordinary 128 MiB heap contract");

#[cfg(feature = "driver-virtio-rng")]
#[path = "../../qemu-virt/src/entropy.rs"]
pub(super) mod entropy;

#[cfg(feature = "driver-virtio-blk")]
#[path = "../../qemu-virt/src/storage.rs"]
pub(super) mod storage;

#[cfg(feature = "driver-virtio-net")]
#[path = "../../qemu-virt/src/network.rs"]
pub(super) mod network;

unsafe fn platform_init(_write: fn(&str)) {}
unsafe fn platform_report(_print: fn(core::fmt::Arguments<'_>)) {
    #[cfg(feature = "ssh-security-test")]
    _print(format_args!(
        "ENTROPY_COMPLETION_MODE {:?}\n",
        vibeos_hal::entropy::device().completion_mode
    ));
}

#[cfg(feature = "driver-pci")]
#[path = "../../qemu-virt/src/pci.rs"]
pub(super) mod pci;

#[cfg(feature = "driver-xhci")]
#[path = "../../qemu-virt/src/usb.rs"]
pub(super) mod usb;

#[cfg(feature = "driver-virtio-mmio")]
#[path = "../../qemu-virt/src/transport.rs"]
pub(super) mod transport;

// Preserve the established storage namespace independently of HAL frontend choice.
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0001).unwrap();
const NETWORK_DRIVER_NAME: &str = "virtio-mmio";

fn hart_ids() -> &'static [usize] {
    Board::HART_IDS
}
fn timebase_hz() -> u64 {
    Board::INFO.timebase_hz
}
const BOOT_ADMISSION: Option<
    unsafe fn(vibeos_hal::boot::BootRequest) -> Result<(), vibeos_hal::boot::BootError>,
> = None;

const BOOT_HEAP_REGIONS: Option<fn() -> &'static [vibeos_hal::AddressRange]> = None;

#[cfg(feature = "mmu-large-memory")]
const HEAP_END: usize = 0x88000000;
#[cfg(not(feature = "mmu-large-memory"))]
const HEAP_END: usize = Board::MMU.ram.end;
