//! Exercise the real kernel mapper with eight distinct 2 MiB device windows.
//! Added apertures are never dereferenced: QEMU has no device at these addresses.
use vibeos_bsp_qemu_virt::Board as Qemu;
use vibeos_hal::{
    AddressRange, Board as Contract, BoardInfo, IdentityMapping, MemoryRegion, MmuDescription,
};
pub struct Board;
const MAPPINGS: &[IdentityMapping] = &[
    Qemu::MMU.identity_mappings[0],
    Qemu::MMU.identity_mappings[1],
    Qemu::MMU.identity_mappings[2],
    Qemu::MMU.identity_mappings[3],
    Qemu::MMU.identity_mappings[4],
    IdentityMapping::pages("capacity probe 6", 0x03200000, 0x03201000),
    IdentityMapping::pages("capacity probe 7", 0x03400000, 0x03401000),
    IdentityMapping::pages("capacity probe 8", 0x03600000, 0x03601000),
];
impl Contract for Board {
    const INFO: BoardInfo = Qemu::INFO;
    const MEMORY_MAP: &'static [MemoryRegion] = Qemu::MEMORY_MAP;
    const MMU: MmuDescription = MmuDescription {
        identity_mappings: MAPPINGS,
        device_level0_tables: 8,
        ..Qemu::MMU
    };
    const HART_IDS: &'static [usize] = Qemu::HART_IDS;
    const RTC: Option<AddressRange> = Qemu::RTC;
    fn plic_s_context(hart: usize) -> Option<usize> {
        Qemu::plic_s_context(hart)
    }
}
