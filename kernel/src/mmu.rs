//! One shared Sv39 address space for every kernel hart.
//!
//! M6 uses paging for integrity, not process isolation.  The initial map keeps
//! kernel RAM and the three QEMU `virt` MMIO regions at identical virtual and
//! physical addresses.  RAM uses 4 KiB leaves from the outset so later guard,
//! W^X, and read-only milestones can change one page without splitting a live
//! superpage.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::exec;
use crate::sync::SpinLock;
use sv39::{PagePermissions, PageTableEntry};
use vibeos_core::mmu as sv39;

pub const KERNEL_RAM_START: usize = 0x8020_0000;
pub const KERNEL_RAM_END: usize = 0x8800_0000;
pub const PLIC_START: usize = 0x0c00_0000;
pub const PLIC_END: usize = 0x0c40_0000;
pub const UART_VIRTIO_START: usize = 0x1000_0000;
pub const UART_VIRTIO_END: usize = 0x1000_9000;

const MEGAPAGE_SIZE: usize = 2 * 1024 * 1024;
const RAM_LEVEL0_TABLES: usize = (KERNEL_RAM_END - KERNEL_RAM_START) / MEGAPAGE_SIZE;
const PLIC_ENABLE_PAGE: usize = PLIC_START + 0x2000;
pub const PLIC_CONTEXT_START: usize = PLIC_START + 0x20_0000;

const RAM_PERMISSIONS: PagePermissions = PagePermissions::READ
    .union(PagePermissions::WRITE)
    .union(PagePermissions::EXECUTE);
const MMIO_PERMISSIONS: PagePermissions = PagePermissions::READ.union(PagePermissions::WRITE);

#[repr(C, align(4096))]
struct PageTable {
    entries: [PageTableEntry; sv39::ENTRIES_PER_TABLE],
}

impl PageTable {
    const fn empty() -> Self {
        Self {
            entries: [PageTableEntry::EMPTY; sv39::ENTRIES_PER_TABLE],
        }
    }
}

#[repr(C)]
struct AddressSpace {
    root: PageTable,
    devices_level1: PageTable,
    plic_control_level0: PageTable,
    plic_context_level0: PageTable,
    uart_virtio_level0: PageTable,
    ram_level1: PageTable,
    ram_level0: [PageTable; RAM_LEVEL0_TABLES],
}

impl AddressSpace {
    const fn empty() -> Self {
        Self {
            root: PageTable::empty(),
            devices_level1: PageTable::empty(),
            plic_control_level0: PageTable::empty(),
            plic_context_level0: PageTable::empty(),
            uart_virtio_level0: PageTable::empty(),
            ram_level1: PageTable::empty(),
            ram_level0: [const { PageTable::empty() }; RAM_LEVEL0_TABLES],
        }
    }
}

struct SharedAddressSpace(UnsafeCell<AddressSpace>);

// Every mutation is either the single-hart boot construction or is serialized
// by PAGE_TABLE_LOCK. Hardware page-table walkers only read published entries.
unsafe impl Sync for SharedAddressSpace {}

static TABLES: SharedAddressSpace = SharedAddressSpace(UnsafeCell::new(AddressSpace::empty()));
static PAGE_TABLE_LOCK: SpinLock<()> = SpinLock::new(());
static INIT_STARTED: AtomicBool = AtomicBool::new(false);
static TABLES_READY: AtomicBool = AtomicBool::new(false);
static ENABLED_HARTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub physical: usize,
    pub permissions: PagePermissions,
    pub page_size: usize,
}

/// Build the one global address space before the boot hart starts peers.
pub fn init_boot(boot_physical_hart: usize) {
    assert!(
        INIT_STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "Sv39 tables initialized twice"
    );
    assert_eq!(KERNEL_RAM_START % MEGAPAGE_SIZE, 0);
    assert_eq!(KERNEL_RAM_END % MEGAPAGE_SIZE, 0);
    assert!(
        boot_physical_hart < exec::MAX_HARTS,
        "dense QEMU boot hart must fit the mapped PLIC topology"
    );

    // Safety: no secondary is released and TABLES_READY is false, so the boot
    // hart has exclusive access to the complete table hierarchy.
    let tables = unsafe { &mut *TABLES.0.get() };
    // `_start` has already zeroed `.bss`, including TABLES. Do not assign a
    // fresh 276 KiB `AddressSpace::empty()` here: materializing that value can
    // create a stack temporary larger than the boot hart's 256 KiB stack.

    tables.root.entries[sv39::vpn_index(PLIC_START, 2)] =
        PageTableEntry::table(table_address(&tables.devices_level1))
            .expect("device level-1 table is page aligned");
    tables.root.entries[sv39::vpn_index(KERNEL_RAM_START, 2)] =
        PageTableEntry::table(table_address(&tables.ram_level1))
            .expect("RAM level-1 table is page aligned");

    link_level0(
        &mut tables.devices_level1,
        PLIC_START,
        &tables.plic_control_level0,
    );
    link_level0(
        &mut tables.devices_level1,
        PLIC_CONTEXT_START,
        &tables.plic_context_level0,
    );
    link_level0(
        &mut tables.devices_level1,
        UART_VIRTIO_START,
        &tables.uart_virtio_level0,
    );
    map_page(
        &mut tables.plic_control_level0,
        PLIC_START,
        MMIO_PERMISSIONS,
    );
    map_page(
        &mut tables.plic_control_level0,
        PLIC_ENABLE_PAGE,
        MMIO_PERMISSIONS,
    );
    map_page(
        &mut tables.plic_context_level0,
        plic_s_context_page(boot_physical_hart).expect("boot physical hart is in range"),
        MMIO_PERMISSIONS,
    );
    for physical in (UART_VIRTIO_START..UART_VIRTIO_END).step_by(sv39::PAGE_SIZE) {
        map_page(&mut tables.uart_virtio_level0, physical, MMIO_PERMISSIONS);
    }

    for (table_index, level0) in tables.ram_level0.iter_mut().enumerate() {
        let base = KERNEL_RAM_START + table_index * MEGAPAGE_SIZE;
        let level1_index = sv39::vpn_index(base, 1);
        tables.ram_level1.entries[level1_index] = PageTableEntry::table(table_address(level0))
            .expect("RAM level-0 table is page aligned");
        for (page_index, entry) in level0.entries.iter_mut().enumerate() {
            let physical = base + page_index * sv39::PAGE_SIZE;
            *entry = PageTableEntry::leaf(physical, RAM_PERMISSIONS)
                .expect("identity RAM leaf is architecturally valid");
        }
    }

    // Release publishes every PTE to secondaries before their acquire of the
    // boot barrier. The enabling hart also issues a full fence around `satp`.
    TABLES_READY.store(true, Ordering::Release);
}

/// Enable the shared address space on the calling hart and publish readback.
///
/// `logical_index` is explicit because secondaries have not installed their
/// `sscratch` cache yet. The online barrier is never set before this returns.
pub fn enable(logical_index: usize) {
    assert!(logical_index < exec::MAX_HARTS);
    assert!(
        TABLES_READY.load(Ordering::Acquire),
        "Sv39 tables must be published before enabling paging"
    );
    let expected = sv39::satp(root_physical()).expect("Sv39 root is page aligned");
    unsafe {
        asm!(
            "fence rw, rw",
            "sfence.vma x0, x0",
            "csrw satp, {value}",
            "sfence.vma x0, x0",
            value = in(reg) expected,
            options(nostack),
        );
    }
    assert_eq!(
        local_satp(),
        expected,
        "satp readback differs from Sv39 root"
    );
    ENABLED_HARTS.fetch_or(1usize << logical_index, Ordering::Release);
}

pub fn enabled_hart_mask() -> usize {
    ENABLED_HARTS.load(Ordering::Acquire)
}

pub fn local_satp() -> usize {
    let value: usize;
    unsafe { asm!("csrr {}, satp", out(reg) value, options(nostack, nomem)) };
    value
}

pub fn local_paging_enabled() -> bool {
    local_satp() == sv39::satp(root_physical()).expect("Sv39 root remains page aligned")
}

pub fn root_physical() -> usize {
    // Safety: taking a raw address does not access the UnsafeCell contents.
    unsafe { core::ptr::addr_of!((*TABLES.0.get()).root) as usize }
}

pub fn plic_s_context_page(physical_hart: usize) -> Option<usize> {
    (physical_hart < exec::MAX_HARTS)
        .then(|| PLIC_CONTEXT_START + (physical_hart * 2 + 1) * sv39::PAGE_SIZE)
}

/// Walk the live hierarchy exactly as the hardware would for diagnostics and
/// in-kernel acceptance tests. The returned physical address includes the
/// offset within a 4 KiB or 2 MiB leaf.
pub fn mapping(virtual_address: usize) -> Option<Mapping> {
    if !TABLES_READY.load(Ordering::Acquire) || !sv39::is_canonical_virtual_address(virtual_address)
    {
        return None;
    }
    let _tables = PAGE_TABLE_LOCK.lock();
    let mut table = root_physical() as *const PageTable;
    for level in (0..sv39::SV39_LEVELS).rev() {
        // Safety: every non-leaf in the published hierarchy was constructed
        // from one of the aligned PageTable objects in TABLES. The lock keeps
        // future permission mutations from racing this diagnostic walk.
        let entry = unsafe { (*table).entries[sv39::vpn_index(virtual_address, level)] };
        if !entry.is_valid() {
            return None;
        }
        if entry.is_leaf() {
            let page_size = 1usize << (sv39::PAGE_SHIFT + level * 9);
            let offset = virtual_address & (page_size - 1);
            return Some(Mapping {
                physical: entry.physical_address() | offset,
                permissions: entry.permissions(),
                page_size,
            });
        }
        table = entry.physical_address() as *const PageTable;
    }
    None
}

fn link_level0(level1: &mut PageTable, base: usize, level0: &PageTable) {
    assert_eq!(base % MEGAPAGE_SIZE, 0);
    level1.entries[sv39::vpn_index(base, 1)] =
        PageTableEntry::table(table_address(level0)).expect("device level-0 table is page aligned");
}

fn map_page(level0: &mut PageTable, physical: usize, permissions: PagePermissions) {
    assert_eq!(physical % sv39::PAGE_SIZE, 0);
    level0.entries[sv39::vpn_index(physical, 0)] = PageTableEntry::leaf(physical, permissions)
        .expect("identity MMIO page is architecturally valid");
}

fn table_address(table: &PageTable) -> usize {
    table as *const PageTable as usize
}
