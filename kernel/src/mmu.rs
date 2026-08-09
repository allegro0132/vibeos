//! One shared Sv39 address space for every kernel hart.
//!
//! M6 uses paging for integrity, not process isolation.  The initial map keeps
//! kernel RAM and the three QEMU `virt` MMIO regions at identical virtual and
//! physical addresses.  RAM uses 4 KiB leaves from the outset so later guard,
//! W^X, and read-only milestones can change one page without splitting a live
//! superpage.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
pub const STACK_GUARD_SIZE: usize = sv39::PAGE_SIZE;
pub const STACK_SLOT_STRIDE: usize = 256 * 1024;

const MEGAPAGE_SIZE: usize = 2 * 1024 * 1024;
const RAM_LEVEL0_TABLES: usize = (KERNEL_RAM_END - KERNEL_RAM_START) / MEGAPAGE_SIZE;
const PLIC_ENABLE_PAGE: usize = PLIC_START + 0x2000;
pub const PLIC_CONTEXT_START: usize = PLIC_START + 0x20_0000;

const WRITABLE_PERMISSIONS: PagePermissions =
    PagePermissions::READ.union(PagePermissions::WRITE);
const TEXT_PERMISSIONS: PagePermissions =
    PagePermissions::READ.union(PagePermissions::EXECUTE);
const EXECUTABLE_PERMISSIONS: PagePermissions = PagePermissions::EXECUTE;
const MMIO_PERMISSIONS: PagePermissions = PagePermissions::READ.union(PagePermissions::WRITE);
const STACK_PERMISSIONS: PagePermissions = WRITABLE_PERMISSIONS;

extern "C" {
    static __stacks_bottom: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __code_pool_start: u8;
    static __code_pool_end: u8;
}

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
static MXR_CLEARED_HARTS: AtomicUsize = AtomicUsize::new(0);
static WX_TRANSITIONS: AtomicU64 = AtomicU64::new(0);
static REMOTE_SFENCES: AtomicU64 = AtomicU64::new(0);
static REMOTE_FENCE_I: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub physical: usize,
    pub permissions: PagePermissions,
    pub page_size: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WxSyncStats {
    pub transitions: u64,
    pub remote_sfences: u64,
    pub remote_fence_i: u64,
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
            *entry = PageTableEntry::leaf(physical, WRITABLE_PERMISSIONS)
                .expect("identity RAM leaf is architecturally valid");
        }
    }

    let (text_start, text_end) = text_range();
    assert_page_range(text_start, text_end);
    remap_boot_range(tables, text_start, text_end, TEXT_PERMISSIONS);

    let (code_start, code_end) = code_pool_range();
    assert_page_range(code_start, code_end);
    remap_boot_range(tables, code_start, code_end, WRITABLE_PERMISSIONS);

    for logical_index in 0..exec::MAX_HARTS {
        let guard = stack_guard_page(logical_index).expect("logical stack guard is in range");
        *ram_leaf_mut(tables, guard) = PageTableEntry::EMPTY;
        for address in
            (guard + STACK_GUARD_SIZE..guard + STACK_SLOT_STRIDE).step_by(sv39::PAGE_SIZE)
        {
            *ram_leaf_mut(tables, address) = PageTableEntry::leaf(address, STACK_PERMISSIONS)
                .expect("mapped kernel stack page is valid");
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
    crate::sbi::clear_mxr();
    assert!(
        !crate::sbi::mxr_enabled(),
        "execute-only mappings require sstatus.MXR=0"
    );
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
    let bit = 1usize << logical_index;
    MXR_CLEARED_HARTS.fetch_or(bit, Ordering::Release);
    ENABLED_HARTS.fetch_or(bit, Ordering::Release);
}

pub fn enabled_hart_mask() -> usize {
    ENABLED_HARTS.load(Ordering::Acquire)
}

pub fn mxr_cleared_hart_mask() -> usize {
    MXR_CLEARED_HARTS.load(Ordering::Acquire)
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

pub fn stack_slots_start() -> usize {
    core::ptr::addr_of!(__stacks_bottom) as usize
}

pub fn stack_guard_page(logical_index: usize) -> Option<usize> {
    (logical_index < exec::MAX_HARTS)
        .then(|| stack_slots_start() + logical_index * STACK_SLOT_STRIDE)
}

pub fn stack_usable_start(logical_index: usize) -> Option<usize> {
    stack_guard_page(logical_index).map(|guard| guard + STACK_GUARD_SIZE)
}

pub fn stack_guard_hart(address: usize) -> Option<usize> {
    let offset = address.checked_sub(stack_slots_start())?;
    let logical_index = offset / STACK_SLOT_STRIDE;
    (logical_index < exec::MAX_HARTS && offset % STACK_SLOT_STRIDE < STACK_GUARD_SIZE)
        .then_some(logical_index)
}

pub fn text_range() -> (usize, usize) {
    (
        core::ptr::addr_of!(__text_start) as usize,
        core::ptr::addr_of!(__text_end) as usize,
    )
}

pub fn code_pool_range() -> (usize, usize) {
    (
        core::ptr::addr_of!(__code_pool_start) as usize,
        core::ptr::addr_of!(__code_pool_end) as usize,
    )
}

pub fn code_pool_contains(address: usize) -> bool {
    let (start, end) = code_pool_range();
    address >= start && address < end
}

pub fn wx_sync_stats() -> WxSyncStats {
    WxSyncStats {
        transitions: WX_TRANSITIONS.load(Ordering::Acquire),
        remote_sfences: REMOTE_SFENCES.load(Ordering::Acquire),
        remote_fence_i: REMOTE_FENCE_I.load(Ordering::Acquire),
    }
}

/// The shared address space can mutate executable PTEs on a multicore machine
/// only when firmware supplies synchronous remote TLB and I-cache fences.
pub fn wx_remote_fence_ready() -> bool {
    remote_hart_mask().is_some_and(|mask| {
        mask == 0 || crate::sbi::probe_extension(crate::sbi::RFENCE_EXTENSION_ID)
    })
}

/// Turn a private code-pool run from RW-NX into execute-only.
///
/// Publication happens only after break-before-make, two all-hart TLB
/// shootdowns, and an all-hart instruction-cache fence have completed.
pub fn seal_code(start: usize, pages: usize) {
    transition_code(
        start,
        pages,
        WRITABLE_PERMISSIONS,
        EXECUTABLE_PERMISSIONS,
        true,
    );
}

/// Remove execute permission before the caller clears and releases a code run.
pub fn unseal_code(start: usize, pages: usize) {
    transition_code(
        start,
        pages,
        EXECUTABLE_PERMISSIONS,
        WRITABLE_PERMISSIONS,
        false,
    );
}

/// Scan the actual leaf PTEs under one lock. `None` is the W^X invariant.
pub fn first_writable_executable_ram_page() -> Option<usize> {
    if !TABLES_READY.load(Ordering::Acquire) {
        return None;
    }
    let _tables = PAGE_TABLE_LOCK.lock();
    // Safety: the lock serializes all post-boot mutations and TABLES_READY
    // proves the complete hierarchy was published.
    let tables = unsafe { &*TABLES.0.get() };
    for (table_index, level0) in tables.ram_level0.iter().enumerate() {
        for (page_index, entry) in level0.entries.iter().copied().enumerate() {
            let permissions = entry.permissions();
            if entry.is_valid()
                && entry.is_leaf()
                && permissions.contains(PagePermissions::WRITE)
                && permissions.contains(PagePermissions::EXECUTE)
            {
                return Some(
                    KERNEL_RAM_START
                        + table_index * MEGAPAGE_SIZE
                        + page_index * sv39::PAGE_SIZE,
                );
            }
        }
    }
    None
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

fn assert_page_range(start: usize, end: usize) {
    assert!(start >= KERNEL_RAM_START && end <= KERNEL_RAM_END && start < end);
    assert_eq!(start % sv39::PAGE_SIZE, 0);
    assert_eq!(end % sv39::PAGE_SIZE, 0);
}

fn remap_boot_range(
    tables: &mut AddressSpace,
    start: usize,
    end: usize,
    permissions: PagePermissions,
) {
    for address in (start..end).step_by(sv39::PAGE_SIZE) {
        *ram_leaf_mut(tables, address) = PageTableEntry::leaf(address, permissions)
            .expect("boot RAM permission override is valid");
    }
}

fn transition_code(
    start: usize,
    pages: usize,
    expected_permissions: PagePermissions,
    target_permissions: PagePermissions,
    synchronize_instructions: bool,
) {
    assert!(pages != 0, "W^X transition requires at least one page");
    assert_eq!(start % sv39::PAGE_SIZE, 0, "W^X start is not page aligned");
    let size = pages
        .checked_mul(sv39::PAGE_SIZE)
        .expect("W^X transition length overflowed");
    let end = start
        .checked_add(size)
        .expect("W^X transition range overflowed");
    let (pool_start, pool_end) = code_pool_range();
    assert!(
        start >= pool_start && end <= pool_end,
        "W^X transition escaped the dedicated code pool"
    );

    let _page_tables = PAGE_TABLE_LOCK.lock();
    // Safety: the page-table lock is the unique post-publication mutation
    // authority. The code-pool allocation stays reserved across this call.
    let tables = unsafe { &mut *TABLES.0.get() };

    // Validate the complete old range before changing its first PTE. A stale,
    // overlapping, or repeated transition therefore cannot partially apply.
    for address in (start..end).step_by(sv39::PAGE_SIZE) {
        let expected = PageTableEntry::leaf(address, expected_permissions)
            .expect("expected code-pool leaf is valid");
        assert_eq!(
            *ram_leaf_mut(tables, address),
            expected,
            "code-pool PTE did not have the required old permissions"
        );
    }

    // Break before make. Directly replacing RW with X (or vice versa) could
    // leave one hart using a stale writable TLB entry while another already
    // observes the executable entry.
    for address in (start..end).step_by(sv39::PAGE_SIZE) {
        *ram_leaf_mut(tables, address) = PageTableEntry::EMPTY;
    }
    publish_pte_writes();
    synchronize_tlbs(start, size);

    for address in (start..end).step_by(sv39::PAGE_SIZE) {
        *ram_leaf_mut(tables, address) = PageTableEntry::leaf(address, target_permissions)
            .expect("target code-pool leaf is valid");
    }
    publish_pte_writes();
    synchronize_tlbs(start, size);
    if synchronize_instructions {
        synchronize_instruction_caches();
    }
    WX_TRANSITIONS.fetch_add(1, Ordering::Release);
}

fn publish_pte_writes() {
    unsafe { asm!("fence rw, rw", options(nostack)) };
}

fn remote_hart_mask() -> Option<usize> {
    let mut mask = crate::ipi::online_physical_hart_mask()?;
    let current = crate::sbi::current_hart_id();
    if current >= usize::BITS as usize {
        return None;
    }
    mask &= !(1usize << current);
    Some(mask)
}

fn synchronize_tlbs(start: usize, size: usize) {
    crate::sbi::local_sfence_vma(start, size);
    let Some(remote) = remote_hart_mask() else {
        crate::sbi::shutdown(true);
    };
    if remote == 0 {
        return;
    }
    if !crate::sbi::probe_extension(crate::sbi::RFENCE_EXTENSION_ID)
        || crate::sbi::remote_sfence_vma(remote, 0, start, size).is_err()
    {
        // A partially completed shootdown cannot be rolled back safely and a
        // task fault catcher must not turn it into an ordinary component fault.
        crate::sbi::shutdown(true);
    }
    REMOTE_SFENCES.fetch_add(1, Ordering::Release);
}

fn synchronize_instruction_caches() {
    crate::sbi::local_fence_i();
    let Some(remote) = remote_hart_mask() else {
        crate::sbi::shutdown(true);
    };
    if remote == 0 {
        return;
    }
    if !crate::sbi::probe_extension(crate::sbi::RFENCE_EXTENSION_ID)
        || crate::sbi::remote_fence_i(remote, 0).is_err()
    {
        crate::sbi::shutdown(true);
    }
    REMOTE_FENCE_I.fetch_add(1, Ordering::Release);
}

fn ram_leaf_mut(tables: &mut AddressSpace, address: usize) -> &mut PageTableEntry {
    assert!(address >= KERNEL_RAM_START && address < KERNEL_RAM_END);
    assert_eq!(address % sv39::PAGE_SIZE, 0);
    let offset = address - KERNEL_RAM_START;
    let table_index = offset / MEGAPAGE_SIZE;
    let page_index = offset % MEGAPAGE_SIZE / sv39::PAGE_SIZE;
    &mut tables.ram_level0[table_index].entries[page_index]
}

fn table_address(table: &PageTable) -> usize {
    table as *const PageTable as usize
}
